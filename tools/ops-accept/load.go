package main

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// AC-OPS-90-1 的运维流量、AC-OPS-90-2 的统计：20 个 ops_engineer 账号，每个账号 0.5 次/秒排查、
// 每 15 秒刷新总览、每 60 秒打开配置检查和数据库页。im-loadtest 通过 -ops-phase-file 控制开关段（on / off / done），
// 这样 IM 延迟和运维流量在同一轮里交替。只统计开始于"开"段的请求。
//
// Grafana 24 小时面板的那部分流量和首次加载耗时还没有实现：要等有真实 Grafana 的压测环境。

type sampleSet struct {
	mu       sync.Mutex
	lat      map[string][]time.Duration
	errs     map[string]int
	limited  map[string]int
	firstErr map[string]string
}

func newSampleSet() *sampleSet {
	return &sampleSet{lat: map[string][]time.Duration{}, errs: map[string]int{}, limited: map[string]int{}, firstErr: map[string]string{}}
}

func (s *sampleSet) add(class string, r reply, took time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case r.status == 200 && r.body["partial"] != true:
		s.lat[class] = append(s.lat[class], took)
	case r.status == 429: // 每分钟上限：不是耗时样本，单独报告
		s.limited[class]++
	default:
		s.errs[class]++
		if _, ok := s.firstErr[class]; !ok {
			s.firstErr[class] = fmt.Sprintf("%d %s", r.status, r.raw[:min(len(r.raw), 200)])
		}
	}
}

func every(ctx context.Context, d time.Duration, active *atomic.Bool, f func()) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if active.Load() {
				f()
			}
		}
	}
}

func stepLoad(super, approver *user, phaseFile string, accounts int) {
	section(fmt.Sprintf("AC-OPS-90-1、90-2：%d 个账号的运维流量，由 %s 控制开关段", accounts, phaseFile))
	if r := super.do("POST", "/console/api/auth/step-up", map[string]any{"otp": super.otp()}); r.status != 200 {
		fail("step-up: %d %s", r.status, r.raw)
		return
	}
	var engineers []*user
	for i := range accounts {
		e, err := super.createEngineer(approver, fmt.Sprintf("loadeng%02d", i+1))
		if err != nil {
			fail("%v", err)
			return
		}
		engineers = append(engineers, e)
	}
	// 每个账号只查同一批 50 个 userId，不触发每日上限。这些是 opsimpact 场景里的收发用户。
	var targets []string
	for i := 1; i <= 25; i++ {
		targets = append(targets, fmt.Sprintf("a%03d", i), fmt.Sprintf("b%03d", i))
	}

	samples := newSampleSet()
	var active atomic.Bool
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	timed := func(class string, f func() reply) {
		start := time.Now()
		r := f()
		took := time.Since(start)
		if active.Load() {
			samples.add(class, r, took)
		}
	}
	for i, e := range engineers {
		// 错开各账号的相位，不要 20 个账号在同一瞬间打过来。
		offset := time.Duration(i) * 100 * time.Millisecond
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(offset)
			var n atomic.Int64
			var inner sync.WaitGroup
			inner.Add(3)
			go func() {
				defer inner.Done()
				every(ctx, 2*time.Second, &active, func() {
					uid := targets[n.Add(1)%int64(len(targets))]
					timed("排查", func() reply {
						return e.do("POST", opsAPI+"/troubleshoot/query", map[string]any{"userId": uid, "ticket": "CS-1024", "reason": "性能验收排查"})
					})
				})
			}()
			go func() {
				defer inner.Done()
				every(ctx, 15*time.Second, &active, func() {
					timed("总览", func() reply { return e.do("GET", opsAPI+"/overview", nil) })
				})
			}()
			go func() {
				defer inner.Done()
				every(ctx, 60*time.Second, &active, func() {
					timed("配置检查", func() reply { return e.do("GET", opsAPI+"/config", nil) })
					timed("数据库页", func() reply { return e.do("GET", opsAPI+"/db", nil) })
				})
			}()
			inner.Wait()
		}()
	}

	last := ""
	for {
		raw, err := os.ReadFile(phaseFile) // #nosec G304 -- 路径来自命令行参数，只在测试环境运行
		phase := strings.TrimSpace(string(raw))
		if err == nil && phase != last {
			fmt.Printf("[%s] 运维流量：%s\n", time.Now().Format("15:04:05"), phase)
			last = phase
		}
		active.Store(phase == "on")
		if phase == "done" {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	cancel()
	wg.Wait()

	section("AC-OPS-90-2：console-server 接口耗时（开段）")
	limits := map[string]time.Duration{"总览": time.Second, "排查": 500 * time.Millisecond}
	for _, class := range []string{"总览", "排查", "配置检查", "数据库页"} {
		lat := samples.lat[class]
		slices.Sort(lat)
		if len(lat) == 0 {
			fail("%s 没有样本（错误 %d：%s）", class, samples.errs[class], samples.firstErr[class])
			continue
		}
		p := func(q float64) time.Duration { return lat[min(int(float64(len(lat))*q), len(lat)-1)] }
		line := fmt.Sprintf("%s：%d 个样本，错误 %d，被限流 %d；P50 %v，P99 %v，最大 %v", class, len(lat), samples.errs[class], samples.limited[class],
			p(0.5).Round(time.Millisecond), p(0.99).Round(time.Millisecond), lat[len(lat)-1].Round(time.Millisecond))
		limit, gated := limits[class]
		if !gated {
			ok("%s", line)
			continue
		}
		check(p(0.99) <= limit && len(lat) >= 300 && samples.errs[class] == 0, line+fmt.Sprintf("（要求 P99 ≤ %v，≥ 300 个样本）", limit), samples.firstErr[class])
	}
}
