package app

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"tianting/console/internal/prom"
)

// CS-113：总览。卡片互相独立：一个数据源挂了只影响自己的卡片，而且显示"不可用"，绝不显示 0。

type unavailableCard struct {
	Unavailable bool   `json:"unavailable"`
	Reason      string `json:"reason"`
}

func cardDown(source string) unavailableCard { return unavailableCard{true, source + " 不可用"} }

type codeCount struct {
	Code  string  `json:"code"`
	Count float64 `json:"count"`
}

// topCodes 取数量最多的 n 个（数量相同时按码排序，结果稳定）。
func topCodes(samples []prom.Sample, n int, skip func(string) bool) []codeCount {
	out := []codeCount{}
	for _, s := range samples {
		code := s.Labels["code"]
		if s.Value <= 0 || (skip != nil && skip(code)) {
			continue
		}
		out = append(out, codeCount{code, s.Value})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Code < out[j].Code
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// errorCard 算错误率：5xxx、4xxx 分开，分母是全部命令。code 是 "0" 表示成功。
func errorCard(samples []prom.Sample) map[string]any {
	var total, c4, c5 float64
	for _, s := range samples {
		total += s.Value
		switch {
		case strings.HasPrefix(s.Labels["code"], "5"):
			c5 += s.Value
		case strings.HasPrefix(s.Labels["code"], "4"):
			c4 += s.Value
		}
	}
	share := func(v float64) float64 {
		if total == 0 {
			return 0
		}
		return v / total
	}
	return map[string]any{
		"share5xx": share(c5), "share4xx": share(c4), "total": total,
		"top": topCodes(samples, 3, func(code string) bool { return code == "0" }),
	}
}

func sinceShanghaiMidnight(now time.Time) time.Duration {
	local := now.In(shanghai)
	return now.Sub(time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, shanghai))
}

func (c *rc) opsOverview() {
	list, mismatch, err := c.a.loadNodes(c.ctx)
	if err != nil {
		c.failErr("ops overview", err)
		return
	}
	ready := 0
	conns := map[string]int{}
	total := 0
	for _, n := range list {
		if n.Status == nodeReady {
			ready++
		}
		if n.Status == nodeUnreachable || n.Status == nodeIdentity {
			continue // 探测不到的节点，上一次的连接数已经不可信
		}
		for p, v := range n.Connections {
			conns[p] += v
			total += v
		}
	}
	state := "down"
	switch {
	case len(list) > 0 && ready == len(list):
		state = "ok"
	case ready > 0:
		state = "degraded"
	}
	data := map[string]any{
		"status":      state,
		"versions":    versionInfo(list, mismatch, c.now()),
		"nodes":       map[string]int{"ready": ready, "total": len(list)},
		"connections": map[string]any{"total": total, "byPlatform": conns},
	}

	// 并发查询：单个超时 1 秒，一个慢不拖累其他。
	now := c.a.Clock.Now()
	var mu sync.Mutex
	put := func(k string, v any) {
		mu.Lock()
		defer mu.Unlock()
		data[k] = v
	}
	var wg sync.WaitGroup
	run := func(fn func(context.Context)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn(c.ctx)
		}()
	}
	run(func(ctx context.Context) {
		rate, err1 := c.a.Prom.Scalar(ctx, prom.QueryMessageRate)
		today, err2 := c.a.Prom.Scalar(ctx, prom.QueryMessagesToday(sinceShanghaiMidnight(now)))
		if err1 != nil || err2 != nil {
			put("messages", cardDown("Prometheus"))
			return
		}
		put("messages", map[string]any{"perSecond": rate, "today": today})
	})
	run(func(ctx context.Context) {
		s, err := c.a.Prom.Query(ctx, prom.QueryCommandsByCode)
		if err != nil {
			put("errors", cardDown("Prometheus"))
			return
		}
		put("errors", errorCard(s))
	})
	run(func(ctx context.Context) {
		hs, err1 := c.a.Prom.Query(ctx, prom.QueryHandshake)
		ss, err2 := c.a.Prom.Query(ctx, prom.QuerySession)
		if err1 != nil || err2 != nil {
			put("disconnects", cardDown("Prometheus"))
			return
		}
		put("disconnects", map[string]any{"handshake": topCodes(hs, 0, nil), "sessionTop3": topCodes(ss, 3, nil)})
	})
	run(func(ctx context.Context) {
		put("alerts", c.a.alertsCard(ctx))
	})
	run(func(ctx context.Context) {
		b, err := c.a.backups(ctx)
		if err != nil {
			put("backup", cardDown("备份存储"))
			return
		}
		put("backup", b.overviewCard(now.UnixMilli()))
	})
	wg.Wait()
	c.opsOK(data, missingNodes(list))
}

func (c *rc) opsAlerts() {
	c.opsOK(c.a.alertsCard(c.ctx), nil)
}

// alertsCard 是告警卡片：正在触发的告警和生效的静默（F-OPS-18 规则 4）。
// 静默读不到时单独标"不可用"：不能让人以为没有静默，也不能因此丢了告警。
func (a *App) alertsCard(ctx context.Context) any {
	alerts, err := a.Alertmanager.Alerts(ctx)
	if err != nil {
		return cardDown("Alertmanager")
	}
	silences, err := a.Alertmanager.Silences(ctx)
	if err != nil {
		return map[string]any{"list": alerts, "silences": cardDown("Alertmanager")}
	}
	return map[string]any{"list": alerts, "silences": silences}
}
