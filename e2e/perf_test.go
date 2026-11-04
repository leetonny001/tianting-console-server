package e2e

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"tianting/console/internal/audit"
	"tianting/console/internal/ids"
)

func percentile(d []time.Duration, p float64) time.Duration {
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	return d[int(float64(len(d)-1)*p)]
}

// AC-ADM-90-4：两个实例并发写 60 秒，吞吐 ≥ 200 条 / 秒、P95 ≤ 20ms，之后校验通过。只在 CON_TEST_AUDIT_PERF=1 时运行。
func TestPerfAuditWrite(t *testing.T) {
	if os.Getenv("CON_TEST_AUDIT_PERF") == "" {
		t.Skip("set CON_TEST_AUDIT_PERF=1")
	}
	w := newWorld(t, nil)
	w.a.Clock.Unfreeze()
	ctx := context.Background()
	if err := w.a.EnsurePartitions(ctx); err != nil {
		t.Fatal(err)
	}
	second := &audit.Writer{DB: w.a.DB, Now: time.Now}
	writers := []*audit.Writer{w.a.Audit, second}
	dur := 60 * time.Second
	stop := time.Now().Add(dur)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var lat []time.Duration
	var errs atomic.Int64
	for i := range 8 { // 每个实例 4 个并发：比生产的后台操作量大得多
		wg.Add(1)
		go func() {
			defer wg.Done()
			wr := writers[i%2]
			var local []time.Duration
			for time.Now().Before(stop) {
				s := time.Now()
				if err := wr.Write(ctx, audit.Record{Space: "admin", Phase: audit.PhaseEvent, RequestID: ids.New(s), Actor: "perf", Username: "perf", Action: "perf.write", Target: audit.NewTarget("user", "u1"), Result: audit.Success, Params: map[string]any{"a": 1}}); err != nil {
					errs.Add(1)
					continue
				}
				local = append(local, time.Since(s))
			}
			mu.Lock()
			lat = append(lat, local...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	rate := float64(len(lat)) / dur.Seconds()
	p95 := percentile(lat, 0.95)
	t.Logf("AC-ADM-90-4: %d writes, %.0f/s, P50=%v P95=%v P99=%v, errors=%d", len(lat), rate, percentile(lat, 0.5), p95, percentile(lat, 0.99), errs.Load())
	if rate < 200 || p95 > 20*time.Millisecond || errs.Load() > 0 {
		t.Errorf("below target: %.0f/s, P95=%v, errors=%d", rate, p95, errs.Load())
	}
	start := time.Now()
	res, err := audit.Verify(ctx, w.db, 0, nil)
	if err != nil || res.Issue != nil || int(res.Records) != len(lat) {
		t.Errorf("verify = %+v %v, want %d records", res, err, len(lat))
	}
	t.Logf("verify: %d records in %v", res.Records, time.Since(start))
}

// AC-ADM-90-3：1000 万条，31 天按操作人筛选 P95 ≤ 2 秒。只在 CON_TEST_AUDIT_PERF=1 时运行。
//
// 查询按时间裁剪分区，只碰窗口内的几个月。所以默认按"每年 1000 万条"的密度灌 73 天（200 万条），
// 分区大小和窗口内行数与真实规模相同，省下约 8GB 磁盘。CON_TEST_AUDIT_PERF_ROWS 可以改条数，密度不变。
func TestPerfAuditQuery(t *testing.T) {
	if os.Getenv("CON_TEST_AUDIT_PERF") == "" {
		t.Skip("set CON_TEST_AUDIT_PERF=1")
	}
	w := newWorld(t, nil)
	a1 := w.super("adm1")
	aud := a1.create("aud1", "auditor")
	ctx := context.Background()
	total := 2_000_000
	if v, err := strconv.Atoi(os.Getenv("CON_TEST_AUDIT_PERF_ROWS")); err == nil && v > 0 {
		total = v
	}
	end := w.now.Add(-time.Hour)
	begin := end.Add(-time.Duration(float64(total) / 10_000_000 * float64(365*24*time.Hour)))
	c, err := pgx.Connect(ctx, w.owner)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	for m := begin; !m.After(end.AddDate(0, 1, 0)); m = m.AddDate(0, 1, 0) {
		if _, err := c.Exec(ctx, `SELECT audit.ensure_partition($1, $2)`, m.UTC().Year(), int(m.UTC().Month())); err != nil {
			t.Fatal(err)
		}
	}
	var seq int64
	var prev string
	if err := c.QueryRow(ctx, `SELECT seq, hash FROM audit.chain_head`).Scan(&seq, &prev); err != nil {
		t.Fatal(err)
	}
	// 账号操作已经写了当前时间的审计，再写更早的 ts 会破坏单调性；这里只测查询，不校验这段时间顺序。
	span := end.Sub(begin).Milliseconds()
	phases := []string{"intent", "result", "event"}
	i := 0
	start := time.Now()
	cols := []string{"seq", "id", "ts", "space", "phase", "request_id", "account_id", "username", "roles", "actor", "ip", "ua", "action", "target", "params", "reason", "ticket", "result", "code", "prev_hash", "hash"}
	n, err := c.CopyFrom(ctx, pgx.Identifier{"audit", "records"}, cols, pgx.CopyFromFunc(func() ([]any, error) {
		if i == total {
			return nil, nil
		}
		ts := begin.UnixMilli() + span*int64(i)/int64(total)
		seq++
		id := ids.New(time.UnixMilli(ts))
		actor := fmt.Sprintf("kf%d", i%50)
		action := fmt.Sprintf("user.op%d", i%30)
		s := audit.Stored{Seq: seq, ID: id, TS: ts, Space: "admin", Phase: phases[i%3], RequestID: id, Roles: `["support"]`, Actor: actor, Username: actor, IP: "10.0.0.1", UA: "Mozilla/5.0 perf", Action: action,
			Target: fmt.Sprintf(`{"type":"user","ids":["u%d"],"count":1}`, i%100000), Params: `{"reason":"x"}`, Reason: "工单处理", Result: "success", PrevHash: prev}
		h, err := s.Recompute()
		if err != nil {
			return nil, err
		}
		prev = h
		i++
		return []any{s.Seq, s.ID, s.TS, s.Space, s.Phase, s.RequestID, "", s.Username, s.Roles, s.Actor, s.IP, s.UA, s.Action, s.Target, s.Params, s.Reason, "", s.Result, 0, s.PrevHash, h}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(ctx, `UPDATE audit.chain_head SET seq = $1, hash = $2`, seq, prev); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(ctx, `ANALYZE audit.records`); err != nil {
		t.Fatal(err)
	}
	var size string
	_ = c.QueryRow(ctx, `SELECT pg_size_pretty(pg_database_size(current_database()))`).Scan(&size)
	t.Logf("seeded %d records in %v, database %s", n, time.Since(start), size)

	to := end.UnixMilli()
	from := to - 31*24*3600*1000
	cases := []struct{ name, extra string }{
		{"按操作人", "&actor=kf7"},
		{"操作人 + 动作", "&actor=kf7&action=user.op7"},
		{"操作人（没有匹配）", "&actor=nobody"},
		{"按目标", "&target=user:u77"},
		{"只有时间", ""},
	}
	for _, tc := range cases {
		var lat []time.Duration
		for round := range 20 {
			w.tick() // 不让会话空闲
			_ = round
			s := time.Now()
			r := aud.do("GET", auditURL(from, to, tc.extra+"&limit=50"), nil)
			lat = append(lat, time.Since(s))
			expect(t, tc.name, r, 200, 0)
		}
		t.Logf("AC-ADM-90-3 %s: P50=%v P95=%v", tc.name, percentile(lat, 0.5), percentile(lat, 0.95))
		if tc.name == "按操作人" && percentile(lat, 0.95) > 2*time.Second {
			t.Errorf("%s P95 = %v", tc.name, percentile(lat, 0.95))
		}
	}
	// 对账扫描也要跑得动。
	s := time.Now()
	w.a.Clock.Freeze(w.now)
	rows, err := c.Query(ctx, `EXPLAIN ANALYZE SELECT seq FROM audit.records i WHERE i.phase = 'intent' AND i.ts >= $1 AND i.ts < $2
		AND NOT EXISTS (SELECT 1 FROM audit.records r WHERE r.request_id = i.request_id AND r.phase = 'result' AND (r.result <> 'unknown' OR r.params LIKE '%"reconciled"%')) ORDER BY i.seq LIMIT 500`, from, to)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
	}
	rows.Close()
	t.Logf("reconcile scan (intents without results are the common case in this data): %v", time.Since(s))
}
