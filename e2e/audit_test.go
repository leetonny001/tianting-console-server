package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/jackc/pgx/v5"

	"tianting/console/internal/anchor"
	"tianting/console/internal/apierr"
	"tianting/console/internal/audit"
	"tianting/console/internal/ids"
	"tianting/console/internal/imclient"
	"tianting/console/internal/objstore"
	"tianting/console/internal/objstore/objstoretest"
)

// seedChain 用 COPY 追加 n 条合法的审计记录，比逐条事务快得多。tsOf 决定每条的时间。
func seedChain(t *testing.T, ownerURL string, n int, tsOf func(i int) int64) {
	t.Helper()
	ctx := context.Background()
	c, err := pgx.Connect(ctx, ownerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	var seq, lastTS int64
	var prev string
	if err := c.QueryRow(ctx, `SELECT seq, hash, ts FROM audit.chain_head`).Scan(&seq, &prev, &lastTS); err != nil {
		t.Fatal(err)
	}
	cols := []string{"seq", "id", "ts", "space", "phase", "request_id", "account_id", "username", "roles", "actor", "ip", "ua", "action", "target", "params", "reason", "ticket", "result", "code", "prev_hash", "hash"}
	rows := make([][]any, 0, n)
	for i := range n {
		seq++
		ts := max(tsOf(i), lastTS)
		lastTS = ts
		id := ids.New(time.UnixMilli(ts))
		s := audit.Stored{Seq: seq, ID: id, TS: ts, Space: "admin", Phase: "event", RequestID: id, Roles: `[]`, Actor: "seed", Action: "seed.write", Target: `{}`, Params: `{}`, Result: "success", PrevHash: prev}
		h, err := s.Recompute()
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, []any{s.Seq, s.ID, s.TS, s.Space, s.Phase, s.RequestID, "", "", s.Roles, s.Actor, "", "", s.Action, s.Target, s.Params, "", "", s.Result, 0, s.PrevHash, h})
		prev = h
	}
	if _, err := c.CopyFrom(ctx, pgx.Identifier{"audit", "records"}, cols, pgx.CopyFromRows(rows)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(ctx, `UPDATE audit.chain_head SET seq = $1, hash = $2, ts = $3`, seq, prev, lastTS); err != nil {
		t.Fatal(err)
	}
}

// ownerExec 以超级账号执行：模拟有库权限的攻击者。
func ownerExec(t *testing.T, ownerURL, sql string, args ...any) {
	t.Helper()
	c, err := pgx.Connect(context.Background(), ownerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(context.Background())
	if _, err := c.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal(err)
	}
}

// anchorRig 是一个 WORM 桶和对应的配置。
type anchorRig struct {
	bucket *objstoretest.Server
	env    map[string]string
}

func newAnchorRig(t *testing.T) *anchorRig {
	f := objstoretest.New(t, "anchor")
	return &anchorRig{bucket: f, env: map[string]string{
		"CON_AUDIT_ANCHOR": "s3://anchor/prod", "CON_AUDIT_ANCHOR_ENDPOINT": f.URL(),
		"CON_AUDIT_ANCHOR_ACCESS_KEY": f.Writer.AccessKey, "CON_AUDIT_ANCHOR_SECRET_KEY": f.Writer.SecretKey,
		"CON_AUDIT_ANCHOR_READ_ACCESS_KEY": f.Reader.AccessKey, "CON_AUDIT_ANCHOR_READ_SECRET_KEY": f.Reader.SecretKey,
	}}
}

func envList(appURL string, maps ...map[string]string) []string {
	out := []string{"CON_DATABASE_URL=" + appURL}
	for _, m := range maps {
		for k, v := range m {
			out = append(out, k+"="+v)
		}
	}
	return out
}

func wantVerify(t *testing.T, env []string, wantFail bool, wants ...string) string {
	t.Helper()
	out, err := run(t, env, "audit", "verify")
	if wantFail != (err != nil) {
		t.Errorf("verify err=%v, wantFail=%v\n%s", err, wantFail, out)
	}
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("verify output misses %q:\n%s", w, out)
		}
	}
	return out
}

// anchorAt 把链头写成一个外部锚定（走真实的 AnchorTick，靠跨整点触发）。
func (w *world) anchorNow() {
	w.t.Helper()
	w.advance(time.Hour)
	if err := w.a.AnchorTick(context.Background()); err != nil {
		w.t.Fatal(err)
	}
}

// 重算第 from 条起的整条链：攻击者的做法。
func rewriteChain(t *testing.T, ownerURL string, from int64) {
	t.Helper()
	ctx := context.Background()
	c, err := pgx.Connect(ctx, ownerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	prev := ""
	if from > 1 {
		if err := c.QueryRow(ctx, `SELECT hash FROM audit.records WHERE seq = $1`, from-1).Scan(&prev); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := c.Query(ctx, `SELECT `+audit.StoredColumns+` FROM audit.records WHERE seq >= $1 ORDER BY seq`, from)
	if err != nil {
		t.Fatal(err)
	}
	var list []audit.Stored
	for rows.Next() {
		var s audit.Stored
		if err := s.Scan(rows); err != nil {
			t.Fatal(err)
		}
		list = append(list, s)
	}
	rows.Close()
	for i := range list {
		list[i].PrevHash = prev
		h, err := list[i].Recompute()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Exec(ctx, `UPDATE audit.records SET prev_hash = $1, hash = $2 WHERE seq = $3`, prev, h, list[i].Seq); err != nil {
			t.Fatal(err)
		}
		prev = h
	}
	if _, err := c.Exec(ctx, `UPDATE audit.chain_head SET hash = $1`, prev); err != nil {
		t.Fatal(err)
	}
}

// AC-CON-08-5：删除中间记录。
func TestCON08VerifyGap(t *testing.T) {
	owner, appURL := newDB(t)
	seedChain(t, owner, 1000, func(i int) int64 { return 1_800_000_000_000 + int64(i) })
	env := envList(appURL)
	out := wantVerify(t, env, false, "OK", "records=1000", "source=database")
	if !strings.Contains(out, "anchors were read from the database only") {
		t.Errorf("no warning about the anchor source:\n%s", out)
	}
	ownerExec(t, owner, `DELETE FROM audit.records WHERE seq = 500`)
	wantVerify(t, env, true, "gap", "seq=500")
	// 通过和失败都写了 event 审计。
	c, _ := pgx.Connect(context.Background(), owner)
	defer c.Close(context.Background())
	var ok, failed int
	_ = c.QueryRow(context.Background(), `SELECT count(*) FILTER (WHERE result = 'success'), count(*) FILTER (WHERE result = 'failure') FROM audit.records WHERE action = 'audit.verify' AND actor LIKE 'cli:%@%'`).Scan(&ok, &failed)
	if ok != 1 || failed != 1 {
		t.Errorf("verify audit: ok=%d failed=%d", ok, failed)
	}
}

// TC-CON-08-08：只改一条不重算；--from-seq 跳过被改的段。
func TestCON08VerifyHashMismatch(t *testing.T) {
	owner, appURL := newDB(t)
	seedChain(t, owner, 100, func(i int) int64 { return 1_800_000_000_000 + int64(i) })
	ownerExec(t, owner, `UPDATE audit.records SET reason = 'tampered' WHERE seq = 10`)
	env := envList(appURL)
	wantVerify(t, env, true, "hashMismatch", "seq=10")
	if out, err := run(t, env, "audit", "verify", "--from-seq", "11"); err != nil || !strings.Contains(out, "first=11") {
		t.Errorf("from-seq: %v\n%s", err, out)
	}
	// 只改 prev_hash 并重算这一条：哈希对，但和上一条接不上。
	ownerExec(t, owner, `UPDATE audit.records SET reason = '' WHERE seq = 10`)
	c, _ := pgx.Connect(context.Background(), owner)
	defer c.Close(context.Background())
	rows, _ := c.Query(context.Background(), `SELECT `+audit.StoredColumns+` FROM audit.records WHERE seq = 20`)
	var s audit.Stored
	rows.Next()
	if err := s.Scan(rows); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	s.PrevHash = "bogus"
	h, _ := s.Recompute()
	ownerExec(t, owner, `UPDATE audit.records SET prev_hash = 'bogus', hash = $1 WHERE seq = 20`, h)
	wantVerify(t, env, true, "hashMismatch", "seq=20")
}

// AC-CON-08-6：锚定之后的截断通过，锚定之前的截断被发现。
func TestCON08VerifyTruncated(t *testing.T) {
	rig := newAnchorRig(t)
	w := newWorld(t, rig.env)
	base := w.now.UnixMilli()
	seedChain(t, w.owner, 900, func(i int) int64 { return base })
	w.anchorNow()
	seedChain(t, w.owner, 100, func(i int) int64 { return w.now.UnixMilli() })
	appEnv := envList(w.a.Cfg.DatabaseURL.Raw(), rig.env)
	wantVerify(t, appEnv, false, "OK", "source=external")

	ownerExec(t, w.owner, `DELETE FROM audit.records WHERE seq >= 950`)
	out := wantVerify(t, appEnv, false, "OK")
	if !strings.Contains(out, "may have been removed") {
		t.Errorf("no warning about the chain head:\n%s", out)
	}
	ownerExec(t, w.owner, `DELETE FROM audit.records WHERE seq >= 850`)
	wantVerify(t, appEnv, true, "truncated", "seq=850", "latest anchor is seq 900")
	// 连 audit.anchors 一起删也一样：比的是外部存储。上一次校验写的事件也要一起删掉，才算尾部截断。
	ownerExec(t, w.owner, `DELETE FROM audit.records WHERE seq >= 850`)
	ownerExec(t, w.owner, `DELETE FROM audit.anchors`)
	wantVerify(t, appEnv, true, "truncated", "seq=850")
}

// AC-CON-08-7：改记录并整链重算。
func TestCON08VerifyRewrittenChain(t *testing.T) {
	rig := newAnchorRig(t)
	w := newWorld(t, rig.env)
	seedChain(t, w.owner, 500, func(i int) int64 { return w.now.UnixMilli() })
	w.anchorNow()
	seedChain(t, w.owner, 500, func(i int) int64 { return w.now.UnixMilli() })
	w.anchorNow()
	if n := len(rig.bucket.Objects()); n != 2 {
		t.Fatalf("anchors in bucket = %d", n)
	}
	env := envList(w.a.Cfg.DatabaseURL.Raw(), rig.env)
	wantVerify(t, env, false, "OK", "anchors=2")

	ownerExec(t, w.owner, `UPDATE audit.records SET reason = 'tampered' WHERE seq = 10`)
	rewriteChain(t, w.owner, 10)
	wantVerify(t, env, true, "anchorMismatch", "seq=500")

	// 攻击者把库里的锚定也改掉：只比对库的话看不出来，比对外部存储还是能发现。
	ownerExec(t, w.owner, `UPDATE audit.anchors a SET hash = r.hash FROM audit.records r WHERE r.seq = a.seq`)
	wantVerify(t, env, true, "anchorMismatch", "seq=500")
	dbOnly := envList(w.a.Cfg.DatabaseURL.Raw(), map[string]string{"CON_AUDIT_ANCHOR": rig.env["CON_AUDIT_ANCHOR"], "CON_AUDIT_ANCHOR_ENDPOINT": rig.bucket.URL(),
		"CON_AUDIT_ANCHOR_ACCESS_KEY": rig.bucket.Writer.AccessKey, "CON_AUDIT_ANCHOR_SECRET_KEY": rig.bucket.Writer.SecretKey})
	wantVerify(t, dbOnly, false, "anchors were read from the database only")
}

// 持有写入凭证的人写不掉旧锚定：伪造的只会多一个对象，校验时两条都要匹配。
func TestCON08ForgedAnchorDoesNotOverride(t *testing.T) {
	rig := newAnchorRig(t)
	w := newWorld(t, rig.env)
	seedChain(t, w.owner, 100, func(i int) int64 { return w.now.UnixMilli() })
	w.anchorNow()
	ownerExec(t, w.owner, `UPDATE audit.records SET reason = 'tampered' WHERE seq = 10`)
	rewriteChain(t, w.owner, 10)
	c, _ := pgx.Connect(context.Background(), w.owner)
	defer c.Close(context.Background())
	var newHash string
	if err := c.QueryRow(context.Background(), `SELECT hash FROM audit.records WHERE seq = 100`).Scan(&newHash); err != nil {
		t.Fatal(err)
	}
	if err := w.a.Anchor.Put(context.Background(), anchor.Point{Seq: 100, Hash: newHash, TS: 1}); err != nil {
		t.Fatal(err)
	}
	wantVerify(t, envList(w.a.Cfg.DatabaseURL.Raw(), rig.env), true, "anchorMismatch", "seq=100")
}

// AC-CON-08-8（校验部分）：两个实例并发写，校验通过。
func TestCON08VerifyAfterConcurrentWrites(t *testing.T) {
	rig := newAnchorRig(t)
	w := newWorld(t, rig.env)
	var wg sync.WaitGroup
	for inst := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				if err := w.a.Audit.Write(context.Background(), audit.Record{Space: "admin", Phase: audit.PhaseEvent, RequestID: fmt.Sprintf("r%d", inst), Action: "x.y", Result: audit.Success}); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	wantVerify(t, envList(w.a.Cfg.DatabaseURL.Raw(), rig.env), false, "records=200")
}

// AC-CON-08-12：整点锚定，内容和库一致，写入凭证删不掉、也读不了。
func TestCON08AnchorHourly(t *testing.T) {
	rig := newAnchorRig(t)
	w := newWorld(t, rig.env)
	ctx := context.Background()
	seedChain(t, w.owner, 5, func(i int) int64 { return w.now.UnixMilli() })
	if err := w.a.AnchorTick(ctx); err != nil { // 第一次：还没有锚定，有记录就写
		t.Fatal(err)
	}
	if n := len(rig.bucket.Objects()); n != 1 {
		t.Fatalf("first anchor: %d", n)
	}
	seedChain(t, w.owner, 3, func(i int) int64 { return w.now.UnixMilli() })
	if err := w.a.AnchorTick(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(rig.bucket.Objects()); n != 1 {
		t.Errorf("anchored again within the hour: %d", n)
	}
	w.advance(time.Hour)
	if err := w.a.AnchorTick(ctx); err != nil {
		t.Fatal(err)
	}
	objs := rig.bucket.Objects()
	if len(objs) != 2 {
		t.Fatalf("after one hour: %d", len(objs))
	}
	var seq int64
	var hash string
	if err := w.db.QueryRow(ctx, `SELECT seq, hash FROM audit.records ORDER BY seq DESC LIMIT 1`).Scan(&seq, &hash); err != nil {
		t.Fatal(err)
	}
	key := "prod/" + anchor.Key(anchor.Point{Seq: seq, Hash: hash})
	obj, ok := objs[key]
	if !ok {
		t.Fatalf("no object %s in %v", key, objs)
	}
	var p anchor.Point
	if err := json.Unmarshal(obj.Body, &p); err != nil || p.Seq != seq || p.Hash != hash || p.TS != w.now.UnixMilli() {
		t.Errorf("object = %s %v", obj.Body, err)
	}
	if obj.Mode != "COMPLIANCE" || obj.RetainUntil.Before(time.Now().Add(3*365*24*time.Hour)) {
		t.Errorf("lock = %s until %v", obj.Mode, obj.RetainUntil)
	}
	var dbHash string
	if err := w.db.QueryRow(ctx, `SELECT hash FROM audit.anchors WHERE seq = $1`, seq).Scan(&dbHash); err != nil || dbHash != hash {
		t.Errorf("audit.anchors = %q %v", dbHash, err)
	}
	// 没有新记录：过了整点也不写。
	w.advance(time.Hour)
	if err := w.a.AnchorTick(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(rig.bucket.Objects()); n != 2 {
		t.Errorf("anchored without new records: %d", n)
	}
	writer := objstore.New(objstore.Config{Endpoint: rig.bucket.URL(), Bucket: "anchor", Prefix: "prod", AccessKey: rig.bucket.Writer.AccessKey, SecretKey: []byte(rig.bucket.Writer.SecretKey)})
	if err := writer.Delete(ctx, anchor.Key(p)); !objstore.IsDenied(err) {
		t.Errorf("delete = %v", err)
	}
	if _, err := writer.Get(ctx, anchor.Key(p)); !objstore.IsDenied(err) {
		t.Errorf("get = %v", err)
	}
	if _, err := w.db.Exec(ctx, `UPDATE audit.anchors SET hash = 'x'`); !isPermissionDenied(err) {
		t.Errorf("console_app updated anchors: %v", err)
	}
}

// TC-CON-08-14：满 1000 条立即锚定；失败告警、重试，恢复后补上。
func TestCON08AnchorEvery1000AndRetry(t *testing.T) {
	rig := newAnchorRig(t)
	w := newWorld(t, rig.env)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a1 := w.super("adm1")
	aud := a1.create("aud1", "auditor")
	kf := a1.create("kf1", "support")
	ops := w.opsSuper("ops1")
	if err := w.a.AnchorTick(ctx); err != nil { // 先把账号操作的审计锚定掉
		t.Fatal(err)
	}
	base := len(rig.bucket.Objects())
	var head int64
	if err := w.db.QueryRow(ctx, `SELECT seq FROM audit.chain_head`).Scan(&head); err != nil {
		t.Fatal(err)
	}
	// 同一小时内，靠写入唤醒后台任务（RunJobs），不等每分钟的那一轮。
	jobsDone := make(chan struct{})
	go func() { defer close(jobsDone); w.a.RunJobs(ctx) }()
	for range 1000 + int(1000-(head%1000)) {
		if err := w.a.Audit.Write(ctx, audit.Record{Space: "admin", Phase: audit.PhaseEvent, RequestID: "r", Action: "x.y", Result: audit.Success}); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for len(rig.bucket.Objects()) == base && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := len(rig.bucket.Objects()); n <= base {
		t.Fatalf("no anchor after 1000 records: %d", n)
	}
	cancel()
	<-jobsDone
	ctx = context.Background()

	rig.bucket.SetDown(true)
	seedChain(t, w.owner, 1000, func(i int) int64 { return w.now.UnixMilli() })
	if err := w.a.AnchorTick(ctx); err == nil {
		t.Fatal("anchor to a down store succeeded")
	}
	if err := w.a.AnchorTick(ctx); err == nil {
		t.Fatal("anchor to a down store succeeded")
	}
	if v := metricValue(t, w, "console_audit_anchor_failures_total"); v != 2 {
		t.Errorf("failures metric = %v", v)
	}
	count := func(u *user) int {
		n := 0
		for _, s := range w.notifications(u) {
			if strings.HasPrefix(s, "audit.anchor_failed:") {
				n++
			}
		}
		return n
	}
	// 超管和审计员各收到一条（重试不重复发）；客服收不到；运维空间也是同一条链。
	if count(a1) != 1 || count(aud) != 1 || count(kf) != 0 || count(ops) != 1 {
		t.Errorf("notified: a1=%d aud=%d kf=%d ops=%d", count(a1), count(aud), count(kf), count(ops))
	}
	var before int
	_ = w.db.QueryRow(ctx, `SELECT count(*) FROM audit.anchors`).Scan(&before)
	rig.bucket.SetDown(false)
	w.advance(time.Minute)
	if err := w.a.AnchorTick(ctx); err != nil {
		t.Fatal(err)
	}
	var seq, head2 int64
	_ = w.db.QueryRow(ctx, `SELECT max(seq) FROM audit.anchors`).Scan(&seq)
	_ = w.db.QueryRow(ctx, `SELECT seq FROM audit.chain_head`).Scan(&head2)
	if seq != head2 {
		t.Errorf("after recovery: anchor %d head %d", seq, head2)
	}
	if strings.Contains(w.logs.String(), rig.bucket.Writer.SecretKey) {
		t.Error("anchor secret in logs")
	}
	// 校验失败也通知。
	ownerExec(t, w.owner, `DELETE FROM audit.records WHERE seq = 5`)
	wantVerify(t, envList(w.a.Cfg.DatabaseURL.Raw(), rig.env), true, "gap", "seq=5")
	if !hasNotice(w.notifications(aud), "audit.verify_failed", "gap") || !hasNotice(w.notifications(a1), "audit.verify_failed", "gap") {
		t.Error("verify failure not notified")
	}
}

// 日志平台形式的锚定：POST 写入、GET 读回。
func TestCON08AnchorHTTPSink(t *testing.T) {
	var mu sync.Mutex
	var points []anchor.Point
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == "POST" && r.Header.Get("Authorization") == "Bearer write-token":
			var p anchor.Point
			_ = json.NewDecoder(r.Body).Decode(&p)
			points = append(points, p)
		case r.Method == "GET" && r.Header.Get("Authorization") == "Bearer read-token":
			_ = json.NewEncoder(w).Encode(points)
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer srv.Close()
	env := map[string]string{"CON_AUDIT_ANCHOR": srv.URL, "CON_AUDIT_ANCHOR_TOKEN": "write-token", "CON_AUDIT_ANCHOR_READ_TOKEN": "read-token"}
	w := newWorld(t, env)
	seedChain(t, w.owner, 10, func(i int) int64 { return w.now.UnixMilli() })
	if err := w.a.AnchorTick(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	n := len(points)
	mu.Unlock()
	if n != 1 {
		t.Fatalf("points = %d", n)
	}
	wantVerify(t, envList(w.a.Cfg.DatabaseURL.Raw(), env), false, "source=external", "anchors=1")
	ownerExec(t, w.owner, `UPDATE audit.records SET reason = 'x' WHERE seq = 10`)
	rewriteChain(t, w.owner, 10)
	wantVerify(t, envList(w.a.Cfg.DatabaseURL.Raw(), env), true, "anchorMismatch", "seq=10")
}

// 生产环境没有读取凭证时 verify 拒绝运行：只比对库发现不了整链重算。
func TestCON08VerifyRequiresReaderInProduction(t *testing.T) {
	owner, appURL := newDB(t)
	seedChain(t, owner, 3, func(i int) int64 { return 1_800_000_000_000 })
	out, err := run(t, prodEnv(appURL), "audit", "verify")
	if err == nil || !strings.Contains(out, "CON_AUDIT_ANCHOR_READ") {
		t.Errorf("err=%v\n%s", err, out)
	}
}

func isPermissionDenied(err error) bool {
	return err != nil && strings.Contains(err.Error(), "permission denied")
}

// ---------- CS-014 ----------

func auditURL(from, to int64, extra string) string {
	return fmt.Sprintf("/console/api/audit?from=%d&to=%d%s", from, to, extra)
}

// AC-CON-09-2、09-3、09-4、09-5、09-9。
func TestCON09Query(t *testing.T) {
	w := newWorld(t, nil)
	a1 := w.super("adm1")
	aud := a1.create("aud1", "auditor")
	kf := a1.create("kf1", "support")
	ops := w.opsSuper("ops1")
	opsAud := ops.create("oaud1", "ops_auditor")
	now := w.now.UnixMilli()
	from := now - 24*3600*1000

	// 权限：只有审计员。
	expect(t, "support", kf.do("GET", auditURL(from, now, ""), nil), 403, 4030)
	expect(t, "super admin", a1.do("GET", auditURL(from, now, ""), nil), 403, 4030)
	expect(t, "anonymous", w.client("x").do("GET", auditURL(from, now, ""), nil), 401, 4014)

	// 时间范围。
	day := int64(24 * 3600 * 1000)
	expect(t, "32 days", aud.do("GET", auditURL(now-32*day, now, ""), nil), 400, 4000)
	expect(t, "31 days", aud.do("GET", auditURL(now-31*day, now, ""), nil), 200, 0)
	expect(t, "no range", aud.do("GET", "/console/api/audit", nil), 400, 4000)
	expect(t, "reversed", aud.do("GET", auditURL(now, now-1, ""), nil), 400, 4000)
	expect(t, "limit", aud.do("GET", auditURL(from, now, "&limit=201"), nil), 400, 4000)
	expect(t, "result", aud.do("GET", auditURL(from, now, "&result=nope"), nil), 400, 4000)

	// 筛选 + 查询本身留痕。
	w.tick()
	now = w.now.UnixMilli()
	r := aud.do("GET", auditURL(from, now, "&actor=adm1&action=account.create&result=success"), nil)
	expect(t, "filter", r, 200, 0)
	records := r.body["records"].([]any)
	if len(records) != 2 { // adm1 建了 aud1、kf1：两条 result。intent 的 result 字段是空的，被筛掉
		t.Errorf("filtered = %d: %s", len(records), r.raw)
	}
	for _, it := range records {
		m := it.(map[string]any)
		if m["actor"] != "adm1" || m["action"] != "account.create" || m["result"] != "success" || m["space"] != "admin" {
			t.Errorf("record = %v", m)
		}
	}
	q := w.auditRows(`action = 'audit.query' AND username = 'aud1' AND params LIKE '%account.create%'`)
	if len(q) != 1 || !strings.Contains(q[0]["params"].(string), `"actor":"adm1"`) {
		t.Errorf("audit.query = %v", q)
	}
	// 目标筛选。
	r = aud.do("GET", auditURL(from, now, "&target=account:kf1&result=success&action=account.create"), nil)
	if list := r.body["records"].([]any); len(list) != 1 {
		t.Errorf("target filter = %s", r.raw)
	}
	r = aud.do("GET", auditURL(from, now, "&target=nobody"), nil)
	if list := r.body["records"].([]any); len(list) != 0 {
		t.Errorf("target nobody = %s", r.raw)
	}

	// 跨空间（AC-CON-09-4、09-9）。
	for _, sp := range []string{"ops", "all", "bogus"} {
		expect(t, "admin auditor space="+sp, aud.do("GET", auditURL(from, now, "&space="+sp), nil), 403, 4030)
	}
	if err := w.a.FlushDenied(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rows := w.auditRows(`result = 'denied' AND username = 'aud1' AND action = 'audit.query'`); len(rows) == 0 {
		t.Error("denied cross-space query not audited")
	}
	r = opsAud.do("GET", auditURL(from, now, "&space=all&action=account.create&result=success"), nil)
	spaces := map[string]bool{}
	for _, it := range r.body["records"].([]any) {
		spaces[it.(map[string]any)["space"].(string)] = true
	}
	if !spaces["admin"] || !spaces["ops"] {
		t.Errorf("ops auditor all spaces = %s", r.raw)
	}
	r = opsAud.do("GET", auditURL(from, now, "&action=account.create&result=success"), nil)
	for _, it := range r.body["records"].([]any) {
		if it.(map[string]any)["space"] != "ops" {
			t.Errorf("default space leaks: %v", it)
		}
	}
	expect(t, "ops auditor bogus", opsAud.do("GET", auditURL(from, now, "&space=bogus"), nil), 403, 4030)

	// 只读（AC-CON-09-5）。
	for _, m := range []string{"PATCH", "DELETE", "PUT", "POST"} {
		for _, p := range []string{"/console/api/audit", "/console/api/audit/requests/abc", "/console/api/audit/im"} {
			if r := aud.do(m, p, map[string]any{}); r.status != 405 {
				t.Errorf("%s %s = %d", m, p, r.status)
			}
		}
	}

	// 查询审计写失败：不返回数据。
	w.a.SetAuditFault("fail")
	r = aud.do("GET", auditURL(from, now, ""), nil)
	expect(t, "audit down", r, 503, 5031)
	if strings.Contains(r.raw, "account.create") {
		t.Error("data returned without audit")
	}
	w.a.SetAuditFault("ok")
}

func TestCON09Pagination(t *testing.T) {
	w := newWorld(t, nil)
	a1 := w.super("adm1")
	aud := a1.create("aud1", "auditor")
	base := w.now.UnixMilli()
	seedChain(t, w.owner, 25, func(i int) int64 { return base })
	seen := map[float64]bool{}
	cursor := ""
	last := float64(1 << 60)
	for page := 0; ; page++ {
		r := aud.do("GET", auditURL(base-1, base+1, "&action=seed.write&limit=10"+cursor), nil)
		expect(t, "page", r, 200, 0)
		for _, it := range r.body["records"].([]any) {
			s := it.(map[string]any)["seq"].(float64)
			if s >= last {
				t.Errorf("not descending: %v after %v", s, last)
			}
			last = s
			seen[s] = true
		}
		next := r.body["nextCursor"].(float64)
		if next == 0 {
			break
		}
		cursor = fmt.Sprintf("&cursor=%d", int64(next))
		if page > 5 {
			t.Fatal("pagination does not end")
		}
	}
	if len(seen) != 25 {
		t.Errorf("seen %d", len(seen))
	}
}

// fakeIM 是 im-server 的 /admin/audit。
type fakeIM struct {
	srv     *httptest.Server
	mu      sync.Mutex
	entries map[string][]map[string]any
	fail    atomic.Bool
	calls   atomic.Int64
	delay   time.Duration
	seenIDs []string
}

func newFakeIM(t *testing.T) *fakeIM {
	f := &fakeIM{entries: map[string][]map[string]any{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		if f.delay > 0 {
			time.Sleep(f.delay)
		}
		if f.fail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"code":5030,"msg":"down"}`))
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.seenIDs = append(f.seenIDs, r.Header.Get("X-Request-Id"))
		list := f.entries[r.URL.Query().Get("requestId")]
		if list == nil {
			list = []map[string]any{}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"entries": list, "nextCursor": 0})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func imEnv(f *fakeIM) map[string]string {
	return map[string]string{"CON_IM_ADMIN_URL": f.srv.URL, "CON_IM_SIGNING_KEY": b64(testSeed)}
}

func (w *world) intent(requestID, action string) {
	w.t.Helper()
	err := w.a.Audit.Write(context.Background(), audit.Record{Space: "admin", Phase: audit.PhaseIntent, RequestID: requestID, AccountID: "acct", Username: "kf1", Actor: "kf1",
		Roles: []string{"support"}, IP: "10.0.0.9", UA: "ua", Action: action, Target: audit.NewTarget("user", "u1"), Reason: "why", Ticket: "T-1"})
	if err != nil {
		w.t.Fatal(err)
	}
}

// AC-CON-09-6、AC-CON-08-9、08-10 的对账部分。
func TestCON09Reconcile(t *testing.T) {
	im := newFakeIM(t)
	w := newWorld(t, imEnv(im))
	ctx := context.Background()
	w.intent("r-none", "user.kick")
	w.intent("r-ok", "user.kick")
	w.intent("r-bad", "user.kick")
	w.intent("r-started", "user.kick")
	w.intent("r-unknown", "user.kick")
	w.intent("r-local", "account.disable")
	w.intent("r-done", "user.kick")
	if err := w.a.Audit.Write(ctx, audit.Record{Space: "admin", Phase: audit.PhaseResult, RequestID: "r-done", Action: "user.kick", Result: audit.Success}); err != nil {
		t.Fatal(err)
	}
	if err := w.a.Audit.Write(ctx, audit.Record{Space: "admin", Phase: audit.PhaseResult, RequestID: "r-unknown", Action: "user.kick", Result: audit.Unknown, Code: 5040}); err != nil {
		t.Fatal(err)
	}
	im.entries["r-ok"] = []map[string]any{{"phase": "intent", "code": 0}, {"phase": "result", "code": 0}}
	im.entries["r-unknown"] = []map[string]any{{"phase": "intent", "code": 0}, {"phase": "result", "code": 0}}
	im.entries["r-bad"] = []map[string]any{{"phase": "intent", "code": 0}, {"phase": "result", "code": 4042}}
	im.entries["r-started"] = []map[string]any{{"phase": "intent", "code": 0}}

	// 不到 5 分钟不动。
	w.advance(4 * time.Minute)
	if err := w.a.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if n := im.calls.Load(); n != 0 {
		t.Errorf("reconciled too early: %d calls", n)
	}
	// im-server 查询失败：什么都不写，不能当成"没执行"。
	w.advance(11 * time.Minute)
	im.fail.Store(true)
	if err := w.a.Reconcile(ctx); err == nil {
		t.Error("reconcile hid the im-server failure")
	}
	if rows := w.auditRows(`params LIKE '%notExecuted%' AND request_id <> 'r-local'`); len(rows) != 0 {
		t.Errorf("wrote a conclusion while im-server was down: %v", rows)
	}
	im.fail.Store(false)
	if err := w.a.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	check := func(id, result string, code int, marker string) {
		t.Helper()
		rows := w.auditRows(`request_id = $1 AND phase = 'result' AND params LIKE '%reconciled%'`, id)
		if len(rows) != 1 {
			t.Fatalf("%s: %d reconciled rows", id, len(rows))
		}
		r := rows[0]
		if r["result"] != result || int(r["code"].(int32)) != code || !strings.Contains(r["params"].(string), marker) {
			t.Errorf("%s = %v", id, r)
		}
		if r["username"] != "kf1" || r["action"] == "" || r["reason"] != "why" {
			t.Errorf("%s lost fields: %v", id, r)
		}
	}
	check("r-none", audit.Failure, 0, `"reconciled":"notExecuted"`)
	check("r-ok", audit.Success, 0, `"reconciled":true`)
	check("r-unknown", audit.Success, 0, `"reconciled":true`)
	check("r-bad", audit.Failure, 4042, `"reconciled":true`)
	check("r-started", audit.Unknown, 0, `"reconciled":"imIntentOnly"`)
	// 只改本地数据库的动作：不能说它"没执行"。
	check("r-local", audit.Unknown, 0, `"reconciled":"localOnly"`)
	if rows := w.auditRows(`request_id = 'r-done' AND params LIKE '%reconciled%'`); len(rows) != 0 {
		t.Errorf("reconciled a settled request: %v", rows)
	}
	// 再跑一次不重复补写，也不再调 im-server。
	calls := im.calls.Load()
	w.advance(11 * time.Minute)
	if err := w.a.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if im.calls.Load() != calls {
		t.Error("settled requests were queried again")
	}
	if rows := w.auditRows(`request_id = 'r-none' AND phase = 'result'`); len(rows) != 1 {
		t.Errorf("duplicate result: %v", rows)
	}
	// 查询自己的 requestId 不是被查的那个：否则下一轮会把查询当成执行过。
	im.mu.Lock()
	defer im.mu.Unlock()
	for _, id := range im.seenIDs {
		if strings.HasPrefix(id, "r-") {
			t.Errorf("query reused the target requestId: %s", id)
		}
	}
	// 校验仍然通过。
	res, err := audit.Verify(ctx, w.db, 0, nil)
	if err != nil || res.Issue != nil {
		t.Errorf("verify = %+v %v", res.Issue, err)
	}
}

// AC-CON-08-9 / 09-3 的页面数据：结果未知 + 详情合并。
func TestCON09ResultMissingAndDetail(t *testing.T) {
	im := newFakeIM(t)
	w := newWorld(t, imEnv(im))
	a1 := w.super("adm1")
	aud := a1.create("aud1", "auditor")
	ops := w.opsSuper("ops1")
	opsAud := ops.create("oaud1", "ops_auditor")
	w.intent("r-missing", "user.kick")
	now := w.now.UnixMilli()
	r := aud.do("GET", auditURL(now-1000, now+1000, "&requestId=r-missing"), nil)
	list := r.body["records"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["resultMissing"] != true {
		t.Errorf("result missing = %s", r.raw)
	}
	r = aud.do("GET", "/console/api/audit/requests/r-missing", nil)
	expect(t, "detail", r, 200, 0)
	if r.str("status") != "unknown" || r.body["intent"] == nil || len(r.body["results"].([]any)) != 0 {
		t.Errorf("detail = %s", r.raw)
	}
	w.advance(6 * time.Minute)
	if err := w.a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	r = aud.do("GET", "/console/api/audit/requests/r-missing", nil)
	if r.str("status") != "failure" || len(r.body["results"].([]any)) != 1 {
		t.Errorf("detail after reconcile = %s", r.raw)
	}
	now = w.now.UnixMilli()
	r = aud.do("GET", auditURL(now-3600000, now+1000, "&requestId=r-missing"), nil)
	for _, it := range r.body["records"].([]any) {
		if it.(map[string]any)["resultMissing"] == true {
			t.Errorf("still missing: %v", it)
		}
	}
	expect(t, "no such request", aud.do("GET", "/console/api/audit/requests/nope", nil), 404, 4040)

	// 跳转 im-server。
	im.mu.Lock()
	im.entries["r-missing"] = []map[string]any{{"phase": "result", "code": 0, "route": "x"}}
	im.mu.Unlock()
	r = aud.do("GET", "/console/api/audit/im?requestId=r-missing", nil)
	expect(t, "im", r, 200, 0)
	if len(r.body["entries"].([]any)) != 1 {
		t.Errorf("im = %s", r.raw)
	}
	if rows := w.auditRows(`action = 'audit.query' AND username = 'aud1' AND params LIKE '%"im":true%'`); len(rows) != 1 {
		t.Errorf("im query audit = %v", rows)
	}
	expect(t, "im no id", aud.do("GET", "/console/api/audit/im", nil), 400, 4000)

	// 空间隔离：管理审计员不能拿运维空间的 requestId 去查，详情和 im 跳转都不行。
	if err := w.a.Audit.Write(context.Background(), audit.Record{Space: "ops", Phase: audit.PhaseIntent, RequestID: "r-ops", Action: "ops.x"}); err != nil {
		t.Fatal(err)
	}
	im.mu.Lock()
	im.entries["r-ops"] = []map[string]any{{"phase": "result", "code": 0}}
	im.mu.Unlock()
	expect(t, "admin sees ops detail", aud.do("GET", "/console/api/audit/requests/r-ops", nil), 404, 4040)
	expect(t, "admin sees ops via im", aud.do("GET", "/console/api/audit/im?requestId=r-ops", nil), 404, 4040)
	expect(t, "admin asks space=ops", aud.do("GET", "/console/api/audit/requests/r-ops?space=ops", nil), 403, 4030)
	expect(t, "ops own", opsAud.do("GET", "/console/api/audit/requests/r-ops", nil), 200, 0)
	expect(t, "ops all admin", opsAud.do("GET", "/console/api/audit/requests/r-missing?space=all", nil), 200, 0)
	expect(t, "ops default admin", opsAud.do("GET", "/console/api/audit/requests/r-missing", nil), 404, 4040)

}

// im-server 不回答：504 / 5040。
func TestCON09IMTimeout(t *testing.T) {
	im := newFakeIM(t)
	env := imEnv(im)
	env["CON_IM_TIMEOUT"] = "50ms"
	w := newWorld(t, env)
	a1 := w.super("adm1")
	aud := a1.create("aud1", "auditor")
	w.intent("r-1", "user.kick")
	w.a.IMLatencyMs.Store(60_000)
	expect(t, "im timeout", aud.do("GET", "/console/api/audit/im?requestId=r-1", nil), 504, 5040)
	w.advance(6 * time.Minute)
	if err := w.a.Reconcile(context.Background()); err == nil {
		t.Error("reconcile hid the timeout")
	}
	if rows := w.auditRows(`request_id = 'r-1' AND phase = 'result'`); len(rows) != 0 {
		t.Errorf("wrote a conclusion on timeout: %v", rows)
	}
}

// TC-CON-09-07：两个实例同时对账，同一条只补一次。
func TestCON09ReconcileSingleInstance(t *testing.T) {
	im := newFakeIM(t)
	im.delay = 100 * time.Millisecond
	w := newWorld(t, imEnv(im))
	for i := range 3 {
		w.intent(fmt.Sprintf("r-%d", i), "user.kick")
	}
	w.advance(6 * time.Minute)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := w.a.Reconcile(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if rows := w.auditRows(`phase = 'result'`); len(rows) != 3 {
		t.Errorf("results = %d", len(rows))
	}
}

// ---------- CS-015 ----------

const monthMs = int64(30 * 24 * 3600 * 1000)

// AC-CON-09-7、09-8。
func TestCON09Archive(t *testing.T) {
	rig := newAnchorRig(t)
	archive := objstoretest.New(t, "archive")
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	w := newWorld(t, rig.env)
	ctx := context.Background()
	archiverURL := withDB(w.a.Cfg.DatabaseURL.Raw(), dbName(t, w.owner), "console_archiver")
	env := map[string]string{
		"CON_AUDIT_ARCHIVE": "s3://archive/audit", "CON_AUDIT_ARCHIVE_ENDPOINT": archive.URL(),
		"CON_AUDIT_ARCHIVE_ACCESS_KEY": archive.ReadWrite.AccessKey, "CON_AUDIT_ARCHIVE_SECRET_KEY": archive.ReadWrite.SecretKey,
		"CON_ARCHIVE_RECIPIENT": id.Recipient().String(), "CON_ARCHIVER_DATABASE_URL": archiverURL,
	}
	// 13 个月的数据：从 2025-11 到 2026-11，每月 100 条。[C 钟] 由环境变量传不进命令行，所以用真实时间推算。
	nowReal := time.Now().UTC()
	first := time.Date(nowReal.Year(), nowReal.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -13, 0)
	for m := range 13 {
		start := first.AddDate(0, m, 0)
		seedChain(t, w.owner, 100, func(i int) int64 { return start.Add(time.Duration(i) * time.Hour).UnixMilli() })
		w.a.Clock.Freeze(start.AddDate(0, 0, 10))
		w.anchorPoint(t, rig) // 每个月一个锚定
	}
	w.a.Clock.Freeze(nowReal)
	appEnv := envList(w.a.Cfg.DatabaseURL.Raw(), rig.env, env)
	wantVerify(t, appEnv, false, "OK", "records=1300", "source=external")

	// 没有归档配置时拒绝。
	if out, err := run(t, envList(w.a.Cfg.DatabaseURL.Raw(), rig.env), "audit", "archive"); err == nil || !strings.Contains(out, "CON_AUDIT_ARCHIVE") {
		t.Errorf("no config: %v %s", err, out)
	}

	// 运行账号不能删分区，也不能调用删除函数（AC-CON-09-8）。
	wantName := audit.PartitionName(first)
	if _, err := w.db.Exec(ctx, `SELECT audit.ensure_partition($1, $2)`, first.Year(), int(first.Month())); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{`DROP TABLE audit.` + wantName, `SELECT audit.drop_archived_partition('` + wantName + `')`, `TRUNCATE audit.` + wantName, `ALTER TABLE audit.records DETACH PARTITION audit.` + wantName, `DELETE FROM audit.records`, `UPDATE audit.records SET reason = 'x'`, `INSERT INTO audit.archives (partition_name, seq_first, seq_last, last_hash, record_count, object_key, ciphertext_sha256, archived_at, retain_until) VALUES ('x',1,1,'','1','','',0,0)`} {
		if _, err := w.db.Exec(ctx, sql); err == nil || (!isPermissionDenied(err) && !strings.Contains(err.Error(), "must be owner")) {
			t.Errorf("console_app %q: %v", sql, err)
		}
	}
	// 归档账号也不能直接 DROP，只能走函数，而且函数要求先有归档记录。
	arch, err := pgx.Connect(ctx, archiverURL)
	if err != nil {
		t.Fatal(err)
	}
	defer arch.Close(ctx)
	if _, err := arch.Exec(ctx, `DROP TABLE audit.`+wantName); err == nil {
		t.Error("archiver dropped a partition directly")
	}
	if _, err := arch.Exec(ctx, `SELECT audit.drop_archived_partition($1)`, wantName); err == nil || !strings.Contains(err.Error(), "no archive record") {
		t.Errorf("drop without record: %v", err)
	}
	if _, err := arch.Exec(ctx, `SELECT audit.drop_archived_partition('records_default')`); err == nil {
		t.Error("drop default partition")
	}

	out, err := run(t, appEnv, "audit", "archive")
	if err != nil {
		t.Fatalf("archive: %v\n%s", err, out)
	}
	if strings.Count(out, "archived ") != 1 || !strings.Contains(out, wantName) || !strings.Contains(out, "seq=1..100") {
		t.Errorf("archive output:\n%s", out)
	}
	// 分区没了。
	var reg *string
	if err := w.db.QueryRow(ctx, `SELECT to_regclass('audit.`+wantName+`')::text`).Scan(&reg); err != nil || reg != nil {
		t.Errorf("partition still exists: %v %v", reg, err)
	}
	// 解密后条数和哈希与链一致；桶里的对象被锁定 3 年。
	objs := archive.Objects()
	if len(objs) != 1 {
		t.Fatalf("archive objects = %d", len(objs))
	}
	for key, obj := range objs {
		if !strings.HasPrefix(key, "audit/archive/"+wantName) {
			t.Errorf("key = %s", key)
		}
		if bytes.Contains(obj.Body, []byte("seed.write")) {
			t.Error("archive is not encrypted")
		}
		if obj.Mode != "COMPLIANCE" || obj.RetainUntil.Before(time.Now().AddDate(2, 11, 0)) {
			t.Errorf("lock = %s %v", obj.Mode, obj.RetainUntil)
		}
		plain, err := age.Decrypt(bytes.NewReader(obj.Body), id)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(plain)
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) != 100 {
			t.Fatalf("lines = %d", len(lines))
		}
		prev := ""
		for i, l := range lines {
			var s audit.Stored
			if err := json.Unmarshal([]byte(l), &s); err != nil {
				t.Fatal(err)
			}
			h, _ := s.Recompute()
			if s.Seq != int64(i+1) || s.PrevHash != prev || h != s.Hash {
				t.Fatalf("line %d does not verify", i)
			}
			prev = s.Hash
		}
		var lastHash string
		if err := w.db.QueryRow(ctx, `SELECT last_hash FROM audit.archives WHERE partition_name = $1`, wantName).Scan(&lastHash); err != nil || lastHash != prev {
			t.Errorf("archive record = %q %v, want %q", lastHash, err, prev)
		}
	}
	// 写了审计；verify 从归档末条接续。
	var rec int
	_ = w.db.QueryRow(ctx, `SELECT count(*) FROM audit.records WHERE action = 'audit.archive' AND actor LIKE 'cli:%@%' AND target LIKE '%`+wantName+`%'`).Scan(&rec)
	if rec != 1 {
		t.Errorf("audit.archive = %d", rec)
	}
	wantVerify(t, appEnv, false, "OK", "first=101")
	// 再跑一次：没有到期的分区。
	if out, err := run(t, appEnv, "audit", "archive"); err != nil || !strings.Contains(out, "nothing to archive") {
		t.Errorf("second run: %v\n%s", err, out)
	}

	// 伪造归档记录：谎称更多记录已归档，再删掉它们。外部没有对应锚定，verify 能发现。
	second := audit.PartitionName(first.AddDate(0, 1, 0))
	ownerExec(t, w.owner, `INSERT INTO audit.archives (partition_name, seq_first, seq_last, last_hash, record_count, object_key, ciphertext_sha256, archived_at, retain_until) VALUES ($1, 101, 150, 'forged', 50, 'x', 'x', 0, 0)`, second)
	ownerExec(t, w.owner, `DELETE FROM audit.records WHERE seq BETWEEN 101 AND 150`)
	wantVerify(t, appEnv, true, "anchorMismatch", "seq=150")
	// 删掉归档记录：链头断了。
	ownerExec(t, w.owner, `DELETE FROM audit.archives`)
	wantVerify(t, appEnv, true, "gap", "seq=1")
}

// anchorPoint 把当前链头写一个外部锚定（直接写，时间不一定跨整点）。
func (w *world) anchorPoint(t *testing.T, rig *anchorRig) {
	t.Helper()
	ctx := context.Background()
	var p anchor.Point
	if err := w.db.QueryRow(ctx, `SELECT seq, hash FROM audit.chain_head`).Scan(&p.Seq, &p.Hash); err != nil {
		t.Fatal(err)
	}
	p.TS = w.a.Clock.Now().UnixMilli()
	if err := w.a.Anchor.Put(ctx, p); err != nil {
		t.Fatal(err)
	}
	if _, err := w.db.Exec(ctx, `INSERT INTO audit.anchors (seq, hash, ts) VALUES ($1, $2, $3)`, p.Seq, p.Hash, p.TS); err != nil {
		t.Fatal(err)
	}
}

func dbName(t *testing.T, raw string) string {
	t.Helper()
	i := strings.LastIndex(raw, "/")
	name, _, _ := strings.Cut(raw[i+1:], "?")
	return name
}

// 归档发现链有问题时不删分区。
func TestCON09ArchiveRefusesBrokenChain(t *testing.T) {
	rig := newAnchorRig(t)
	archive := objstoretest.New(t, "archive")
	id, _ := age.GenerateX25519Identity()
	w := newWorld(t, rig.env)
	archiverURL := withDB(w.a.Cfg.DatabaseURL.Raw(), dbName(t, w.owner), "console_archiver")
	env := map[string]string{
		"CON_AUDIT_ARCHIVE": "s3://archive", "CON_AUDIT_ARCHIVE_ENDPOINT": archive.URL(),
		"CON_AUDIT_ARCHIVE_ACCESS_KEY": archive.ReadWrite.AccessKey, "CON_AUDIT_ARCHIVE_SECRET_KEY": archive.ReadWrite.SecretKey,
		"CON_ARCHIVE_RECIPIENT": id.Recipient().String(), "CON_ARCHIVER_DATABASE_URL": archiverURL,
	}
	old := time.Now().UTC().AddDate(-2, 0, 0)
	seedChain(t, w.owner, 20, func(i int) int64 { return old.UnixMilli() })
	ownerExec(t, w.owner, `UPDATE audit.records SET reason = 'tampered' WHERE seq = 5`)
	appEnv := envList(w.a.Cfg.DatabaseURL.Raw(), rig.env, env)
	out, err := run(t, appEnv, "audit", "archive")
	if err == nil || !strings.Contains(out, "partition kept") || !strings.Contains(out, "hashMismatch") {
		t.Errorf("err=%v\n%s", err, out)
	}
	if n := len(archive.Objects()); n != 0 {
		t.Errorf("uploaded %d objects", n)
	}
	var c int
	_ = w.db.QueryRow(context.Background(), `SELECT count(*) FROM audit.records`).Scan(&c)
	if c < 20 {
		t.Errorf("records = %d", c)
	}
	// 存储不可用：同样不删。
	ownerExec(t, w.owner, `UPDATE audit.records SET reason = '' WHERE seq = 5`)
	archive.SetDown(true)
	if out, err := run(t, appEnv, "audit", "archive"); err == nil {
		t.Errorf("archived to a down store:\n%s", out)
	}
	_ = w.db.QueryRow(context.Background(), `SELECT count(*) FROM audit.records`).Scan(&c)
	if c < 20 {
		t.Errorf("records after failed upload = %d", c)
	}
}

// CS-015 内容 1：预建分区；默认分区里已有的数据搬过去；ts 单调。
func TestCON09Partitions(t *testing.T) {
	w := newWorld(t, nil)
	ctx := context.Background()
	month := audit.PartitionName(w.now)
	seedChain(t, w.owner, 10, func(i int) int64 { return w.now.UnixMilli() })
	count := func(table string) int {
		c, _ := pgx.Connect(ctx, w.owner)
		defer c.Close(ctx)
		var n int
		if err := c.QueryRow(ctx, `SELECT count(*) FROM audit.`+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count("records_default") != 10 {
		t.Fatal("seed did not land in the default partition")
	}
	if err := w.a.EnsurePartitions(ctx); err != nil {
		t.Fatal(err)
	}
	if err := w.a.EnsurePartitions(ctx); err != nil { // 幂等
		t.Fatal(err)
	}
	if count("records_default") != 0 || count(month) != 10 {
		t.Errorf("default=%d month=%d", count("records_default"), count(month))
	}
	next := audit.PartitionName(w.now.AddDate(0, 1, 0))
	if count(next) != 0 {
		t.Error("next month missing")
	}
	// 新分区运行账号不能直接碰，走父表可以读写。
	if _, err := w.db.Exec(ctx, `DELETE FROM audit.`+month); !isPermissionDenied(err) {
		t.Errorf("direct partition read: %v", err)
	}
	if err := w.a.Audit.Write(ctx, audit.Record{Space: "admin", Phase: audit.PhaseEvent, RequestID: "r", Action: "x.y", Result: audit.Success}); err != nil {
		t.Fatal(err)
	}
	if count(month) != 11 {
		t.Error("write did not reach the month partition")
	}
	res, err := audit.Verify(ctx, w.db, 0, nil)
	if err != nil || res.Issue != nil || res.Records != 11 {
		t.Errorf("verify = %+v %v", res, err)
	}
	// 时钟回拨（多实例偏差）：ts 不倒退，seq 不会跨分区交错。
	back := w.now.Add(-48 * time.Hour)
	w.a.Clock.Freeze(back)
	if err := w.a.Audit.Write(ctx, audit.Record{Space: "admin", Phase: audit.PhaseEvent, RequestID: "r2", Action: "x.y", Result: audit.Success}); err != nil {
		t.Fatal(err)
	}
	var ts int64
	if err := w.db.QueryRow(ctx, `SELECT ts FROM audit.records WHERE request_id = 'r2'`).Scan(&ts); err != nil || ts != w.now.UnixMilli() {
		t.Errorf("ts went backwards: %d %v", ts, err)
	}
	res, err = audit.Verify(ctx, w.db, 0, nil)
	if err != nil || res.Issue != nil {
		t.Errorf("verify = %+v %v", res, err)
	}
}

// 对账对真实的 im-server：签名、operator 格式、/admin/audit 的响应字段都是真的。
func TestCON09ReconcileAgainstRealIMServer(t *testing.T) {
	adminAddr, priv := startRealIM(t)
	w := newWorld(t, map[string]string{"CON_IM_ADMIN_URL": "http://" + adminAddr, "CON_IM_SIGNING_KEY": base64.StdEncoding.EncodeToString(priv.Seed())})
	w.a.Clock.Unfreeze() // im-server 校验签名时间戳
	ctx := context.Background()
	cl, err := imclient.New(imclient.Config{BaseURL: "http://" + adminAddr, Caller: "console", Key: priv})
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-6 * time.Minute).UnixMilli()
	intent := func(id string) {
		t.Helper()
		if err := w.a.Audit.Write(ctx, audit.Record{TS: past, Space: "admin", Phase: audit.PhaseIntent, RequestID: id, Actor: "kf1", Username: "kf1", Action: "user.import"}); err != nil {
			t.Fatal(err)
		}
	}
	// 执行成功、业务失败、console 根本没调用。
	intent("req-ok")
	if err := cl.Do(ctx, imclient.Call{Operator: "admin:7", RequestID: "req-ok"}, "POST", "/admin/users/import", nil, map[string]any{"users": []any{map[string]any{"userId": "u200", "nickname": "n"}}}, nil); err != nil {
		t.Fatal(err)
	}
	intent("req-bad")
	var wantCode int
	err = cl.Do(ctx, imclient.Call{Operator: "admin:7", RequestID: "req-bad"}, "POST", "/admin/users/import", nil, map[string]any{"users": "not-a-list"}, nil)
	var ae *apierr.Error
	if !errors.As(err, &ae) {
		t.Fatalf("bad import = %v", err)
	}
	wantCode = ae.Code
	intent("req-none")
	if err := w.a.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	check := func(id, result string, code int, marker string) {
		t.Helper()
		rows := w.auditRows(`request_id = $1 AND phase = 'result'`, id)
		if len(rows) != 1 || rows[0]["result"] != result || int(rows[0]["code"].(int32)) != code || !strings.Contains(rows[0]["params"].(string), marker) {
			t.Errorf("%s = %v", id, rows)
		}
	}
	check("req-ok", audit.Success, 0, `"reconciled":true`)
	check("req-bad", audit.Failure, wantCode, `"reconciled":true`)
	check("req-none", audit.Failure, 0, `"reconciled":"notExecuted"`)
}

// 真实的 MinIO（Object Lock）：只在 tools/minio-test.sh 启动了容器时运行（CI 里跑）。
func TestRealMinIOWORM(t *testing.T) {
	endpoint := os.Getenv("CON_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("CON_TEST_S3_ENDPOINT is not set; run tools/minio-test.sh")
	}
	ctx := context.Background()
	store := func(prefix string) *objstore.Store {
		return objstore.New(objstore.Config{Endpoint: endpoint, Bucket: os.Getenv("CON_TEST_S3_BUCKET"), AccessKey: os.Getenv("CON_TEST_S3_" + prefix + "_ACCESS"), SecretKey: []byte(os.Getenv("CON_TEST_S3_" + prefix + "_SECRET"))})
	}
	sink := &anchor.S3{Store: store("WRITER"), Retain: 24 * time.Hour}
	reader := &anchor.S3{Store: store("READER")}
	p := anchor.Point{Seq: time.Now().UnixNano(), Hash: "abc123", TS: 1}
	if err := sink.Put(ctx, p); err != nil {
		t.Fatal(err)
	}
	points, err := reader.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, got := range points {
		found = found || (got.Seq == p.Seq && got.Hash == p.Hash)
	}
	if !found {
		t.Errorf("anchor not listed: %v", points)
	}
	rc, err := store("READER").Get(ctx, anchor.Key(p))
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(rc)
	rc.Close()
	var body anchor.Point
	if err := json.Unmarshal(data, &body); err != nil || body.Seq != p.Seq {
		t.Errorf("body = %s %v", data, err)
	}
	// 写入凭证：删不掉、读不了、列不出。
	if err := store("WRITER").Delete(ctx, anchor.Key(p)); !objstore.IsDenied(err) {
		t.Errorf("writer delete = %v", err)
	}
	if _, err := store("WRITER").Get(ctx, anchor.Key(p)); !objstore.IsDenied(err) {
		t.Errorf("writer get = %v", err)
	}
	if _, err := sink.List(ctx); !objstore.IsDenied(err) {
		t.Errorf("writer list = %v", err)
	}
	// 读取凭证：写不了、删不掉。
	if err := store("READER").Put(ctx, "anchors/x.json", strings.NewReader("x"), time.Now().Add(time.Hour)); !objstore.IsDenied(err) {
		t.Errorf("reader put = %v", err)
	}
	if err := store("READER").Delete(ctx, anchor.Key(p)); !objstore.IsDenied(err) {
		t.Errorf("reader delete = %v", err)
	}
}
