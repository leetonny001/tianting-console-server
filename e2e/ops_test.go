package e2e

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"tianting/console/internal/app"
	"tianting/console/internal/imclient"
	"tianting/console/internal/opsnode"
)

const opsAPI = "/console/api/ops/v1"

func opsData(t *testing.T, r reply) map[string]any {
	t.Helper()
	if r.status != 200 {
		t.Fatalf("status %d: %s", r.status, r.raw)
	}
	d, ok := r.body["data"].(map[string]any)
	if !ok {
		t.Fatalf("no data: %s", r.raw)
	}
	if _, ok := r.body["dataTime"]; !ok {
		t.Errorf("no dataTime: %s", r.raw)
	}
	return d
}

// AC-OPS-02-1、02-3：清单 × 4 个角色 + 无会话。数据源是 YAML，和注册的路由已经在启动时比对过。
func TestOpsMatrix(t *testing.T) {
	n1 := startNode(t, "n1")
	o := newOpsWorld(t, n1)
	specs, err := app.OpsRouteSpecs()
	if err != nil || len(specs) == 0 {
		t.Fatal(specs, err)
	}
	matrix := map[string]map[string]bool{
		"ops.overview.read": {"viewer": true, "engineer": true},
		"ops.config.read":   {"viewer": true, "engineer": true},
		"ops.troubleshoot":  {"engineer": true},
	}
	users := map[string]*user{"viewer": o.viewer, "engineer": o.engineer, "auditor": o.auditor, "super": o.super}
	body := map[string]any{"userId": "u1", "ticket": "CS-1024", "reason": "用户反馈掉线"}
	anon := o.opsClient("nobody")
	for _, s := range specs {
		allowed, ok := matrix[s.Perm]
		if !ok {
			t.Errorf("%s: %s is not in the matrix", s.Path, s.Perm)
		}
		var b any
		if s.Method == "POST" {
			b = body
		}
		for name, u := range users {
			r := u.do(s.Method, opsAPI+s.Path, b)
			if allowed[name] {
				if r.status == 403 {
					t.Errorf("%s %s as %s = 403", s.Method, s.Path, name)
				}
			} else if r.status != 403 || r.code() != 4030 {
				t.Errorf("%s %s as %s = %d %s", s.Method, s.Path, name, r.status, r.raw)
			}
		}
		expect(t, s.Path+" anon", anon.do(s.Method, opsAPI+s.Path, b), 401, 4014)
		// 配置检查等只读接口对其他方法 405（AC-OPS-10-7）。
		if s.Method == "GET" {
			for _, m := range []string{"PUT", "POST", "PATCH", "DELETE"} {
				if r := o.engineer.do(m, opsAPI+s.Path, map[string]any{}); r.status != 405 {
					t.Errorf("%s %s = %d", m, s.Path, r.status)
				}
			}
		}
	}
	// 个人设置接口都能用。
	for name, u := range users {
		expect(t, name+" session", u.do("GET", "/console/api/session", nil), 200, 0)
	}
	// 运维空间没有应急授权（AC-OPS-02-9）。
	o.super.stepUp()
	expect(t, "emergency", o.super.do("POST", "/console/api/me/emergency-grants", map[string]any{"role": "ops_engineer", "minutes": 30, "reason": goodReason}), 403, 4030)
	// 管理空间路由不存在。
	expect(t, "admin route", o.engineer.do("GET", "/console/api/users?q=a", nil), 404, 4040)
	// 管理空间的会话到不了运维接口（AC-OPS-01-14）。
	adm := o.super2Admin()
	r := adm.do("GET", opsAPI+"/nodes", nil)
	if r.status != 404 && r.status != 403 {
		t.Errorf("admin space reached ops: %d %s", r.status, r.raw)
	}
	// 越权记录带目标（AC-OPS-02-5）。
	rows := o.auditRows(`action = 'ops.troubleshoot.query' AND result = 'denied' AND username = 'oview1'`)
	if len(rows) == 0 || !strings.Contains(rows[0]["target"].(string), `"u1"`) || rows[0]["space"] == "admin" {
		t.Errorf("denied audit = %v", rows)
	}
}

func (o *opsWorld) super2Admin() *user       { return o.super2("adm9") }
func (o *opsWorld) super2(name string) *user { return o.world.super(name) }

// AC-OPS-05-1、05-2、05-3、04-1、04-4、11-3。
func TestOpsNodes(t *testing.T) {
	n1 := startNode(t, "n1", "IM_TEST_MODE=1", "IM_ADMIN_KEY=legacy-test-key")
	n2 := startNode(t, "n2")
	o := newOpsWorld(t, n1, n2)
	u := "u" + uid()
	n1.import_(t, u)
	c1 := n1.dial(t, o.world, u, "web")
	n1.dial(t, o.world, u, "web")
	n1.dial(t, o.world, u, "pc")
	time.Sleep(50 * time.Millisecond)
	o.probe()

	d := opsData(t, o.viewer.do("GET", opsAPI+"/nodes", nil))
	nodes := d["nodes"].([]any)
	if len(nodes) != 2 {
		t.Fatalf("nodes = %v", nodes)
	}
	first := nodes[0].(map[string]any)
	if first["nodeId"] != "n1" || first["status"] != "ready" || first["addr"] != n1.ops || first["version"] == "" || first["liveBytes"].(float64) <= 0 {
		t.Errorf("n1 = %v", first)
	}
	started := first["startedAt"]

	// 总览不扇出（AC-OPS-04-1）：只读探测结果。
	before := strings.Count(n1.logs.String(), "ops request")
	ov := opsData(t, o.viewer.do("GET", opsAPI+"/overview", nil))
	if n := strings.Count(n1.logs.String(), "ops request"); n != before {
		t.Errorf("overview called the node: %d -> %d", before, n)
	}
	conns := ov["connections"].(map[string]any)
	by := conns["byPlatform"].(map[string]any)
	if conns["total"].(float64) != 3 || by["web"].(float64) != 2 || by["pc"].(float64) != 1 || ov["status"] != "ok" {
		t.Errorf("overview = %v", ov)
	}
	_ = c1.ws.CloseNow()
	time.Sleep(100 * time.Millisecond)
	o.probe()
	ov = opsData(t, o.viewer.do("GET", opsAPI+"/overview", nil))
	if ov["connections"].(map[string]any)["total"].(float64) != 2 {
		t.Errorf("after close = %v", ov["connections"])
	}

	// 未就绪：store 故障注入（AC-OPS-11-3）。
	post := func(path, body string) {
		t.Helper()
		req, _ := http.NewRequest("POST", "http://"+n1.admin+path, strings.NewReader(body))
		req.Header.Set("X-Admin-Key", "legacy-test-key")
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("%s: %v %v", path, err, resp)
		}
		resp.Body.Close()
	}
	post("/admin/test/faults", `{"storePing":"fail"}`)
	time.Sleep(100 * time.Millisecond)
	o.probe()
	r := o.viewer.do("GET", opsAPI+"/nodes", nil)
	if got := opsData(t, r)["nodes"].([]any)[0].(map[string]any)["status"]; got != "notReady" {
		t.Errorf("store down = %v", got)
	}
	if ov := opsData(t, o.viewer.do("GET", opsAPI+"/overview", nil)); ov["status"] != "degraded" {
		t.Errorf("degraded = %v", ov["status"])
	}
	post("/admin/test/faults", `{"storePing":""}`)
	time.Sleep(100 * time.Millisecond)
	o.probe()

	// kill n2：一次失败还不算，15 秒后不可达，一直在列表里（AC-OPS-05-2）。
	o.probe()
	r = o.viewer.do("GET", opsAPI+"/nodes", nil)
	seen := opsData(t, r)["nodes"].([]any)[1].(map[string]any)["lastSeenAt"]
	_ = n2.cmd.Process.Kill()
	_ = n2.cmd.Wait()
	o.probe()
	if got := opsData(t, o.viewer.do("GET", opsAPI+"/nodes", nil))["nodes"].([]any)[1].(map[string]any); got["status"] != "ready" || got["lastSeenAt"] != seen {
		t.Errorf("right after kill = %v", got)
	}
	for range 3 {
		o.probe()
	}
	r = o.viewer.do("GET", opsAPI+"/nodes", nil)
	row := opsData(t, r)["nodes"].([]any)[1].(map[string]any)
	if row["status"] != "unreachable" || row["lastSeenAt"] != seen {
		t.Errorf("unreachable = %v (seen %v)", row, seen)
	}
	if r.body["partial"] != true || fmt.Sprint(r.body["missingNodes"]) != "[n2]" {
		t.Errorf("missing = %s", r.raw)
	}
	o.advance(24 * time.Hour)
	expect(t, "login", o.viewer.login(), 200, 0)
	if list := opsData(t, o.viewer.do("GET", opsAPI+"/nodes", nil))["nodes"].([]any); len(list) != 2 {
		t.Errorf("after a day = %v", list)
	}
	_ = started

	// 两个实例看到的一致（AC-OPS-05-5）：状态只来自库，5 秒内不重复探测。
	o.probe()
	before = strings.Count(n1.logs.String(), "ops request")
	if err := o.a.ProbeNodes(context.Background()); err != nil { // 同一时刻第二次：另一个实例
		t.Fatal(err)
	}
	if n := strings.Count(n1.logs.String(), "ops request"); n != before {
		t.Errorf("duplicate probes: %d -> %d", before, n)
	}
}

// fakeNode 是不校验签名的假节点：测真实节点造不出来的情况（版本不一致、下线中）。
func fakeNode(t *testing.T, id string, version *atomic.Value, draining *atomic.Bool) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"nodeId":%q,"version":%q,"ready":%v,"draining":%v,"connections":{"web":1},"totalConns":1,"startedAt":1}`, id, version.Load(), !draining.Load(), draining.Load())
	}))
	t.Cleanup(srv.Close)
	return srv
}

func fakeFleet(t *testing.T, o *opsWorld, servers map[string]*httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "k")
	if err := os.WriteFile(keyFile, []byte(b64(testSeed)), 0o600); err != nil {
		t.Fatal(err)
	}
	var rows []string
	for id, s := range servers {
		rows = append(rows, fmt.Sprintf(`{"nodeId":%q,"addr":%q,"keyFile":%q}`, id, strings.TrimPrefix(s.URL, "http://"), keyFile))
	}
	table := filepath.Join(dir, "t.json")
	if err := os.WriteFile(table, []byte("["+strings.Join(rows, ",")+"]"), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, problems := opsnode.LoadTable(table, false)
	if len(problems) > 0 {
		t.Fatal(problems)
	}
	f, err := opsnode.New(entries, "", o.a.Clock)
	if err != nil {
		t.Fatal(err)
	}
	o.a.Nodes = f
}

// AC-OPS-04-5、04-6、04-9、04-4、12-3：卡片互相独立；不可用不显示 0。
func TestOpsOverviewCards(t *testing.T) {
	o := newOpsWorld(t)
	var v1, v2 atomic.Value
	v1.Store("0.3.0")
	v2.Store("0.3.0")
	var d1, d2 atomic.Bool
	fakeFleet(t, o, map[string]*httptest.Server{"n1": fakeNode(t, "n1", &v1, &d1), "n2": fakeNode(t, "n2", &v2, &d2)})
	o.probe()
	o.prom.results.Store("increase(im_messages_total", "["+promVec("", 1200)+"]")
	o.prom.results.Store("rate(im_messages_total[1m]", "["+promVec("", 10)+"]")
	o.prom.results.Store("im_commands_total", "["+promVec("0", 21)+","+promVec("4290", 9)+"]")
	o.prom.results.Store(`phase="handshake"`, "["+promVec("4011", 5)+","+promVec("4401", 3)+"]")
	o.prom.results.Store(`phase="session"`, "["+promVec("1000", 7)+","+promVec("4012", 2)+","+promVec("4400", 1)+","+promVec("4429", 1)+"]")
	o.alerts.Store(`[{"labels":{"alertname":"HighErrorRate","severity":"critical","node_id":"n1"},"annotations":{"summary":"x"},"startsAt":"2027-01-15T00:00:00Z"}]`)
	now := o.now.UnixMilli()
	o.putManifest("im", now-1000, map[string]any{"source": "im", "result": "success", "finishedAt": now - 1000, "file": "/a/b/c.db.age"})

	ov := opsData(t, o.viewer.do("GET", opsAPI+"/overview", nil))
	if m := ov["messages"].(map[string]any); m["perSecond"].(float64) != 10 || m["today"].(float64) != 1200 {
		t.Errorf("messages = %v", m)
	}
	e := ov["errors"].(map[string]any)
	if e["share4xx"].(float64) != 0.3 || e["share5xx"].(float64) != 0 || e["top"].([]any)[0].(map[string]any)["code"] != "4290" {
		t.Errorf("errors = %v", e)
	}
	dc := ov["disconnects"].(map[string]any)
	if len(dc["handshake"].([]any)) != 2 || len(dc["sessionTop3"].([]any)) != 3 {
		t.Errorf("disconnects = %v", dc)
	}
	if a := ov["alerts"].(map[string]any)["list"].([]any); len(a) != 1 || a[0].(map[string]any)["name"] != "HighErrorRate" {
		t.Errorf("alerts = %v", a)
	}
	if b := ov["backup"].(map[string]any)["sources"].([]any)[0].(map[string]any); b["overdue"] != false {
		t.Errorf("backup = %v", b)
	}

	// Prometheus 挂了：对应卡片不可用，不是 0；节点相关正常。
	o.prom.down.Store(true)
	r := o.viewer.do("GET", opsAPI+"/overview", nil)
	ov = opsData(t, r)
	for _, card := range []string{"messages", "errors", "disconnects"} {
		c := ov[card].(map[string]any)
		if c["unavailable"] != true || c["reason"] == "" {
			t.Errorf("%s = %v", card, c)
		}
		if strings.Contains(fmt.Sprint(c), "today") || strings.Contains(fmt.Sprint(c), "share") {
			t.Errorf("%s has numbers: %v", card, c)
		}
	}
	if ov["connections"].(map[string]any)["total"].(float64) != 2 || ov["status"] != "ok" {
		t.Errorf("node cards = %v", ov)
	}
	o.prom.down.Store(false)

	// Alertmanager 挂了：不可用，而不是空列表。
	o.alerts.Store("")
	ov = opsData(t, o.viewer.do("GET", opsAPI+"/overview", nil))
	if a := ov["alerts"].(map[string]any); a["unavailable"] != true || a["list"] != nil {
		t.Errorf("alerts down = %v", a)
	}
	if a := opsData(t, o.viewer.do("GET", opsAPI+"/alerts", nil)); a["unavailable"] != true {
		t.Errorf("alerts api = %v", a)
	}
	o.alerts.Store("[]")

	// 版本不一致 31 分钟（AC-OPS-04-6）。
	v2.Store("0.3.1")
	o.probe()
	ver := opsData(t, o.viewer.do("GET", opsAPI+"/overview", nil))["versions"].(map[string]any)
	if ver["mismatch"] != true || ver["over30Min"] != false || len(ver["list"].([]any)) != 2 {
		t.Errorf("versions = %v", ver)
	}
	o.advance(31 * time.Minute)
	expect(t, "login", o.viewer.login(), 200, 0)
	o.probe()
	if ver := opsData(t, o.viewer.do("GET", opsAPI+"/overview", nil))["versions"].(map[string]any); ver["over30Min"] != true {
		t.Errorf("after 31 minutes = %v", ver)
	}
	v2.Store("0.3.0")
	o.probe()
	if ver := opsData(t, o.viewer.do("GET", opsAPI+"/overview", nil))["versions"].(map[string]any); ver["mismatch"] != false {
		t.Errorf("restored = %v", ver)
	}

	// 下线中（AC-OPS-04-4）：单节点全部不就绪就是"不可用"。
	d1.Store(true)
	d2.Store(true)
	o.probe()
	if ov := opsData(t, o.viewer.do("GET", opsAPI+"/overview", nil)); ov["status"] != "down" {
		t.Errorf("draining = %v", ov["status"])
	}
	if n := opsData(t, o.viewer.do("GET", opsAPI+"/nodes", nil))["nodes"].([]any)[0].(map[string]any); n["status"] != "draining" {
		t.Errorf("draining node = %v", n)
	}

	// 备份超过 2 小时标红（AC-OPS-12-3）。
	o.advance(2*time.Hour + time.Minute)
	expect(t, "login", o.viewer.login(), 200, 0)
	if b := opsData(t, o.viewer.do("GET", opsAPI+"/overview", nil))["backup"].(map[string]any)["sources"].([]any)[0].(map[string]any); b["overdue"] != true {
		t.Errorf("overdue = %v", b)
	}
}

// AC-OPS-16-5：证书服务名不对：只握手，没有 HTTP 请求（签名没发出去）。
func TestOpsNodeIdentity(t *testing.T) {
	o := newOpsWorld(t)
	var hits atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "k")
	if err := os.WriteFile(key, []byte(b64(testSeed)), 0o600); err != nil {
		t.Fatal(err)
	}
	table := filepath.Join(dir, "t.json")
	addr := strings.TrimPrefix(srv.URL, "https://")
	if err := os.WriteFile(table, []byte(fmt.Sprintf(`[{"nodeId":"n2","addr":%q,"tlsServerName":"n2.ops.internal","keyFile":%q}]`, addr, key)), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, problems := opsnode.LoadTable(table, true)
	if len(problems) > 0 {
		t.Fatal(problems)
	}
	f, err := opsnode.New(entries, ca, o.a.Clock)
	if err != nil {
		t.Fatal(err)
	}
	o.a.Nodes = f
	o.probe()
	row := opsData(t, o.viewer.do("GET", opsAPI+"/nodes", nil))["nodes"].([]any)[0].(map[string]any)
	if row["status"] != "identityFailed" {
		t.Errorf("status = %v", row)
	}
	r := o.engineer.do("POST", opsAPI+"/troubleshoot/query", map[string]any{"userId": "u1", "ticket": "CS-1024", "reason": goodReason})
	if d := opsData(t, r); d["verdict"] != "unknown" || r.body["partial"] != true {
		t.Errorf("troubleshoot = %s", r.raw)
	}
	if hits.Load() != 0 {
		t.Errorf("the fake node received %d HTTP requests", hits.Load())
	}
	// 服务名对、CA 对：通过（说明上面确实是服务名的问题）。
	hostOK := fmt.Sprintf(`[{"nodeId":"n2","addr":%q,"tlsServerName":"example.com","keyFile":%q}]`, addr, key)
	if err := os.WriteFile(table, []byte(hostOK), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, _ = opsnode.LoadTable(table, true)
	f, err = opsnode.New(entries, ca, o.a.Clock)
	if err != nil {
		t.Fatal(err)
	}
	o.a.Nodes = f
	o.probe()
	if hits.Load() == 0 {
		t.Error("a correct server name still did not connect")
	}
}

func tsBody(user string) map[string]any {
	return map[string]any{"userId": user, "ticket": "CS-1024", "reason": "用户反馈掉线"}
}

// AC-OPS-08-1～08-11、09-1、09-3、09-7、09-11、14-4、15-1。
func TestOpsTroubleshoot(t *testing.T) {
	n1 := startNode(t, "n1")
	n2 := startNode(t, "n2")
	o := newOpsWorld(t, n1, n2)
	const path = opsAPI + "/troubleshoot/query"
	u := "u" + uid()
	n1.import_(t, u)
	n2.import_(t, u)
	n1.dial(t, o.world, u, "web")
	n2.dial(t, o.world, u, "pc")
	time.Sleep(100 * time.Millisecond)

	// 校验失败不调用节点（AC-OPS-08-3、08-5）。
	before := strings.Count(n1.logs.String(), "ops request")
	for _, bad := range []map[string]any{
		{"userId": u, "reason": goodReason}, {"userId": u, "ticket": "CS 1024", "reason": goodReason}, {"userId": u, "ticket": strings.Repeat("a", 33), "reason": goodReason},
		{"userId": u, "ticket": "AB", "reason": goodReason}, {"userId": u, "ticket": "CS-1024", "reason": "  abc "}, {"userId": u, "ticket": "CS-1024", "reason": "aaaa"},
	} {
		expect(t, fmt.Sprint(bad), o.engineer.do("POST", path, bad), 400, 4000)
	}
	expect(t, "traversal", o.engineer.do("POST", path, tsBody("u1/../x")), 400, 4004)
	if n := strings.Count(n1.logs.String(), "ops request"); n != before {
		t.Errorf("validation reached the node: %d", n-before)
	}

	// 两个节点各一个连接（AC-OPS-08-1、08-10）。
	r := o.engineer.do("POST", path, tsBody(u))
	d := opsData(t, r)
	conns := d["connections"].([]any)
	if len(conns) != 2 || d["verdict"] != "online" || r.body["partial"] != false {
		t.Fatalf("query = %s", r.raw)
	}
	nodes := map[string]string{}
	for _, c := range conns {
		m := c.(map[string]any)
		nodes[m["node"].(string)] = m["platform"].(string)
		if ip := m["ip"].(string); !regexp.MustCompile(`^\d+\.\d+\.\*\.\*$`).MatchString(ip) {
			t.Errorf("ip = %s", ip)
		}
	}
	if nodes["n1"] != "web" || nodes["n2"] != "pc" {
		t.Errorf("nodes = %v", nodes)
	}
	for _, bad := range []string{"token", "body", "convs"} {
		if strings.Contains(strings.ToLower(r.raw), `"`+bad) {
			t.Errorf("response has %s: %s", bad, r.raw)
		}
	}

	// 审计（AC-OPS-08-7）：工单、理由、条数、partial、节点；节点日志有同一请求 ID，没有 userId。
	rows := o.auditRows(`action = 'ops.troubleshoot.query' AND phase = 'result' AND target LIKE '%' || $1 || '%'`, u)
	if len(rows) != 1 {
		t.Fatalf("audit = %v", rows)
	}
	row := rows[0]
	p := row["params"].(string)
	if row["reason"] != "用户反馈掉线" || !strings.Contains(p, `"partial":false`) || !strings.Contains(p, `"count":2`) || !strings.Contains(p, `"nodes":["n1","n2"]`) || row["result"] != "success" {
		t.Errorf("row = %v", row)
	}
	reqID := row["request_id"].(string)
	var ticket string
	if err := o.db.QueryRow(context.Background(), `SELECT ticket FROM audit.records WHERE seq = $1`, row["seq"]).Scan(&ticket); err != nil || ticket != "CS-1024" {
		t.Errorf("ticket = %q %v", ticket, err)
	}
	for _, n := range []*imNode{n1, n2} {
		logs := n.logs.String()
		if !strings.Contains(logs, reqID) {
			t.Errorf("%s log has no request id", n.id)
		}
		for _, line := range strings.Split(logs, "\n") {
			if strings.Contains(line, "ops request") && strings.Contains(line, u) {
				t.Errorf("%s log has the userId: %s", n.id, line)
			}
		}
	}
	for _, canary := range []string{u, "CS-1024", "用户反馈掉线"} {
		if strings.Contains(o.logs.String(), canary) {
			t.Errorf("console log has %q", canary)
		}
	}

	// 不在线和不存在响应一样（AC-OPS-08-2）。
	offline := "u" + uid()
	n1.import_(t, offline)
	a := o.engineer.do("POST", path, tsBody(offline))
	b := o.engineer.do("POST", path, tsBody("never-existed"))
	strip := func(s string) string { return regexp.MustCompile(`"dataTime":\d+`).ReplaceAllString(s, "") }
	if a.status != b.status || strip(a.raw) != strip(b.raw) || opsData(t, a)["verdict"] != "offline" {
		t.Errorf("responses differ:\n%s\n%s", a.raw, b.raw)
	}

	// 断开记录：强制下线后（AC-OPS-09-1、09-11 的合并）。
	if err := n1.sys.Do(context.Background(), callOf("kick"), "POST", "/admin/users/"+u+"/force-logout", nil, struct{}{}, nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	o.tick()
	d = opsData(t, o.engineer.do("POST", path, tsBody(u)))
	recs := d["disconnects"].([]any)
	if len(recs) == 0 {
		t.Fatalf("no disconnects: %v", d)
	}
	rec := recs[0].(map[string]any)
	if rec["phase"] != "session" || rec["code"].(float64) != 4012 || rec["reason"] != "banned" || rec["by"] != "server" || rec["node"] != "n1" {
		t.Errorf("record = %v", rec)
	}
	if d["bufferFrom"].(map[string]any)["n1"].(float64) <= 0 {
		t.Errorf("bufferFrom = %v", d["bufferFrom"])
	}
	if d["verdict"] != "online" {
		t.Errorf("n2 still has a connection: %v", d["verdict"])
	}

	// 暂停 n2：2.5 秒内返回，不说"不在线"（AC-OPS-08-11）。
	only := "u" + uid()
	n2.import_(t, only)
	n2.dial(t, o.world, only, "web")
	if err := n2.cmd.Process.Signal(sigStop); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	r = o.engineer.do("POST", path, tsBody(only))
	took := time.Since(start)
	_ = n2.cmd.Process.Signal(sigCont)
	d = opsData(t, r)
	if took > 2500*time.Millisecond {
		t.Errorf("took %v", took)
	}
	if r.body["partial"] != true || fmt.Sprint(r.body["missingNodes"]) != "[n2]" || d["verdict"] != "unknown" || d["respondedNodes"].(float64) != 1 {
		t.Errorf("partial = %s", r.raw)
	}
	rows = o.auditRows(`action = 'ops.troubleshoot.query' AND phase = 'result' AND target LIKE '%' || $1 || '%'`, only)
	if len(rows) != 1 || !strings.Contains(rows[0]["params"].(string), `"partial":true`) {
		t.Errorf("partial audit = %v", rows)
	}

	// 审计写失败不调用节点（AC-OPS-14-4）；配置检查不返回数据；总览正常。
	o.a.SetAuditFault("fail")
	before = strings.Count(n1.logs.String(), "ops request")
	expect(t, "audit down", o.engineer.do("POST", path, tsBody(offline)), 503, 5031)
	if n := strings.Count(n1.logs.String(), "ops request"); n != before {
		t.Error("query reached the node with audit down")
	}
	cfg := o.engineer.do("GET", opsAPI+"/config", nil)
	expect(t, "config audit down", cfg, 503, 5031)
	if strings.Contains(cfg.raw, "productionChecks") {
		t.Error("config returned")
	}
	expect(t, "overview", o.engineer.do("GET", opsAPI+"/overview", nil), 200, 0)
	o.a.SetAuditFault("ok")

	// 审计员看得到（AC-OPS-15-1）；管理空间审计员看不到。
	now := o.now.UnixMilli()
	q := fmt.Sprintf("/console/api/audit?from=%d&to=%d&target=user:%s&action=ops.troubleshoot.query&result=success", now-86400000, now+1000, u)
	r = o.auditor.do("GET", q, nil)
	expect(t, "auditor", r, 200, 0)
	if list := r.body["records"].([]any); len(list) != 2 || list[0].(map[string]any)["ticket"] != "CS-1024" {
		t.Errorf("auditor sees = %s", r.raw)
	}
}

// AC-OPS-08-8、08-9：频率和配额。
func TestOpsTroubleshootLimits(t *testing.T) {
	n1 := startNode(t, "n1")
	o := newOpsWorld(t, n1)
	const path = opsAPI + "/troubleshoot/query"
	for i := range 30 {
		if r := o.engineer.do("POST", path, tsBody("same")); r.status != 200 {
			t.Fatalf("query %d: %s", i, r.raw)
		}
	}
	expect(t, "31st", o.engineer.do("POST", path, tsBody("same")), 429, 4290)
	o.advance(time.Minute)
	for i := range 49 {
		if i%25 == 0 {
			o.advance(time.Minute)
		}
		if r := o.engineer.do("POST", path, tsBody(fmt.Sprintf("q%d", i))); r.status != 200 {
			t.Fatalf("user %d: %s", i, r.raw)
		}
	}
	o.advance(time.Minute)
	expect(t, "51st", o.engineer.do("POST", path, tsBody("q50")), 429, 4292)
	expect(t, "seen", o.engineer.do("POST", path, tsBody("q0")), 200, 0)
	// 第二天（Asia/Shanghai）。
	local := o.now.In(time.FixedZone("Asia/Shanghai", 8*3600))
	next := time.Date(local.Year(), local.Month(), local.Day()+1, 0, 0, 1, 0, local.Location())
	o.advance(next.Sub(o.now))
	expect(t, "login", o.engineer.login(), 200, 0)
	expect(t, "next day", o.engineer.do("POST", path, tsBody("q50")), 200, 0)
}

func callOf(prefix string) imclient.Call {
	return imclient.Call{Operator: "test", RequestID: prefix + uid()}
}

// AC-OPS-10-1、10-2、10-4、10-5；AC-OPS-11-1：配置和数据库。
func TestOpsConfigAndDB(t *testing.T) {
	marker := "SECRET-MARKER-7f3a-" + strings.Repeat("x", 32)
	n1 := startNode(t, "n1", "IM_JWT_KEYS=k1:"+marker+",k2:"+strings.Repeat("y", 48), "IM_JWT_ACTIVE_KID=k2", "IM_ALLOWED_ORIGINS=*")
	n2 := startNode(t, "n2", "IM_MAX_CONNS_PER_USER=20")
	o := newOpsWorld(t, n1, n2)
	r := o.viewer.do("GET", opsAPI+"/config", nil)
	d := opsData(t, r)
	if strings.Contains(r.raw, marker) || strings.Contains(o.logs.String(), marker) {
		t.Error("secret leaked")
	}
	nodes := d["nodes"].([]any)
	if len(nodes) != 2 {
		t.Fatalf("nodes = %v", nodes)
	}
	n := nodes[0].(map[string]any)
	cfg := n["config"].(map[string]any)
	keys := cfg["keys"].(map[string]any)
	if fmt.Sprint(keys["jwtKids"]) != "[k1 k2]" || keys["jwtActiveKid"] != "k2" {
		t.Errorf("keys = %v", keys)
	}
	found := false
	for _, x := range n["risks"].([]any) {
		m := x.(map[string]any)
		if m["item"] == "allowedOrigins" && m["level"] == "high" {
			found = true
		}
	}
	if !found {
		t.Errorf("risks = %v", n["risks"])
	}
	if checks := cfg["productionChecks"].([]any); len(checks) == 0 {
		t.Errorf("checks = %v", cfg)
	}
	diff := fmt.Sprint(d["diff"])
	if !strings.Contains(diff, "limits.maxConnsPerUser") || strings.Contains(diff, "env.nodeId") || strings.Contains(diff, "env.version") {
		t.Errorf("diff = %v", diff)
	}
	if rows := o.auditRows(`action = 'ops.config.view' AND username = 'oview1'`); len(rows) != 1 || rows[0]["space"] == "admin" {
		t.Errorf("audit = %v", rows)
	}
	// 数据库。
	db := opsData(t, o.viewer.do("GET", opsAPI+"/db", nil))
	list := db["nodes"].([]any)
	if len(list) != 2 {
		t.Fatalf("db = %v", db)
	}
	first := list[0].(map[string]any)["db"].(map[string]any)
	if first["connected"] != true || first["type"] == "" || len(first["migrations"].([]any)) == 0 {
		t.Errorf("db = %v", first)
	}
	if rows := o.auditRows(`action LIKE 'ops.db%'`); len(rows) != 0 {
		t.Errorf("db page audited: %v", rows)
	}
}

// AC-OPS-12-3、12-4、12-5、12-6、12-8：备份记录。
func TestOpsBackups(t *testing.T) {
	o := newOpsWorld(t)
	now := o.now.UnixMilli()
	o.putManifest("im", now-3*3600000, map[string]any{"source": "im", "trigger": "schedule", "result": "success", "finishedAt": now - 3*3600000, "file": "old.db.age", "verified": true, "encrypted": true, "uploaded": true})
	o.putManifest("im", now-3600000, map[string]any{"source": "im", "trigger": "pre-migrate", "release": "v1.2.3", "result": "success", "finishedAt": now - 3600000, "file": "/srv/backup/secret/new.db.age", "sha256": "abc", "size": 123, "verified": true, "encrypted": true, "uploaded": true})
	o.putManifest("im", now-60000, map[string]any{"source": "im", "trigger": "schedule", "result": "failed", "finishedAt": now - 60000, "error": "加密失败", "file": "failed.db"})
	o.putManifest("console", now-60000, map[string]any{"source": "console", "trigger": "schedule", "result": "success", "finishedAt": now - 60000, "file": "console.dump.age"})
	r := o.viewer.do("GET", opsAPI+"/backups", nil)
	d := opsData(t, r)
	groups := d["groups"].([]any)
	if len(groups) != 2 || groups[0].(map[string]any)["source"] != "console" {
		t.Fatalf("groups = %s", r.raw)
	}
	im := groups[1].(map[string]any)
	recs := im["records"].([]any)
	if len(recs) != 3 || recs[0].(map[string]any)["result"] != "failed" || recs[0].(map[string]any)["error"] != "加密失败" {
		t.Errorf("records = %v", recs)
	}
	// 健康只看最近一次成功：最新一条失败不影响。
	if im["lastSuccessAt"].(float64) != float64(now-3600000) || im["overdue"] != false {
		t.Errorf("im = %v", im)
	}
	if recs[1].(map[string]any)["file"] != "new.db.age" || strings.Contains(r.raw, "/srv/backup") || strings.Contains(r.raw, o.backups.Reader.SecretKey) || strings.Contains(r.raw, o.backups.URL()) {
		t.Errorf("path leaked: %s", r.raw)
	}
	if recs[1].(map[string]any)["release"] != "v1.2.3" {
		t.Errorf("release = %v", recs[1])
	}
	// 2 小时 1 分钟后标红。
	o.advance(time.Hour + time.Minute)
	expect(t, "login", o.viewer.login(), 200, 0)
	d = opsData(t, o.viewer.do("GET", opsAPI+"/backups", nil))
	if d["groups"].([]any)[1].(map[string]any)["overdue"] != true {
		t.Errorf("overdue = %v", d)
	}
	// 读取凭证：能列能读，不能写不能删（AC-OPS-12-5 在假桶上；真实策略在 BE-313）。
	if _, err := o.a.Backups.List(context.Background(), "manifests/"); err != nil {
		t.Error(err)
	}
	if err := o.a.Backups.Put(context.Background(), "manifests/x", strings.NewReader("x"), time.Now().Add(time.Hour)); err == nil {
		t.Error("read credential could write")
	}
	// 存储不可用。
	o.backups.SetDown(true)
	o.advance(time.Minute)
	if d := opsData(t, o.viewer.do("GET", opsAPI+"/backups", nil)); d["unavailable"] != true {
		t.Errorf("down = %v", d)
	}
}

// grafanaDo 向 Grafana 主机发请求，不跟随跳转。
func (o *opsWorld) grafanaDo(method, path, cookie string, h map[string]string) *http.Response {
	o.t.Helper()
	req, _ := http.NewRequest(method, o.ops.URL+path, nil)
	req.Host = grafanaHost
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	if cookie != "" {
		req.Header.Set("Cookie", "__Host-grafana_sid="+cookie)
	}
	for k, v := range h {
		req.Header.Set(k, v)
	}
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Do(req)
	if err != nil {
		o.t.Fatal(err)
	}
	return resp
}

func (o *opsWorld) grafanaEnter(u *user) string {
	o.t.Helper()
	r := u.do("POST", opsAPI+"/grafana/ticket", map[string]any{})
	d := opsData(o.t, r)
	link := d["url"].(string)
	if !strings.Contains(link, grafanaHost) {
		o.t.Fatalf("url = %s", link)
	}
	ticket := link[strings.Index(link, "/__tianting"):]
	resp := o.grafanaDo("GET", ticket, "", map[string]string{"Sec-Fetch-Mode": "navigate"})
	defer resp.Body.Close()
	if resp.StatusCode != 302 {
		o.t.Fatalf("enter = %d", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-grafana_sid" {
			if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
				o.t.Errorf("cookie flags: %+v", c)
			}
			return c.Value
		}
	}
	o.t.Fatal("no cookie")
	return ""
}

// AC-OPS-17-1、17-2、17-3、17-4、17-8；14-1。
func TestOpsGrafana(t *testing.T) {
	o := newOpsWorld(t)
	// 审计员和超管拿不到（AC-OPS-17-4）。
	expect(t, "auditor", o.auditor.do("POST", opsAPI+"/grafana/ticket", map[string]any{}), 403, 4030)
	expect(t, "super", o.super.do("POST", opsAPI+"/grafana/ticket", map[string]any{}), 403, 4030)

	// 没有 Cookie：导航跳回登录页，数据请求 401。
	resp := o.grafanaDo("GET", "/", "", map[string]string{"Sec-Fetch-Mode": "navigate"})
	if resp.StatusCode != 302 || !strings.HasSuffix(resp.Header.Get("Location"), "/login") {
		t.Errorf("no cookie navigate = %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp.Body.Close()
	resp = o.grafanaDo("GET", "/api/search", "", nil)
	if resp.StatusCode != 401 {
		t.Errorf("no cookie data = %d", resp.StatusCode)
	}
	resp.Body.Close()

	cookie := o.grafanaEnter(o.viewer)
	if rows := o.auditRows(`action = 'ops.grafana.enter' AND username = 'oview1'`); len(rows) != 1 {
		t.Errorf("audit = %v", rows)
	}
	drain := func() {
		for len(o.grafReqs) > 0 {
			<-o.grafReqs
		}
	}
	drain()
	// 客户端自带的身份头被换掉；我们的 Cookie 不给 Grafana；Grafana 的 CSP 和 Set-Cookie 处理。
	resp = o.grafanaDo("GET", "/d/x", cookie, map[string]string{"X-WEBAUTH-USER": "admin", "X-Tianting-Internal-User": "admin"})
	if resp.StatusCode != 200 {
		t.Fatalf("proxy = %d", resp.StatusCode)
	}
	if resp.Header.Get("Set-Cookie") != "" {
		t.Errorf("grafana cookie passed through: %v", resp.Header)
	}
	resp.Body.Close()
	up := <-o.grafReqs
	if up.Header.Get("X-WEBAUTH-USER") != "ops-oview1" || up.Header.Get("X-Tianting-Internal-User") != "" || strings.Contains(up.Header.Get("Cookie"), "grafana_sid") {
		t.Errorf("upstream headers = %v", up.Header)
	}

	// 写接口在代理层就拦下（AC-OPS-17-1）。
	for _, c := range [][2]string{{"POST", "/api/dashboards/db"}, {"DELETE", "/api/dashboards/uid/x"}, {"GET", "/api/datasources"}, {"POST", "/api/datasources"}, {"PUT", "/api/org"}, {"POST", "/api/user/password"}} {
		resp := o.grafanaDo(c[0], c[1], cookie, nil)
		if resp.StatusCode != 403 {
			t.Errorf("%s %s = %d", c[0], c[1], resp.StatusCode)
		}
		resp.Body.Close()
	}
	resp = o.grafanaDo("POST", "/api/ds/query", cookie, nil)
	if resp.StatusCode != 200 {
		t.Errorf("query = %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 票据只能用一次，30 秒过期（AC-OPS-17-2）。
	link := opsData(t, o.viewer.do("POST", opsAPI+"/grafana/ticket", map[string]any{}))["url"].(string)
	ticket := link[strings.Index(link, "/__tianting"):]
	r1 := o.grafanaDo("GET", ticket, "", nil)
	r1.Body.Close()
	if !hasGrafanaCookie(r1) {
		t.Error("first use failed")
	}
	r2 := o.grafanaDo("GET", ticket, "", nil)
	r2.Body.Close()
	if r2.StatusCode != 302 || hasGrafanaCookie(r2) || !strings.HasSuffix(r2.Header.Get("Location"), "/login") {
		t.Errorf("reuse = %d %v", r2.StatusCode, r2.Header)
	}
	link = opsData(t, o.viewer.do("POST", opsAPI+"/grafana/ticket", map[string]any{}))["url"].(string)
	o.advance(31 * time.Second)
	r3 := o.grafanaDo("GET", link[strings.Index(link, "/__tianting"):], "", nil)
	r3.Body.Close()
	if hasGrafanaCookie(r3) {
		t.Error("expired ticket worked")
	}

	// 数据查询不续期；导航续期（AC-OPS-17-8）。
	a := o.grafanaEnter(o.viewer)
	eng := o.engineer
	b := o.grafanaEnter(eng)
	o.advance(20 * time.Minute)
	resp = o.grafanaDo("GET", "/d/other", b, map[string]string{"Sec-Fetch-Mode": "navigate"})
	resp.Body.Close()
	o.advance(5 * time.Minute)
	resp = o.grafanaDo("POST", "/api/ds/query", a, nil) // 只有数据请求
	if resp.StatusCode != 200 {
		t.Errorf("data within window = %d", resp.StatusCode)
	}
	resp.Body.Close()
	o.advance(6 * time.Minute) // 31 分钟
	resp = o.grafanaDo("POST", "/api/ds/query", a, nil)
	if resp.StatusCode != 401 {
		t.Errorf("data request kept the session alive: %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = o.grafanaDo("POST", "/api/ds/query", b, nil)
	if resp.StatusCode != 200 {
		t.Errorf("navigation did not renew: %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 退出后立刻失效（AC-OPS-17-3）。
	expect(t, "logout", eng.do("POST", "/console/api/auth/logout", map[string]any{}), 200, 0)
	resp = o.grafanaDo("GET", "/d/x", b, map[string]string{"Sec-Fetch-Mode": "navigate"})
	if resp.StatusCode != 302 {
		t.Errorf("after logout = %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = o.grafanaDo("GET", "/api/search", b, nil)
	if resp.StatusCode != 401 {
		t.Errorf("after logout data = %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 运维主机上不受影响，Grafana 路径不通。
	if r := o.viewer.do("GET", "/__tianting/enter?ticket=x", nil); strings.Contains(r.raw, "grafana:") {
		t.Errorf("grafana reachable on ops host: %s", r.raw)
	}
}

func hasGrafanaCookie(r *http.Response) bool {
	for _, c := range r.Cookies() {
		if c.Name == "__Host-grafana_sid" {
			return true
		}
	}
	return false
}

// AC-OPS-03-3：一次列全。
func TestOpsStartupGuards(t *testing.T) {
	_, appURL := newDB(t)
	env := append(prodEnv(appURL), "CON_SPACES=admin,ops", "CON_OPS_ALLOWED_CIDRS=0.0.0.0/0", "CON_OPS_ORIGIN=https://ops.example.internal", "CON_TEST_MODE=1")
	dir := t.TempDir()
	key := filepath.Join(dir, "k")
	if err := os.WriteFile(key, []byte(b64(testSeed)), 0o600); err != nil {
		t.Fatal(err)
	}
	table := filepath.Join(dir, "t.json")
	if err := os.WriteFile(table, []byte(fmt.Sprintf(`[{"nodeId":"n1","addr":"10.0.0.1:9091","keyFile":%q}]`, key)), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, append(env, "CON_OPS_NODES="+table))
	if err == nil {
		t.Fatal("started")
	}
	for _, want := range []string{"0.0.0.0/0", "n1 has no tlsServerName", "CON_TEST_MODE", "CON_OPS_GRAFANA_URL", "CON_OPS_CA_FILE"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, testSeed) {
		t.Error("key in output")
	}
}

// 登录页：运维空间还没有账号。
func TestOpsBootstrapStatus(t *testing.T) {
	w := newWorld(t, nil)
	c := w.opsClient("x")
	r := c.do("GET", "/console/api/auth/bootstrap-status", nil)
	if r.body["hasAccounts"] != false {
		t.Errorf("%s", r.raw)
	}
	w.opsSuper("osuper")
	r = c.do("GET", "/console/api/auth/bootstrap-status", nil)
	if r.body["hasAccounts"] != true {
		t.Errorf("%s", r.raw)
	}
	// 管理空间没有这个接口（未登录 401，不暴露）。
	a := w.client("y")
	expect(t, "admin", a.do("GET", "/console/api/auth/bootstrap-status", nil), 401, 4014)
}
