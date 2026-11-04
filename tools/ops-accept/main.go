// ops-accept 对运行中的测试环境（tianting-server 的 deploy/testenv，E2a + console-server）做联调验收：
// 用真实账号登录运维空间，读真实的节点、Prometheus、Alertmanager、Grafana、MinIO。
// 失败不中断，全部跑完一次列全，有失败时退出码 1。需要 tt（环境控制）和节点的管理密钥文件。
//
// 覆盖 AC-OPS-90-3、14-6、08-11、04-2、04-5、04-6、05-1、07-5、12-3（读真实清单），以及 Grafana 代理到真实 Grafana。
// 不覆盖 AC-OPS-90-2：它要在 1 万连接的 EP 环境里和 BE-321 同轮测。
package main

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"tianting/console/internal/totp"
)

const (
	base     = "http://127.0.0.1:18290"
	opsHost  = "ops.localhost:18290"
	origin   = "http://ops.localhost:18290"
	grafHost = "grafana.ops.localhost:18290"
	opsAPI   = "/console/api/ops/v1"
	password = "Correct-Horse-9-Battery"
)

var (
	httpc = &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	tt       string
	adminKey string
	failed   []string
	offset   time.Duration // [C 钟] 被推进后，动态码要按它算
)

func ok(format string, a ...any) { fmt.Printf("ok: "+format+"\n", a...) }

func fail(format string, a ...any) {
	s := fmt.Sprintf(format, a...)
	failed = append(failed, s)
	fmt.Println("FAIL: " + s)
}

func check(cond bool, label string, a ...any) bool {
	if cond {
		ok("%s", label)
	} else {
		fail("%s: %v", label, a)
	}
	return cond
}

func section(s string) { fmt.Printf("== %s\n", s) }

func run(args ...string) (string, error) {
	out, err := exec.Command(tt, args...).CombinedOutput() // #nosec G204 -- tt 的路径来自命令行参数，只在测试环境运行
	return string(out), err
}

func mustRun(args ...string) {
	if out, err := run(args...); err != nil {
		fail("tt %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// ---------------------------------------------------------------------------
// 运维空间的客户端

type reply struct {
	status int
	raw    string
	body   map[string]any
	header http.Header
}

func (r reply) data() map[string]any {
	d, _ := r.body["data"].(map[string]any)
	return d
}

type user struct {
	name, cookie, csrf string
	seed               []byte
	lastStep           int64
}

func (u *user) do(method, path string, body any) reply {
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, base+path, rd)
	if err != nil {
		return reply{raw: err.Error()}
	}
	req.Host = opsHost
	if method != http.MethodGet {
		req.Header.Set("Origin", origin)
		if u.csrf != "" {
			req.Header.Set("X-CSRF-Token", u.csrf)
		}
	}
	if u.cookie != "" {
		req.Header.Set("Cookie", "__Host-ops_sid="+u.cookie)
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return reply{raw: err.Error()}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	r := reply{status: resp.StatusCode, raw: string(raw), header: resp.Header}
	_ = json.Unmarshal(raw, &r.body)
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-ops_sid" && c.Value != "" {
			u.cookie = c.Value
		}
	}
	if v, ok := r.body["csrfToken"].(string); ok {
		u.csrf = v
	}
	return r
}

// otp 等到一个没用过的时间步：同一个动态码不能用两次。
func (u *user) otp() string {
	for {
		step := totp.Step(time.Now().Add(offset))
		if step > u.lastStep {
			u.lastStep = step
			return totp.Code(u.seed, step)
		}
		if offset != 0 { // 冻结的时钟等不到下一步
			return totp.Code(u.seed, step)
		}
		time.Sleep(time.Second)
	}
}

func (u *user) activate(code string) error {
	r := u.do("POST", "/console/api/auth/activate", map[string]any{"username": u.name, "code": code, "newPassword": password})
	if r.status != 200 {
		return fmt.Errorf("activate %s: %d %s", u.name, r.status, r.raw)
	}
	r = u.do("POST", "/console/api/auth/totp/setup", map[string]any{})
	if r.status != 200 {
		return fmt.Errorf("totp setup: %d %s", r.status, r.raw)
	}
	uri, _ := r.body["otpauthUri"].(string)
	parsed, err := url.Parse(uri)
	if err != nil {
		return err
	}
	u.seed, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(parsed.Query().Get("secret"))
	if err != nil {
		return err
	}
	r = u.do("POST", "/console/api/auth/totp/confirm", map[string]any{"otp": u.otp()})
	if r.status != 200 {
		return fmt.Errorf("totp confirm: %d %s", r.status, r.raw)
	}
	return nil
}

func (u *user) create(name string, roles ...string) (*user, error) {
	r := u.do("POST", "/console/api/accounts", map[string]any{"username": name, "displayName": name, "roles": roles})
	if r.status != 200 {
		return nil, fmt.Errorf("create %s: %d %s", name, r.status, r.raw)
	}
	code, _ := r.body["activationCode"].(string)
	c := &user{name: name}
	return c, c.activate(code)
}

// ---------------------------------------------------------------------------
// im-server 一侧：真实的用户和连接

type node struct{ ws, admin string }

var (
	n1 = node{"127.0.0.1:18080", "127.0.0.1:18081"}
	n2 = node{"127.0.0.1:18180", "127.0.0.1:18181"}
)

func (n node) call(path string, body any) (map[string]any, error) {
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, "http://"+n.admin+path, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Admin-Key", adminKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("%s: %d %s", path, resp.StatusCode, out)
	}
	var m map[string]any
	_ = json.Unmarshal(out, &m)
	return m, nil
}

// conn 是一条已鉴权的长连接：一直读、定时 ping，不然服务端 90 秒后断开。
type conn struct {
	ws   *websocket.Conn
	mu   sync.Mutex
	acks int
}

func (n node) connect(ctx context.Context, uid, platform string) (*conn, error) {
	if _, err := n.call("/admin/users/import", map[string]any{"users": []map[string]string{{"userId": uid}}}); err != nil {
		return nil, err
	}
	tok, err := n.call("/admin/users/token", map[string]any{"userId": uid, "ttlSeconds": 86400})
	if err != nil {
		return nil, err
	}
	dial, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(dial, "ws://"+n.ws+"/ws?platform="+platform, nil)
	if err != nil {
		return nil, err
	}
	ws.SetReadLimit(16 << 20)
	c := &conn{ws: ws}
	if err := c.write(ctx, map[string]any{"id": "auth", "cmd": "auth", "data": map[string]any{"token": tok["token"]}}); err != nil {
		return nil, err
	}
	if _, data, err := ws.Read(dial); err != nil || bytes.Contains(data, []byte(`"error"`)) {
		return nil, fmt.Errorf("auth %s: %s %v", uid, data, err)
	}
	go func() {
		for {
			_, data, err := ws.Read(ctx)
			if err != nil {
				return
			}
			if bytes.Contains(data, []byte(`"ack-`)) {
				c.mu.Lock()
				c.acks++
				c.mu.Unlock()
			}
		}
	}()
	go func() {
		t := time.NewTicker(20 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = c.write(ctx, map[string]any{"id": "ping", "cmd": "ping"})
			}
		}
	}()
	return c, nil
}

func (c *conn) write(ctx context.Context, v any) error {
	raw, _ := json.Marshal(v)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ws.Write(ctx, websocket.MessageText, raw)
}

func (c *conn) send(ctx context.Context, to string, i int) error {
	return c.write(ctx, map[string]any{"id": fmt.Sprintf("ack-%d", i), "cmd": "send", "data": map[string]any{
		"convType": "c2c", "to": to, "clientMsgId": fmt.Sprintf("accept-%d-%d", time.Now().UnixNano(), i), "type": "text", "body": map[string]any{"text": "accept"},
	}})
}

// ---------------------------------------------------------------------------

func num(m map[string]any, k string) float64 {
	v, _ := m[k].(float64)
	return v
}

func sub(m map[string]any, k string) map[string]any {
	v, _ := m[k].(map[string]any)
	return v
}

func list(m map[string]any, k string) []any {
	v, _ := m[k].([]any)
	return v
}

func waitFor(d time.Duration, f func() bool) bool {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if f() {
			return true
		}
		time.Sleep(3 * time.Second)
	}
	return f()
}

func probe() {
	u := &user{}
	if r := u.do("POST", "/console/test/probe", nil); r.status != 200 {
		fail("probe: %d %s", r.status, r.raw)
	}
}

func stepNodes(u *user) {
	section("AC-OPS-05-1、04-6：节点和版本来自真实探活")
	probe()
	d := u.do("GET", opsAPI+"/nodes", nil).data()
	var ids, vers []string
	for _, x := range list(d, "nodes") {
		m, _ := x.(map[string]any)
		id, _ := m["nodeId"].(string)
		v, _ := m["version"].(string)
		st, _ := m["status"].(string)
		ids, vers = append(ids, id), append(vers, v)
		check(st == "ready", "节点 "+id+" 状态 ready", st)
	}
	check(slices.Equal(ids, []string{"n1", "n2"}) && slices.Equal(vers, []string{"0.3.0", "0.3.1"}), "节点列表 n1=0.3.0、n2=0.3.1", ids, vers)
	v := sub(d, "versions")
	check(v["mismatch"] == true && len(list(v, "list")) == 2, "版本卡片标记不一致并列出两个版本", v)
}

func stepOverview(ctx context.Context, u *user) {
	section("AC-OPS-04-2：真实 Prometheus 上的消息量（10 条/秒，120 秒）")
	a, err := n1.connect(ctx, "acc-sender", "web")
	if err != nil {
		fail("connect sender: %v", err)
		return
	}
	if _, err := n1.connect(ctx, "acc-receiver", "web"); err != nil {
		fail("connect receiver: %v", err)
		return
	}
	ov := u.do("GET", opsAPI+"/overview", nil).data()
	msgs := sub(ov, "messages")
	if !check(msgs["unavailable"] != true, "消息量卡片能读真实 Prometheus", msgs) {
		return
	}
	for _, card := range []string{"errors", "disconnects"} {
		check(sub(ov, card)["unavailable"] != true, card+" 卡片能读真实 Prometheus", sub(ov, card))
	}
	before := num(msgs, "today")
	start := time.Now()
	var rate float64
	for i := range 1200 {
		if err := a.send(ctx, "acc-receiver", i); err != nil {
			fail("send: %v", err)
			return
		}
		time.Sleep(time.Until(start.Add(time.Duration(i+1) * 100 * time.Millisecond)))
		if i == 900 { // 第 90 秒：rate[1m] 的窗口已经全在发送期内
			rate = num(sub(u.do("GET", opsAPI+"/overview", nil).data(), "messages"), "perSecond")
		}
	}
	check(rate >= 9 && rate <= 11, fmt.Sprintf("每秒新消息数 %.1f（要求 9～11）", rate), rate)
	var today float64
	got := waitFor(60*time.Second, func() bool {
		today = num(sub(u.do("GET", opsAPI+"/overview", nil).data(), "messages"), "today")
		return today-before >= 1188
	})
	check(got && today-before <= 1212, fmt.Sprintf("今日累计增加 %.0f（要求 1200，误差 ≤ 1%%）", today-before), today, before)
	conns := sub(u.do("GET", opsAPI+"/overview", nil).data(), "connections")
	check(num(conns, "total") >= 2, "在线连接数来自节点探活", conns)

	section("AC-OPS-04-5：停止 Prometheus，卡片显示数据不可用，节点卡片正常")
	mustRun("compose", "stop", "prometheus")
	ov = u.do("GET", opsAPI+"/overview", nil).data()
	for _, card := range []string{"messages", "errors", "disconnects"} {
		c := sub(ov, card)
		_, hasToday := c["today"]
		check(c["unavailable"] == true && !hasToday, card+" 不可用且没有数字", c)
	}
	check(sub(ov, "nodes")["total"] != nil && num(sub(ov, "nodes"), "total") == 2, "节点卡片正常", sub(ov, "nodes"))
	mustRun("compose", "start", "prometheus")
}

func stepAlerts(u *user) {
	section("AC-OPS-07-5：备份过期经真实 Alertmanager 出现在告警卡片，恢复后消失")
	has := func() (bool, string) {
		r := u.do("GET", opsAPI+"/alerts", nil)
		for _, x := range list(r.data(), "list") {
			m, _ := x.(map[string]any)
			if m["name"] == "备份过期" {
				node, _ := m["node"].(string)
				return true, node
			}
		}
		return false, r.raw
	}
	mustRun("backup-age", "im", "7260")
	var node string
	got := waitFor(4*time.Minute, func() bool {
		var ok bool
		ok, node = has()
		return ok
	})
	if check(got, "告警卡片列出备份过期", node) {
		check(node == "", "汇总类告警的 node_id=all 显示为全局（node 为空）", node)
	}
	mustRun("backup-age", "im", "0")
	check(waitFor(4*time.Minute, func() bool { ok, _ := has(); return !ok }), "恢复后告警卡片不再列出")
}

func stepBackups(u *user) {
	section("AC-OPS-12-3：console-server 用只读凭证读真实 MinIO 的备份清单")
	nowMs := time.Now().UnixMilli()
	fresh, stale := nowMs-60_000, nowMs-(2*time.Hour+time.Minute).Milliseconds()
	for _, m := range []struct {
		source string
		at     int64
	}{{"im", fresh}, {"console", stale}} {
		raw, _ := json.Marshal(map[string]any{"source": m.source, "trigger": "schedule", "result": "success", "finishedAt": m.at, "file": "accept.db.age", "sha256": "00", "size": 1, "verified": true, "encrypted": true, "uploaded": true})
		mustRun("put-manifest", m.source, fmt.Sprint(m.at), string(raw))
	}
	groups := map[string]map[string]any{}
	got := waitFor(90*time.Second, func() bool { // 接口有 30 秒缓存
		for _, g := range list(u.do("GET", opsAPI+"/backups", nil).data(), "groups") {
			m, _ := g.(map[string]any)
			s, _ := m["source"].(string)
			groups[s] = m
		}
		return num(groups["im"], "lastSuccessAt") == float64(fresh) && num(groups["console"], "lastSuccessAt") == float64(stale)
	})
	if check(got, "读到两个来源的最近一次成功", groups) {
		check(groups["im"]["overdue"] == false, "1 分钟前的备份不标红", groups["im"])
		check(groups["console"]["overdue"] == true, "2 小时 1 分钟前的备份标红", groups["console"])
	}
}

func grafana(method, path, cookie string, body []byte) (*http.Response, []byte, error) {
	req, err := http.NewRequest(method, base+path, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Host = grafHost
	if cookie != "" {
		req.Header.Set("Cookie", "__Host-grafana_sid="+cookie)
	}
	if method == http.MethodGet && strings.HasPrefix(path, "/__tianting") {
		req.Header.Set("Sec-Fetch-Mode", "navigate")
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "http://"+grafHost)
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw, nil
}

func stepGrafana(u *user) {
	section("Grafana：票据进入，经认证代理读真实 Grafana，写接口被拦")
	link, _ := u.do("POST", opsAPI+"/grafana/ticket", map[string]any{}).data()["url"].(string)
	i := strings.Index(link, "/__tianting")
	if !check(i >= 0, "拿到一次性票据", link == "") {
		return
	}
	resp, _, err := grafana(http.MethodGet, link[i:], "", nil)
	if err != nil {
		fail("enter: %v", err)
		return
	}
	var cookie string
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-grafana_sid" {
			cookie = c.Value
		}
	}
	if !check(resp.StatusCode == 302 && cookie != "", "票据换到 Cookie", resp.StatusCode) {
		return
	}
	resp, raw, err := grafana(http.MethodGet, "/api/dashboards/uid/tianting-overview", cookie, nil)
	if err != nil {
		fail("dashboard: %v", err)
		return
	}
	var dash struct {
		Dashboard struct {
			Panels []any `json:"panels"`
		} `json:"dashboard"`
		Meta struct {
			CanSave bool `json:"canSave"`
		} `json:"meta"`
	}
	_ = json.Unmarshal(raw, &dash)
	check(resp.StatusCode == 200 && len(dash.Dashboard.Panels) == 14, "代理读到 14 个面板", resp.StatusCode)
	check(!dash.Meta.CanSave, "代理用户不能保存面板（Viewer）", dash.Meta.CanSave)
	resp, raw, err = grafana(http.MethodGet, "/d/tianting-overview", cookie, nil)
	if err == nil {
		check(resp.StatusCode == 200 && bytes.Contains(raw, []byte("<html")), "面板页面能打开", resp.StatusCode)
	}
	q := []byte(`{"from":"now-5m","to":"now","queries":[{"refId":"A","datasource":{"uid":"prometheus"},"expr":"up{job=\"im\"}","instant":true,"maxDataPoints":10,"intervalMs":15000}]}`)
	resp, raw, err = grafana(http.MethodPost, "/api/ds/query", cookie, q)
	if err == nil {
		check(resp.StatusCode == 200 && bytes.Contains(raw, []byte(`"frames"`)), "数据查询经代理到真实 Prometheus", resp.StatusCode, string(raw[:min(len(raw), 200)]))
	}
	resp, _, err = grafana(http.MethodPost, "/api/dashboards/db", cookie, []byte(`{"dashboard":{"title":"x"}}`))
	if err == nil {
		check(resp.StatusCode == 403, "保存面板在代理层被拒", resp.StatusCode)
	}
}

func stepConfigDB(u *user) {
	section("配置检查和数据库页：两个真实节点")
	r := u.do("GET", opsAPI+"/config", nil)
	nodes := list(r.data(), "nodes")
	check(r.status == 200 && len(nodes) == 2, "配置检查返回两个节点", r.status)
	for _, secret := range []string{adminKey} {
		check(!strings.Contains(r.raw, secret), "配置检查不含管理密钥")
	}
	check(len(list(r.data(), "diff")) >= 1 || r.data()["diff"] != nil, "节点差异可读", r.data()["diff"])
	r = u.do("GET", opsAPI+"/db", nil)
	nodes = list(r.data(), "nodes")
	if check(r.status == 200 && len(nodes) == 2, "数据库页返回两个节点", r.status) {
		for _, x := range nodes {
			m, _ := x.(map[string]any)
			db := sub(m, "db")
			check(db["connected"] == true && len(list(db, "migrations")) > 0, fmt.Sprintf("%v 数据库已连接、有迁移记录", m["nodeId"]), db["connected"])
		}
	}
}

func query(u *user, uid string) (reply, time.Duration) {
	body := map[string]any{"userId": uid, "ticket": "CS-1024", "reason": "联调验收排查"}
	for {
		start := time.Now()
		r := u.do("POST", opsAPI+"/troubleshoot/query", body)
		if r.status != 429 {
			return r, time.Since(start)
		}
		time.Sleep(5 * time.Second) // 每分钟上限：不算样本
	}
}

func stepTroubleshoot(ctx context.Context, engineers []*user, samples int) {
	section(fmt.Sprintf("AC-OPS-90-3：双节点用户 %d 次排查，P99 ≤ 800ms", samples))
	if _, err := n1.connect(ctx, "acc-dual", "web"); err != nil {
		fail("connect: %v", err)
		return
	}
	if _, err := n2.connect(ctx, "acc-dual", "pc"); err != nil {
		fail("connect: %v", err)
		return
	}
	if _, err := n1.connect(ctx, "acc-single", "web"); err != nil {
		fail("connect: %v", err)
		return
	}
	if _, err := n2.call("/admin/users/import", map[string]any{"users": []map[string]string{{"userId": "acc-single"}}}); err != nil {
		fail("import: %v", err)
		return
	}
	first, _ := query(engineers[0], "acc-dual")
	d := first.data()
	conns := list(d, "connections")
	check(first.status == 200 && len(conns) == 2 && d["verdict"] == "online" && first.body["partial"] == false, "双节点用户查到 2 条连接", first.raw)

	var mu sync.Mutex
	var lat []time.Duration
	bad := 0
	var wg sync.WaitGroup
	per := samples / len(engineers)
	for _, e := range engineers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range per {
				r, took := query(e, "acc-dual")
				mu.Lock()
				if r.status == 200 && len(list(r.data(), "connections")) == 2 {
					lat = append(lat, took)
				} else {
					bad++
					fmt.Printf("  排查结果不符：%d %s\n", r.status, r.raw[:min(len(r.raw), 300)])
				}
				mu.Unlock()
				time.Sleep(2100 * time.Millisecond) // 每个账号每分钟 30 次以内
			}
		}()
	}
	wg.Wait()
	slices.Sort(lat)
	if check(len(lat) > 0 && bad == 0, fmt.Sprintf("%d 次全部成功", len(lat)), bad) {
		p := func(q float64) time.Duration { return lat[min(int(float64(len(lat))*q), len(lat)-1)] }
		check(p(0.99) <= 800*time.Millisecond, fmt.Sprintf("P50 %v，P99 %v，最大 %v", p(0.5).Round(time.Millisecond), p(0.99).Round(time.Millisecond), lat[len(lat)-1].Round(time.Millisecond)), p(0.99))
	}

	section("AC-OPS-14-6：单节点和双节点用户各排查后对账，差异 0 条")
	for i := range 20 {
		uid := "acc-dual"
		if i%2 == 0 {
			uid = "acc-single"
		}
		r, _ := query(engineers[i%len(engineers)], uid)
		if r.status != 200 {
			fail("query %s: %d %s", uid, r.status, r.raw)
		}
	}
	out, err := run("reconcile")
	fmt.Print(out)
	check(err == nil && strings.Contains(out, "差异 0 条"), "审计和节点日志双向对账一致", err)
}

func stepPausedNode(ctx context.Context, u *user) {
	section("AC-OPS-08-11：n2 暂停时查只在 n2 上的用户")
	if _, err := n2.connect(ctx, "acc-n2only", "web"); err != nil {
		fail("connect: %v", err)
		return
	}
	mustRun("pause", "n2")
	defer mustRun("resume", "n2")
	r, took := query(u, "acc-n2only")
	d := r.data()
	check(r.status == 200, "接口返回成功", r.status, r.raw)
	check(took <= 2500*time.Millisecond, fmt.Sprintf("%v 内返回（要求 2.5 秒）", took.Round(time.Millisecond)), took)
	check(r.body["partial"] == true && d["verdict"] != "offline", fmt.Sprintf("部分结果，verdict=%v，不判为不在线", d["verdict"]), r.raw)
	missing, _ := r.body["missingNodes"].([]any)
	check(len(missing) == 1 && missing[0] == "n2", "标出未响应的节点", r.body["missingNodes"])
}

// 放在最后：时钟推进之后不再恢复，环境随后就销毁。
func stepVersion31(u *user) {
	section("AC-OPS-04-6：版本不一致超过 30 分钟")
	before := u.do("GET", opsAPI+"/nodes", nil).data()
	check(sub(before, "versions")["over30Min"] == false, "推进前没有超过 30 分钟", sub(before, "versions"))
	offset = 31 * time.Minute
	mustRun("set-clocks", fmt.Sprint(time.Now().Add(offset).UnixMilli()))
	probe()
	r := u.do("POST", "/console/api/auth/login", map[string]any{"username": u.name, "password": password, "otp": u.otp()})
	if !check(r.status == 200, "时钟推进后重新登录", r.status, r.raw) {
		return
	}
	v := sub(u.do("GET", opsAPI+"/overview", nil).data(), "versions")
	check(v["over30Min"] == true, "总览显示版本不一致已超过 30 分钟", v)
}

func main() {
	var code, keyFile, steps string
	var samples int
	flag.StringVar(&tt, "tt", "", "deploy/testenv/tt 的路径")
	flag.StringVar(&code, "code", "", "运维空间第一个超管的激活码（tt bootstrap 的输出）")
	flag.StringVar(&keyFile, "admin-key-file", "", "im-server 的 IM_ADMIN_KEY 所在文件")
	flag.StringVar(&steps, "steps", "nodes,overview,alerts,backups,grafana,configdb,troubleshoot,paused,version", "要跑的步骤")
	flag.IntVar(&samples, "samples", 300, "AC-OPS-90-3 的排查次数")
	flag.Parse()
	key, err := os.ReadFile(keyFile) // #nosec G304 -- 路径来自命令行参数，只在测试环境运行
	if err != nil || tt == "" || code == "" {
		fmt.Fprintln(os.Stderr, "-tt, -code and -admin-key-file are required")
		os.Exit(2)
	}
	adminKey = strings.TrimSpace(string(key))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	section("登录：激活超管（真实 TOTP），创建 3 个 ops_engineer")
	super := &user{name: "accsuper"}
	if err := super.activate(code); err != nil {
		fmt.Println("FAIL:", err)
		os.Exit(1)
	}
	if r := super.do("POST", "/console/api/auth/step-up", map[string]any{"otp": super.otp()}); r.status != 200 {
		fmt.Println("FAIL: step-up:", r.status, r.raw)
		os.Exit(1)
	}
	var engineers []*user
	for _, name := range []string{"acceng1", "acceng2", "acceng3"} {
		e, err := super.create(name, "ops_engineer")
		if err != nil {
			fmt.Println("FAIL:", err)
			os.Exit(1)
		}
		engineers = append(engineers, e)
	}
	ok("3 个工程师账号已激活")
	eng := engineers[0]

	want := strings.Split(steps, ",")
	on := func(s string) bool { return slices.Contains(want, s) }
	if on("nodes") {
		stepNodes(eng)
	}
	if on("overview") {
		stepOverview(ctx, eng)
	}
	if on("alerts") {
		stepAlerts(eng)
	}
	if on("backups") {
		stepBackups(eng)
	}
	if on("grafana") {
		stepGrafana(eng)
	}
	if on("configdb") {
		stepConfigDB(eng)
	}
	if on("troubleshoot") {
		stepTroubleshoot(ctx, engineers, samples)
	}
	if on("paused") {
		stepPausedNode(ctx, eng)
	}
	if on("version") {
		stepVersion31(eng)
	}

	if len(failed) > 0 {
		fmt.Printf("== 联调失败 %d 项\n", len(failed))
		for _, f := range failed {
			fmt.Println("- " + f)
		}
		os.Exit(1)
	}
	fmt.Println("== 联调全部通过")
}
