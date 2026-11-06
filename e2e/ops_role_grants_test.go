package e2e

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// CS-133：双人批准扩大到超管、拒绝、7 天过期、命令行第二超管（PRD-ops F-OPS-02 规则 6）。

const (
	grantReason = "审批记录核对不符"
	opsEngineer = "ops_engineer"
	opsSuperA   = "ops_superadmin"
)

func grantDo(u *user, verb, id, role string, extra map[string]any) reply {
	body := map[string]any{"role": role}
	for k, v := range extra {
		body[k] = v
	}
	return u.do("POST", "/console/api/accounts/"+id+"/roles/"+verb, body)
}

func setRoles(t *testing.T, u *user, id string, roles ...string) reply {
	t.Helper()
	u.stepUp()
	return u.do("POST", "/console/api/accounts/"+id+"/roles", map[string]any{"roles": roles})
}

// accountRoles 从详情接口读角色和待批准的角色。
func accountRoles(t *testing.T, u *user, id string) (roles, pending []string) {
	t.Helper()
	r := u.do("GET", "/console/api/accounts/"+id, nil)
	expect(t, "account view", r, 200, 0)
	for _, x := range r.body["roles"].([]any) {
		roles = append(roles, x.(string))
	}
	for _, x := range r.body["pendingRoles"].([]any) {
		pending = append(pending, x.(map[string]any)["role"].(string))
	}
	slices.Sort(roles)
	return roles, pending
}

func wantRoles(t *testing.T, label string, u *user, id string, roles, pending []string) {
	t.Helper()
	gotR, gotP := accountRoles(t, u, id)
	if !slices.Equal(gotR, roles) || !slices.Equal(gotP, pending) {
		t.Errorf("%s: roles = %v pending = %v, want %v / %v", label, gotR, gotP, roles, pending)
	}
}

func perms(t *testing.T, u *user) string {
	t.Helper()
	r := u.do("GET", "/console/api/session", nil)
	expect(t, "session", r, 200, 0)
	return fmt.Sprint(r.body["perms"])
}

func countRows(t *testing.T, w *world, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := w.db.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// AC-OPS-01-19、TC-OPS-01-21：命令行创建第二个超管；第三个拒绝；管理空间已有启用的超管时拒绝。用真实的命令行进程看退出码。
func TestOpsBootstrapSecond_AC01_19(t *testing.T) {
	w := newWorld(t, nil)
	env := []string{"CON_DATABASE_URL=" + w.db.Config().ConnString(), "CON_DATA_KEYS=k1:" + b64(testDataKey), "CON_HASH_PEPPER=" + b64(testPepper)}
	cli := func(space, name string) (string, error) {
		return run(t, env, "account", "bootstrap", "--space", space, "--username", name)
	}
	s1 := w.opsSuper("osuper")
	aud := s1.create("oaud", "ops_auditor")
	view := s1.create("oview", "ops_viewer")

	out, err := cli("ops", "osuper2")
	if err != nil || !regexp.MustCompile(`[A-Z2-7]{20}`).MatchString(out) {
		t.Fatalf("second: %v\n%s", err, out)
	}
	rows := w.auditRows(`action = 'account.bootstrap' AND space = 'ops' AND target LIKE '%osuper2%'`)
	if len(rows) != 1 || !strings.HasPrefix(rows[0]["actor"].(string), "cli:") || rows[0]["result"] != "success" {
		t.Errorf("audit = %v", rows)
	}
	for _, u := range []*user{s1, aud} {
		if !hasNotice(w.notifications(u), "account.bootstrap", "osuper2") {
			t.Errorf("%s not notified: %v", u.name, w.notifications(u))
		}
	}
	if hasNotice(w.notifications(view), "account.bootstrap", "osuper2") {
		t.Error("viewer was notified")
	}

	// 第三个：一个启用 + 一个待激活已经够 2 个（含待激活）。
	out, err = cli("ops", "osuper3")
	if err == nil || !strings.Contains(out, "already has 2 super admins") {
		t.Errorf("third: %v\n%s", err, out)
	}
	if n := countRows(t, w, `SELECT count(*) FROM auth.accounts WHERE username = 'osuper3'`); n != 0 {
		t.Errorf("third account exists: %d", n)
	}
	if rows := w.auditRows(`action = 'account.bootstrap' AND target LIKE '%osuper3%'`); len(rows) != 0 {
		t.Errorf("third audit = %v", rows)
	}

	// 管理空间：只有 1 个启用的超管也拒绝，例外只在运维空间。
	w.super("adm1")
	out, err = cli("admin", "adm2")
	if err == nil || !strings.Contains(out, "already has an active super admin") {
		t.Errorf("admin second: %v\n%s", err, out)
	}
	if n := countRows(t, w, `SELECT count(*) FROM auth.accounts WHERE username = 'adm2'`); n != 0 {
		t.Errorf("admin second account exists: %d", n)
	}
}

// 管理空间行为不变：没有启用的超管时可以建多个待激活的（AC-CON-02-1 的既有行为），一旦有启用的就拒绝，也不发通知。
func TestBootstrapAdminUnchanged(t *testing.T) {
	w := newWorld(t, nil)
	ctx := context.Background()
	for _, name := range []string{"adma", "admb", "admc"} {
		if _, err := w.a.Bootstrap(ctx, "admin", name); err != nil {
			t.Errorf("admin %s: %v", name, err)
		}
	}
	a := w.super("adm1")
	kf := a.create("aud1", "auditor")
	if _, err := w.a.Bootstrap(ctx, "admin", "admd"); err == nil {
		t.Error("admin bootstrap with an active super admin")
	}
	if _, err := w.a.Bootstrap(ctx, "admin", "adma"); err == nil {
		t.Error("admin resend with an active super admin")
	}
	if hasNotice(w.notifications(a), "account.bootstrap", "") || hasNotice(w.notifications(kf), "account.bootstrap", "") {
		t.Error("admin bootstrap notified")
	}
}

// 运维空间的边界：只数启用和待激活；重发激活码；命令行给了超管之后之前的待批准作废。
func TestOpsBootstrapEdges(t *testing.T) {
	w := newWorld(t, nil)
	ctx := context.Background()
	boot := func(name string) (string, error) { return w.a.Bootstrap(ctx, "ops", name) }
	code1, err := boot("osa")
	if err != nil {
		t.Fatal(err)
	}
	code2, err := boot("osb")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := boot("osc"); err == nil {
		t.Error("third with two pending")
	}
	// 两个都没激活：可以重发已有的，否则激活码过期后这个空间再也进不去；不增加超管。
	if code1, err = boot("osa"); err != nil {
		t.Errorf("resend: %v", err)
	}
	_ = code2
	sa := w.opsClient("osa")
	sa.activate(code1)
	// 有启用的超管之后不能再重发（可以在页面上重置）。
	if _, err := boot("osb"); err == nil {
		t.Error("resend with an active super admin")
	}
	// 停用的不算：osb 停用后又可以建。
	var osbID string
	if err := w.db.QueryRow(ctx, `SELECT id::text FROM auth.accounts WHERE username = 'osb'`).Scan(&osbID); err != nil {
		t.Fatal(err)
	}
	sa.stepUp()
	expect(t, "disable osb", sa.do("POST", "/console/api/accounts/"+osbID+"/disable", map[string]any{}), 200, 0)
	sc := w.opsSuper("osc")
	// 已有 osa、osc 两个。把一个待批准超管的账号交给命令行之前先停用 osc，让命令行还能执行。
	sa.stepUp()
	r := sa.do("POST", "/console/api/accounts", map[string]any{"username": "ypend", "displayName": "y", "roles": []string{opsSuperA}})
	expect(t, "create y", r, 200, 0)
	yID := r.str("id")
	if _, err := boot("ypend"); err == nil {
		t.Error("bootstrap at the limit")
	}
	expect(t, "disable osc", func() reply {
		sa.stepUp()
		return sa.do("POST", "/console/api/accounts/"+sc.id+"/disable", map[string]any{})
	}(), 200, 0)
	if _, err := boot("ypend"); err != nil {
		t.Fatal(err)
	}
	wantRoles(t, "cli took over", sa, yID, []string{opsSuperA}, nil)
	if n := countRows(t, w, `SELECT count(*) FROM auth.role_grant_requests WHERE account_id = $1::uuid AND status = 'pending'`, yID); n != 0 {
		t.Errorf("grant left pending after the cli took over: %d", n)
	}
	sa.stepUp()
	expect(t, "cancelled by cli", grantDo(sa, "reject", yID, opsSuperA, map[string]any{"reason": grantReason}), 409, 4093)
}

// AC-OPS-01-11：唯一的超管停用自己 409；命令行创建第二个并激活；第一个停用第二个成功；再停用自己 409。
func TestOpsLastSuper_AC01_11(t *testing.T) {
	w := newWorld(t, nil)
	a := w.opsSuper("osuper")
	a.stepUp()
	expect(t, "only super", a.do("POST", "/console/api/accounts/"+a.id+"/disable", map[string]any{}), 409, 4093)
	b := w.opsSuper("osuper2")
	a.stepUp()
	expect(t, "disable second", a.do("POST", "/console/api/accounts/"+b.id+"/disable", map[string]any{}), 200, 0)
	a.stepUp()
	expect(t, "disable self", a.do("POST", "/console/api/accounts/"+a.id+"/disable", map[string]any{}), 409, 4093)
	expect(t, "second is out", b.do("GET", "/console/api/session", nil), 401, 4014)
	if got := perms(t, a); !strings.Contains(got, "ops.account.manage") {
		t.Errorf("first super = %s", got)
	}
}

// AC-OPS-02-10、TC-OPS-02-11：新建超管也要第二个人批准；批准前只有"只需登录"；批准后重新登录生效；全部有审计。
func TestOpsSuperApproval_AC02_10(t *testing.T) {
	o := newOpsWorld(t)
	a, b := o.super, o.super2nd
	y := a.create("ysuper", opsSuperA)
	if r := y.do("GET", "/console/api/session", nil); r.status != 200 || len(r.body["perms"].([]any)) != 0 {
		t.Errorf("pending super session = %s", r.raw)
	}
	wantRoles(t, "pending", a, y.id, nil, []string{opsSuperA})
	expect(t, "y manages accounts", y.do("GET", "/console/api/accounts", nil), 403, 4030)

	a.stepUp()
	expect(t, "self approve", grantDo(a, "approve", y.id, opsSuperA, nil), 403, 4030)
	expect(t, "y still out", y.do("GET", "/console/api/accounts", nil), 403, 4030)

	o.advance(6 * time.Minute)
	expect(t, "b no step-up", grantDo(b, "approve", y.id, opsSuperA, nil), 403, 4038)
	b.stepUp()
	expect(t, "b approves", grantDo(b, "approve", y.id, opsSuperA, nil), 200, 0)
	expect(t, "old session", y.do("GET", "/console/api/accounts", nil), 401, 4014)
	relogin(t, y)
	expect(t, "y manages accounts", y.do("GET", "/console/api/accounts", nil), 200, 0)
	wantRoles(t, "approved", a, y.id, []string{opsSuperA}, nil)

	// 三步审计：发起带 pendingRoles，本人批准 denied，第二个人批准 success。
	grant := o.auditRows(`action = 'account.create' AND target LIKE '%ysuper%' AND phase = 'result' AND result = 'success'`)
	if len(grant) != 1 || grant[0]["username"] != "osuper" {
		t.Errorf("grant audit = %v", grant)
	}
	intent := o.auditRows(`action = 'account.create' AND target LIKE '%ysuper%' AND phase = 'intent'`)
	if len(intent) != 1 || !strings.Contains(intent[0]["params"].(string), `"pendingRoles":["ops_superadmin"]`) {
		t.Errorf("grant intent = %v", intent)
	}
	denied := o.auditRows(`action = 'account.role_approve' AND result = 'denied' AND target LIKE '%ysuper%'`)
	if len(denied) != 1 || denied[0]["username"] != "osuper" || denied[0]["code"].(int32) != 4030 {
		t.Errorf("denied audit = %v", denied)
	}
	ok := o.auditRows(`action = 'account.role_approve' AND phase = 'result' AND result = 'success' AND target LIKE '%ysuper%'`)
	if len(ok) != 1 || ok[0]["username"] != "osuper2" || !strings.Contains(ok[0]["params"].(string), `"requestedBy":"osuper"`) {
		t.Errorf("approve audit = %v", ok)
	}
	// 审计员在发起时（标了待批准）和批准时都收到通知。
	list := o.notifications(o.auditor)
	if !hasNotice(list, "account.sensitive_role", `"pending": true`) || !hasNotice(list, "account.sensitive_role", `"by": "osuper2"`) {
		t.Errorf("notifications = %v", list)
	}
	// 新超管可以批准别人发起的授予，这正是双人批准要的第二个人。
	x := a.create("xeng2", opsEngineer)
	y.stepUp()
	expect(t, "y approves", grantDo(y, "approve", x.id, opsEngineer, nil), 200, 0)
}

// F-OPS-02 规则 6"待批准期间"：要替换现有角色的授予，在批准前账号的角色和会话都不变；拒绝后不变；批准后才替换。
func TestOpsPendingKeepsCurrentRoles(t *testing.T) {
	o := newOpsWorld(t)
	a, b := o.super, o.super2nd
	x := a.create("xview", "ops_viewer")
	viewerPerms := perms(t, x)
	r := setRoles(t, a, x.id, opsSuperA)
	expect(t, "request", r, 200, 0)
	if fmt.Sprint(r.body["roles"]) != "[ops_viewer]" || fmt.Sprint(r.body["pendingRoles"]) != "[ops_superadmin]" {
		t.Errorf("response = %s", r.raw)
	}
	if got := perms(t, x); got != viewerPerms {
		t.Errorf("perms while pending = %s, want %s", got, viewerPerms)
	}
	view := a.do("GET", "/console/api/accounts/"+x.id, nil)
	p := view.body["pendingRoles"].([]any)[0].(map[string]any)
	if fmt.Sprint(p["replaces"]) != "[ops_viewer]" {
		t.Errorf("pending = %v", p)
	}
	b.stepUp()
	expect(t, "reject", grantDo(b, "reject", x.id, opsSuperA, map[string]any{"reason": grantReason}), 200, 0)
	wantRoles(t, "rejected", a, x.id, []string{"ops_viewer"}, nil)
	if got := perms(t, x); got != viewerPerms {
		t.Errorf("perms after reject = %s", got)
	}

	expect(t, "request again", setRoles(t, a, x.id, opsSuperA), 200, 0)
	b.stepUp()
	expect(t, "approve", grantDo(b, "approve", x.id, opsSuperA, nil), 200, 0)
	wantRoles(t, "approved", a, x.id, []string{opsSuperA}, nil)
	expect(t, "session revoked", x.do("GET", "/console/api/session", nil), 401, 4014)

	// 审计员 → 查看 + 排障：批准前还是审计员（不能同时有审计员和查看）；批准后两个一起生效。
	z := a.create("zaud", "ops_auditor")
	expect(t, "aud to eng", setRoles(t, a, z.id, opsEngineer, "ops_viewer"), 200, 0)
	wantRoles(t, "aud pending", a, z.id, []string{"ops_auditor"}, []string{opsEngineer})
	b.stepUp()
	expect(t, "approve aud", grantDo(b, "approve", z.id, opsEngineer, nil), 200, 0)
	wantRoles(t, "aud approved", a, z.id, []string{opsEngineer, "ops_viewer"}, nil)

	// 不去掉现有角色的授予：查看马上生效，排障等批准（新建账号也是）。
	v := a.create("vboth", "ops_viewer", opsEngineer)
	wantRoles(t, "both", a, v.id, []string{"ops_viewer"}, []string{opsEngineer})
	// 降级立即生效：没有待批准的改动不等批准（AC-OPS-02-4）。
	expect(t, "drop", setRoles(t, a, z.id, "ops_viewer"), 200, 0)
	wantRoles(t, "dropped", a, z.id, []string{"ops_viewer"}, nil)
}

// AC-OPS-02-11、TC-OPS-02-12：拒绝要理由；拒绝后角色不变、再批准 409；发起人可以拒绝；要重新验证；有审计。
func TestOpsRoleReject_AC02_11(t *testing.T) {
	o := newOpsWorld(t)
	a, b := o.super, o.super2nd
	x := a.create("xrej", "ops_viewer")
	viewer := []string{"ops_viewer"}
	expect(t, "grant", setRoles(t, a, x.id, opsEngineer, "ops_viewer"), 200, 0)

	b.stepUp()
	for _, reason := range []string{"", "   ", "abc", "aaaaaa", strings.Repeat("长", 201)} {
		expect(t, "bad reason "+reason, grantDo(b, "reject", x.id, opsEngineer, map[string]any{"reason": reason}), 400, 4000)
	}
	expect(t, "no reason field", grantDo(b, "reject", x.id, opsEngineer, nil), 400, 4000)
	wantRoles(t, "still pending", a, x.id, viewer, []string{opsEngineer})
	if rows := o.auditRows(`action = 'ops.role.reject'`); len(rows) != 0 {
		t.Errorf("audit for invalid reject = %v", rows)
	}

	expect(t, "other role", grantDo(b, "reject", x.id, "ops_viewer", map[string]any{"reason": grantReason}), 400, 4000)
	r := grantDo(b, "reject", x.id, opsEngineer, map[string]any{"reason": "  " + grantReason + " "})
	expect(t, "reject", r, 200, 0)
	wantRoles(t, "rejected", a, x.id, viewer, nil)
	expect(t, "x not signed out", x.do("GET", "/console/api/session", nil), 200, 0)
	rows := o.auditRows(`action = 'ops.role.reject' AND phase = 'result'`)
	if len(rows) != 1 || rows[0]["username"] != "osuper2" || rows[0]["result"] != "success" || rows[0]["reason"] != grantReason ||
		!strings.Contains(rows[0]["target"].(string), "xrej") || !strings.Contains(rows[0]["params"].(string), `"requestedBy":"osuper"`) {
		t.Errorf("reject audit = %v", rows)
	}
	expect(t, "approve rejected", grantDo(b, "approve", x.id, opsEngineer, nil), 409, 4093)
	expect(t, "reject twice", grantDo(b, "reject", x.id, opsEngineer, map[string]any{"reason": grantReason}), 409, 4093)
	if rows := o.auditRows(`action = 'ops.role.reject' AND phase = 'result' AND code = 4093`); len(rows) != 1 {
		t.Errorf("failed reject audit = %v", rows)
	}

	// 发起人拒绝等于撤回。
	expect(t, "grant 2", setRoles(t, a, x.id, opsEngineer, "ops_viewer"), 200, 0)
	a.stepUp()
	expect(t, "withdraw", grantDo(a, "reject", x.id, opsEngineer, map[string]any{"reason": grantReason}), 200, 0)
	wantRoles(t, "withdrawn", a, x.id, viewer, nil)

	// 重新验证：4038，不改状态。
	expect(t, "grant 3", setRoles(t, a, x.id, opsEngineer, "ops_viewer"), 200, 0)
	o.advance(6 * time.Minute)
	expect(t, "no step-up", grantDo(b, "reject", x.id, opsEngineer, map[string]any{"reason": grantReason}), 403, 4038)
	wantRoles(t, "still pending 3", a, x.id, viewer, []string{opsEngineer})

	// 只有超管能调；不存在的账号 404 且记 denied（F-CON-02 规则 7）；管理空间没有这个接口。
	o.viewer.stepUp()
	expect(t, "viewer", grantDo(o.viewer, "reject", x.id, opsEngineer, map[string]any{"reason": grantReason}), 403, 4030)
	b.stepUp()
	expect(t, "missing", grantDo(b, "reject", "00000000-0000-4000-8000-000000000001", opsEngineer, map[string]any{"reason": grantReason}), 404, 4040)
	if rows := o.auditRows(`action = 'ops.role.reject' AND phase = 'result' AND code = 4040 AND result = 'denied'`); len(rows) != 1 {
		t.Errorf("missing audit = %v", rows)
	}
	admin := o.world.super("adm8")
	admin.stepUp()
	expect(t, "admin route", grantDo(admin, "reject", x.id, opsEngineer, map[string]any{"reason": grantReason}), 404, 4040)
}

// AC-OPS-02-12、TC-OPS-02-13 [C 钟]：6 天 23 小时还在列表；过 7 天批准和拒绝都 409 / 4093，角色不变，ops.role.expire 只写一次。
func TestOpsRoleExpire_AC02_12(t *testing.T) {
	o := newOpsWorld(t)
	a, b := o.super, o.super2nd
	x := a.create("xexp", "ops_viewer")
	expect(t, "grant", setRoles(t, a, x.id, opsEngineer, "ops_viewer"), 200, 0)
	view := a.do("GET", "/console/api/accounts/"+x.id, nil)
	p := view.body["pendingRoles"].([]any)[0].(map[string]any)
	if p["expiresAt"].(float64)-p["requestedAt"].(float64) != float64((7*24*time.Hour).Milliseconds()) || p["requestedBy"] != "osuper" {
		t.Errorf("pending = %v", p)
	}
	expireRows := func() []map[string]any { return o.auditRows(`action = 'ops.role.expire'`) }

	o.advance(6*24*time.Hour + 23*time.Hour)
	relogin(t, b)
	list := b.do("GET", "/console/api/accounts?username=xexp", nil)
	if !strings.Contains(list.raw, `"pendingRoles":[{"role":"ops_engineer"`) {
		t.Errorf("list before expiry = %s", list.raw)
	}
	if rows := expireRows(); len(rows) != 0 {
		t.Errorf("expired early: %v", rows)
	}

	o.advance(2 * time.Hour)
	relogin(t, b)
	relogin(t, a)
	// 没有后台任务也生效：第一次碰到它的就是这次列表查询。
	list = b.do("GET", "/console/api/accounts?username=xexp", nil)
	if strings.Contains(list.raw, `"role":"ops_engineer"`) {
		t.Errorf("list after expiry = %s", list.raw)
	}
	b.stepUp()
	expect(t, "approve expired", grantDo(b, "approve", x.id, opsEngineer, nil), 409, 4093)
	expect(t, "reject expired", grantDo(b, "reject", x.id, opsEngineer, map[string]any{"reason": grantReason}), 409, 4093)
	// 发起人也是 409，不是"本人不能批准"：已经没有待批准了。
	a.stepUp()
	expect(t, "requester approves expired", grantDo(a, "approve", x.id, opsEngineer, nil), 409, 4093)
	wantRoles(t, "unchanged", a, x.id, []string{"ops_viewer"}, nil)
	relogin(t, x)
	if got := perms(t, x); strings.Contains(got, "ops.troubleshoot") {
		t.Errorf("x perms = %s", got)
	}

	// 读、写、定时任务多次，只有一条。
	for range 3 {
		a.do("GET", "/console/api/accounts", nil)
		if err := o.a.ExpireRoleGrants(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	rows := expireRows()
	if len(rows) != 1 || rows[0]["phase"] != "event" || rows[0]["result"] != "success" || !strings.Contains(rows[0]["target"].(string), "xexp") ||
		!strings.Contains(rows[0]["params"].(string), `"role":"ops_engineer"`) {
		t.Errorf("expire audit = %v", rows)
	}

	// 过期之后可以重新发起，是一条全新的待批准。
	expect(t, "grant again", setRoles(t, a, x.id, opsEngineer, "ops_viewer"), 200, 0)
	wantRoles(t, "new grant", a, x.id, []string{"ops_viewer"}, []string{opsEngineer})
	b.stepUp()
	expect(t, "approve new", grantDo(b, "approve", x.id, opsEngineer, nil), 200, 0)
}

// 第一次碰到过期待批准的是批准本身；正好 7 天算过期，差 1 毫秒不算；重复发起不延长 7 天。
func TestOpsRoleExpireBoundary(t *testing.T) {
	o := newOpsWorld(t)
	a, b := o.super, o.super2nd
	x := a.create("xbnd", "ops_viewer")
	expect(t, "grant", setRoles(t, a, x.id, opsEngineer, "ops_viewer"), 200, 0)
	grantAt := o.now // setRoles 里的 step-up 推进了时钟
	o.advance(3 * 24 * time.Hour)
	relogin(t, a)
	expect(t, "repeat", setRoles(t, a, x.id, opsEngineer, "ops_viewer"), 200, 0)
	o.advance(grantAt.Add(7*24*time.Hour - time.Minute).Sub(o.now))
	relogin(t, b)
	b.stepUp()
	stepped := o.now
	o.advance(grantAt.Add(7*24*time.Hour - time.Millisecond).Sub(stepped))
	view := b.do("GET", "/console/api/accounts/"+x.id, nil)
	if len(view.body["pendingRoles"].([]any)) != 1 {
		t.Errorf("1ms before expiry = %s", view.raw)
	}
	o.advance(time.Millisecond)
	expect(t, "approve at exactly 7 days", grantDo(b, "approve", x.id, opsEngineer, nil), 409, 4093)
	if rows := o.auditRows(`action = 'ops.role.expire'`); len(rows) != 1 {
		t.Errorf("expire audit = %v", rows)
	}
}

// 审计写失败：页面和批准仍然按过期处理，下一次补写，还是一条。多实例并发也只有一条。
func TestOpsRoleExpireAuditOnce(t *testing.T) {
	o := newOpsWorld(t)
	a, b := o.super, o.super2nd
	x := a.create("xonce", "ops_viewer")
	expect(t, "grant", setRoles(t, a, x.id, opsEngineer, "ops_viewer"), 200, 0)
	o.advance(7*24*time.Hour + time.Hour)
	relogin(t, b)
	o.a.Audit.Fault = func(phase string) bool { return phase == "event" }
	view := b.do("GET", "/console/api/accounts/"+x.id, nil)
	expect(t, "view while audit is down", view, 200, 0)
	if len(view.body["pendingRoles"].([]any)) != 0 {
		t.Errorf("view = %s", view.raw)
	}
	o.a.Audit.Fault = nil
	if rows := o.auditRows(`action = 'ops.role.expire'`); len(rows) != 0 {
		t.Errorf("audit = %v", rows)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if err := o.a.ExpireRoleGrants(context.Background()); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if rows := o.auditRows(`action = 'ops.role.expire'`); len(rows) != 1 {
		t.Errorf("audit = %v", rows)
	}

	// 上一次写完审计、没来得及改状态（进程在两者之间退出）：不重复写。
	y := a
	relogin(t, y)
	z := y.create("zonce", "ops_viewer")
	expect(t, "grant z", setRoles(t, y, z.id, opsEngineer, "ops_viewer"), 200, 0)
	var reqID string
	if err := o.db.QueryRow(context.Background(), `SELECT id::text FROM auth.role_grant_requests WHERE account_id = $1::uuid AND status = 'pending'`, z.id).Scan(&reqID); err != nil {
		t.Fatal(err)
	}
	o.advance(7*24*time.Hour + time.Hour)
	if err := o.a.ExpireRoleGrants(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := o.db.Exec(ctx, `UPDATE auth.role_grant_requests SET status = 'pending', decided_at = NULL WHERE id = $1::uuid`, reqID); err != nil {
		t.Fatal(err)
	}
	if err := o.a.ExpireRoleGrants(ctx); err != nil {
		t.Fatal(err)
	}
	if rows := o.auditRows(`action = 'ops.role.expire' AND request_id = $1`, reqID); len(rows) != 1 {
		t.Errorf("rewritten audit = %v", rows)
	}
	var status string
	if err := o.db.QueryRow(ctx, `SELECT status FROM auth.role_grant_requests WHERE id = $1::uuid`, reqID).Scan(&status); err != nil || status != "expired" {
		t.Errorf("status = %s %v", status, err)
	}
}

// 批准时重新检查（F-OPS-02 规则 6）：待批准期间账号被停用或角色被改，批准 409 / 4093，角色不变。
func TestOpsApprovalRechecks(t *testing.T) {
	o := newOpsWorld(t)
	a, b := o.super, o.super2nd

	// 停用（新建超管）：409；重新启用后还在 7 天内可以批准。
	d := a.create("xdis", opsSuperA)
	a.stepUp()
	expect(t, "disable", a.do("POST", "/console/api/accounts/"+d.id+"/disable", map[string]any{}), 200, 0)
	b.stepUp()
	expect(t, "approve disabled", grantDo(b, "approve", d.id, opsSuperA, nil), 409, 4093)
	wantRoles(t, "disabled", a, d.id, nil, []string{opsSuperA})
	a.stepUp()
	expect(t, "enable", a.do("POST", "/console/api/accounts/"+d.id+"/enable", map[string]any{}), 200, 0)
	b.stepUp()
	expect(t, "approve enabled", grantDo(b, "approve", d.id, opsSuperA, nil), 200, 0)
	wantRoles(t, "enabled", a, d.id, []string{opsSuperA}, nil)

	// 角色被改成别的：待批准作废。
	c := a.create("xchg", opsSuperA)
	expect(t, "to auditor", setRoles(t, a, c.id, "ops_auditor"), 200, 0)
	b.stepUp()
	expect(t, "approve changed", grantDo(b, "approve", c.id, opsSuperA, nil), 409, 4093)
	wantRoles(t, "changed", a, c.id, []string{"ops_auditor"}, nil)

	// 绕过接口写进了互斥角色：批准不能变成"超管 + 审计员"。
	m := a.create("xmut", opsEngineer)
	if _, err := o.db.Exec(context.Background(), `INSERT INTO auth.account_roles (account_id, role, granted_by, granted_at) VALUES ($1::uuid, 'ops_auditor', 'test', 1)`, m.id); err != nil {
		t.Fatal(err)
	}
	b.stepUp()
	expect(t, "approve conflicting", grantDo(b, "approve", m.id, opsEngineer, nil), 409, 4093)
	wantRoles(t, "conflict", a, m.id, []string{"ops_auditor"}, []string{opsEngineer})

	// 已经有这个角色：409，不是主键冲突的 500。
	dup := a.create("xdup", opsEngineer)
	if _, err := o.db.Exec(context.Background(), `INSERT INTO auth.account_roles (account_id, role, granted_by, granted_at) VALUES ($1::uuid, 'ops_engineer', 'test', 1)`, dup.id); err != nil {
		t.Fatal(err)
	}
	b.stepUp()
	expect(t, "approve duplicate", grantDo(b, "approve", dup.id, opsEngineer, nil), 409, 4093)

	// 批准和失败都留痕。
	if rows := o.auditRows(`action = 'account.role_approve' AND phase = 'result' AND code = 4093`); len(rows) != 4 {
		t.Errorf("failed approvals = %d", len(rows))
	}
}

// 并发批准和拒绝同一条：只有一个成功，另一个 409 / 4093，角色和结果一致。
func TestOpsApprovalConcurrent(t *testing.T) {
	o := newOpsWorld(t)
	a, b := o.super, o.super2nd
	c := a.create("osuper3", opsSuperA)
	b.stepUp()
	expect(t, "approve c", grantDo(b, "approve", c.id, opsSuperA, nil), 200, 0)
	relogin(t, c)

	race := func(label string, fns ...func() reply) []reply {
		t.Helper()
		out := make([]reply, len(fns))
		var wg sync.WaitGroup
		for i, fn := range fns {
			wg.Go(func() { out[i] = fn() })
		}
		wg.Wait()
		wins := 0
		for _, r := range out {
			switch {
			case r.status == 200:
				wins++
			case r.status != 409 || r.code() != 4093:
				t.Errorf("%s: %d %s", label, r.status, r.raw)
			}
		}
		if wins != 1 {
			t.Errorf("%s: %d winners", label, wins)
		}
		return out
	}
	for i := range 6 {
		x := a.create(fmt.Sprintf("xrace%d", i), "ops_viewer")
		expect(t, "grant", setRoles(t, a, x.id, opsEngineer, "ops_viewer"), 200, 0)
		b.stepUp()
		c.stepUp()
		rs := race("approve vs reject", func() reply { return grantDo(b, "approve", x.id, opsEngineer, nil) },
			func() reply { return grantDo(c, "reject", x.id, opsEngineer, map[string]any{"reason": grantReason}) })
		want := []string{"ops_viewer"}
		if rs[0].status == 200 {
			want = []string{opsEngineer, "ops_viewer"}
		}
		wantRoles(t, "after race", a, x.id, want, nil)
	}
	y := a.create("yrace", opsEngineer)
	b.stepUp()
	c.stepUp()
	race("two approvals", func() reply { return grantDo(b, "approve", y.id, opsEngineer, nil) }, func() reply { return grantDo(c, "approve", y.id, opsEngineer, nil) })
	z := a.create("zrace", opsEngineer)
	b.stepUp()
	c.stepUp()
	race("two rejections", func() reply { return grantDo(b, "reject", z.id, opsEngineer, map[string]any{"reason": grantReason}) },
		func() reply { return grantDo(c, "reject", z.id, opsEngineer, map[string]any{"reason": grantReason}) })
	if n := countRows(t, o.world, `SELECT count(*) FROM auth.role_grant_requests WHERE status = 'pending'`); n != 0 {
		t.Errorf("pending left = %d", n)
	}
}

// AC-OPS-01-20: no enabled super admin and both activation codes expired. The command line resends a code to an
// existing pending super admin and adds nobody.
func TestOpsBootstrapResend_AC01_20(t *testing.T) {
	w := newWorld(t, nil)
	ctx := context.Background()
	boot := func(name string) (string, error) { return w.a.Bootstrap(ctx, "ops", name) }
	for _, name := range []string{"osa", "osb"} {
		if _, err := boot(name); err != nil {
			t.Fatal(err)
		}
	}
	w.advance(25 * time.Hour)
	before := len(w.auditRows(`action = 'account.bootstrap' AND space = 'ops' AND target LIKE '%osa%'`))

	code, err := boot("osa")
	if err != nil {
		t.Fatalf("resend: %v", err)
	}
	if rows := w.auditRows(`action = 'account.bootstrap' AND space = 'ops' AND target LIKE '%osa%'`); len(rows) != before+1 {
		t.Errorf("audit: %d rows, had %d", len(rows), before)
	}
	if _, err := boot("osnew"); err == nil {
		t.Error("new account while two are pending")
	}
	if n := countRows(t, w, `SELECT count(*) FROM auth.accounts WHERE space = 'ops'`); n != 2 {
		t.Errorf("ops accounts = %d, want 2", n)
	}
	w.opsClient("osa").activate(code)
}
