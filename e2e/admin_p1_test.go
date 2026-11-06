package e2e

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// CS-063：全群禁言、用户所在群、用户会话列表（PRD-admin F-ADM-42、F-ADM-10 规则 2、F-ADM-30 规则 1 ③）。

const (
	userConvsPath   = "/console/api/users/convs/query"
	userConvsReason = "用户投诉工单核查"
	imUserConvs     = "/admin/users/convs/query"
)

func userConvsQuery(u *user, userID, reason, cursor string) reply {
	body := map[string]any{"userId": userID}
	if reason != "" {
		body["reason"] = reason
	}
	if cursor != "" {
		body["cursor"] = cursor
	}
	return u.do("POST", userConvsPath, body)
}

// AC-ADM-30-9、TC-ADM-30-09：不填理由 400 / 4000 且 im-server 没收到；填理由成功，没有正文和摘要，1 条审计；15 分钟内翻页不要理由、不新增审计；operator 403。
func TestUserConvs_AC30_9(t *testing.T) {
	b := newBizWorld(t)
	super := b.super("adm1")
	kf := super.create("kf1", "support")
	kf2 := super.create("kf2", "support")
	op := super.create("op1", "operator")
	aud := super.create("aud1", "auditor")

	const mark = "ZXQ-BODY-USERCONV"
	u := uniq("uc")
	peer := uniq("up")
	other := uniq("uo")
	b.users(u, peer, other)
	// 51 个群 + 1 个单聊，默认每页 50：有第二页。
	var groups []string
	for range 51 {
		groups = append(groups, b.group(u, peer))
	}
	conn := b.dial(u, "web")
	if f := conn.send("c2c:"+peer, mark); f["error"] != nil {
		t.Fatalf("send c2c: %v", f)
	}
	if f := conn.send("group:"+groups[50], mark); f["error"] != nil {
		t.Fatalf("send group: %v", f)
	}
	imCalls := func() int { return b.im.count("POST", imUserConvs) }
	auditCount := func() int {
		return len(b.auditRows(`action = 'msg.user_convs.query' AND phase = 'result' AND result = 'success'`))
	}

	// 理由校验不过：im-server 没有收到请求，也没有审计。
	for _, reason := range []string{"", "  ", "abc", "aaaaaa"} {
		r := userConvsQuery(kf, u, reason, "")
		expect(t, "bad reason "+reason, r, 400, 4000)
		if r.reason() != "reasonInvalid" {
			t.Errorf("reason code = %s", r.raw)
		}
	}
	expect(t, "bad ticket", kf.do("POST", userConvsPath, map[string]any{"userId": u, "reason": userConvsReason, "ticket": "bad ticket!"}), 400, 4000)
	expect(t, "bad userId", userConvsQuery(kf, "a b", userConvsReason, ""), 400, 4004)
	// 带 cursor 也绕不过去：没有打开过，翻页和打开一样要理由。
	expect(t, "cursor without opening", userConvsQuery(kf, u, "", "abc"), 400, 4000)
	if n := imCalls(); n != 0 {
		t.Errorf("im-server calls before a valid reason = %d", n)
	}
	if rows := b.auditRows(`action = 'msg.user_convs.query'`); len(rows) != 0 {
		t.Errorf("audit before a valid reason = %v", rows)
	}

	// operator、超管、审计员没有 msg.meta：403，同样不调用 im-server。
	expect(t, "operator", userConvsQuery(op, u, userConvsReason, ""), 403, 4030)
	expect(t, "super admin", userConvsQuery(super, u, userConvsReason, ""), 403, 4030)
	expect(t, "auditor", userConvsQuery(aud, u, userConvsReason, ""), 403, 4030)
	if n := imCalls(); n != 0 {
		t.Errorf("im-server calls for forbidden roles = %d", n)
	}

	// 打开。
	first := userConvsQuery(kf, u, userConvsReason, "")
	expect(t, "open", first, 200, 0)
	convs, _ := first.body["convs"].([]any)
	next, _ := first.body["nextCursor"].(string)
	if len(convs) != 50 || next == "" {
		t.Fatalf("first page = %d, next = %q", len(convs), next)
	}
	// 响应只有会话 ID、类型、最后活跃时间；两层响应都没有特征串。
	seen := map[string]bool{}
	for _, c := range convs {
		m := c.(map[string]any)
		var keys []string
		for k := range m {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		if !slices.Equal(keys, []string{"convId", "type", "updatedAt"}) {
			t.Fatalf("conv fields = %v", keys)
		}
		seen[m["type"].(string)] = true
	}
	if !seen["c2c"] || !seen["group"] {
		t.Errorf("conv types = %v", seen)
	}
	for _, leak := range []string{mark, `"body"`, `"text"`, "lastType", "lastFrom", "lastTs", "peerId", "groupName"} {
		if strings.Contains(first.raw, leak) {
			t.Errorf("response has %q: %.200s", leak, first.raw)
		}
	}
	if strings.Contains(b.im.dump(), mark) {
		t.Error("im-server response has the message text")
	}
	rows := b.auditRows(`action = 'msg.user_convs.query' AND phase = 'result'`)
	if len(rows) != 1 || rows[0]["username"] != "kf1" || rows[0]["reason"] != userConvsReason || !strings.Contains(rows[0]["target"].(string), u) ||
		!strings.Contains(rows[0]["params"].(string), `"count":50`) {
		t.Errorf("audit = %v", rows)
	}
	if intents := b.auditRows(`action = 'msg.user_convs.query' AND phase = 'intent'`); len(intents) != 1 || intents[0]["reason"] != userConvsReason {
		t.Errorf("intent = %v", intents)
	}

	// 翻页不要理由、不新增审计，两页加起来 52 条不重复。
	second := userConvsQuery(kf, u, "", next)
	expect(t, "page 2", second, 200, 0)
	if rest, _ := second.body["convs"].([]any); len(rest) != 2 || second.body["nextCursor"] != "" {
		t.Errorf("second page = %s", second.raw)
	}
	if n := auditCount(); n != 1 {
		t.Errorf("audit after paging = %d", n)
	}
	if n := imCalls(); n != 2 {
		t.Errorf("im-server calls = %d", n)
	}

	// 按账号 + 用户：同一账号换一个登录会话还算；换用户、换账号都不算，也不调用 im-server。
	relogin(t, kf)
	expect(t, "same account, new session", userConvsQuery(kf, u, "", next), 200, 0)
	calls := imCalls()
	expect(t, "other user", userConvsQuery(kf, other, "", next), 400, 4000)
	expect(t, "other account", userConvsQuery(kf2, u, "", next), 400, 4000)
	if n := imCalls(); n != calls {
		t.Errorf("im-server called without a window: %d → %d", calls, n)
	}
	// 再次打开（不带 cursor）又要理由，又一条审计。
	expect(t, "reopen without reason", userConvsQuery(kf, u, "", ""), 400, 4000)
	expect(t, "reopen", userConvsQuery(kf, u, userConvsReason, ""), 200, 0)
	if n := auditCount(); n != 2 {
		t.Errorf("audit after reopening = %d", n)
	}

	// [C 钟] 15 分钟从打开算，翻页不延长。
	b.advance(14 * time.Minute)
	expect(t, "14 min", userConvsQuery(kf, u, "", next), 200, 0)
	b.advance(time.Minute)
	expect(t, "15 min", userConvsQuery(kf, u, "", next), 400, 4000)
	expect(t, "15 min with reason", userConvsQuery(kf, u, userConvsReason, next), 200, 0)
	if n := auditCount(); n != 3 {
		t.Errorf("audit after the window = %d", n)
	}

	// 用户不存在：透传 404 / 4042，失败也留痕，窗口不打开。
	ghost := uniq("ghost")
	expect(t, "no such user", userConvsQuery(kf, ghost, userConvsReason, ""), 404, 4042)
	if rows := b.auditRows(`action = 'msg.user_convs.query' AND phase = 'result' AND code = 4042`); len(rows) != 1 {
		t.Errorf("failed audit = %v", rows)
	}
	expect(t, "no window after failure", userConvsQuery(kf, ghost, "", "abc"), 400, 4000)
	// userId 只在请求体：请求记录的路径固定。
	for _, c := range b.im.find("POST", imUserConvs) {
		if !strings.Contains(c.Body, `"userId"`) || strings.Contains(c.Body, "reason") {
			t.Errorf("im-server body = %s", c.Body)
		}
	}
}

// F-ADM-10 规则 2：用户所在群 group.read、分页、不含已解散的群、不写审计。
func TestUserGroups_ADM10(t *testing.T) {
	b := newBizWorld(t)
	super := b.super("adm1")
	kf := super.create("kf1", "support")
	aud := super.create("aud1", "auditor")
	u := uniq("ug")
	b.users(u)
	var groups []string
	for range 21 {
		groups = append(groups, b.group(u))
	}
	path := "/console/api/users/" + u + "/groups"
	base := len(b.auditRows(`true`))
	first := kf.do("GET", path+"?limit=20", nil)
	expect(t, "page 1", first, 200, 0)
	list, _ := first.body["groups"].([]any)
	next, _ := first.body["nextCursor"].(string)
	if len(list) != 20 || next == "" {
		t.Fatalf("page 1 = %d, next = %q", len(list), next)
	}
	second := kf.do("GET", path+"?limit=20&cursor="+next, nil)
	expect(t, "page 2", second, 200, 0)
	if rest, _ := second.body["groups"].([]any); len(rest) != 1 || second.body["nextCursor"] != "" {
		t.Errorf("page 2 = %s", second.raw)
	}
	if g := list[0].(map[string]any); g["groupId"] == nil || g["name"] == nil || g["role"] == nil {
		t.Errorf("group = %v", g)
	}
	if n := len(b.auditRows(`true`)); n != base {
		t.Errorf("audit rows %d → %d", base, n)
	}
	// 已解散的群不在列表里。
	if err := b.sysDo("DELETE", "/admin/groups/"+groups[0], nil, nil); err != nil {
		t.Fatal(err)
	}
	r := super.do("GET", path+"?limit=50", nil)
	expect(t, "super admin", r, 200, 0)
	if strings.Contains(r.raw, `"`+groups[0]+`"`) {
		t.Errorf("dissolved group listed: %s", r.raw)
	}
	if rest, _ := r.body["groups"].([]any); len(rest) != 20 {
		t.Errorf("after dissolve = %d", len(rest))
	}
	expect(t, "auditor", aud.do("GET", path, nil), 403, 4030)
	expect(t, "bad limit", kf.do("GET", path+"?limit=7", nil), 400, 4000)
	expect(t, "bad id", kf.do("GET", "/console/api/users/a%20b/groups", nil), 400, 4004)
	expect(t, "no such user", kf.do("GET", "/console/api/users/"+uniq("ghost")+"/groups", nil), 404, 4042)
}

// AC-ADM-42-3、TC-ADM-42-03：不填理由 400；填理由开启，详情显示、普通成员 4031、审计有操作人和理由；关闭后恢复；operator 403。
func TestGroupAllMute_AC42_3(t *testing.T) {
	b := newBizWorld(t)
	super := b.super("adm1")
	kf := super.create("kf1", "support")
	op := super.create("op1", "operator")
	owner, member := uniq("go"), uniq("gm")
	b.users(owner, member)
	g := uniq("bg")
	if err := b.sysDo("POST", "/admin/groups", map[string]any{"groupId": g, "name": "n", "members": []string{owner, member}, "owner": owner}, nil); err != nil {
		t.Fatal(err)
	}
	ownerConn, memberConn := b.dial(owner, "web"), b.dial(member, "web")
	allMuted := func(label string, want bool) {
		t.Helper()
		r := kf.do("GET", "/console/api/groups/"+g, nil)
		expect(t, label, r, 200, 0)
		if r.body["allMuted"] != want {
			t.Errorf("%s: allMuted = %v, want %v", label, r.body["allMuted"], want)
		}
		if _, ok := r.body["members"]; ok {
			t.Errorf("%s: members in detail", label)
		}
	}
	mutePath, releasePath := "/console/api/mutes", "/console/api/mutes/release"
	body := func(extra map[string]any) map[string]any {
		m := map[string]any{"scope": "groupAll", "groupId": g}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	allMuted("before", false)

	// 校验都在调用 im-server 之前。
	expect(t, "no reason", kf.do("POST", mutePath, body(nil)), 400, 4000)
	expect(t, "short reason", kf.do("POST", mutePath, body(map[string]any{"reason": "abc"})), 400, 4000)
	expect(t, "duration", kf.do("POST", mutePath, body(map[string]any{"reason": "群内刷屏整顿", "duration": "1h"})), 400, 4000)
	expect(t, "customSeconds", kf.do("POST", mutePath, body(map[string]any{"reason": "群内刷屏整顿", "customSeconds": 600})), 400, 4000)
	expect(t, "userId", kf.do("POST", mutePath, body(map[string]any{"reason": "群内刷屏整顿", "userId": member})), 400, 4000)
	expect(t, "bad group", kf.do("POST", mutePath, map[string]any{"scope": "groupAll", "groupId": "a b", "reason": "群内刷屏整顿"}), 400, 4004)
	expect(t, "operator", op.do("POST", mutePath, body(map[string]any{"reason": "群内刷屏整顿"})), 403, 4030)
	expect(t, "operator release", op.do("POST", releasePath, body(map[string]any{"reason": "群内刷屏整顿"})), 403, 4030)
	if n := b.im.count("POST", "/admin/mute"); n != 0 {
		t.Errorf("im-server mute calls = %d", n)
	}
	allMuted("rejected", false)

	// 开启。
	expect(t, "mute", kf.do("POST", mutePath, body(map[string]any{"reason": "群内刷屏整顿"})), 200, 0)
	allMuted("muted", true)
	f := memberConn.send("group:"+g, "x")
	e, _ := f["error"].(map[string]any)
	if e == nil || e["code"] != float64(4031) {
		t.Errorf("member send = %v", f)
	} else if d, _ := e["details"].(map[string]any); d["scope"] != "groupAll" {
		t.Errorf("details = %v", e)
	}
	if f := ownerConn.send("group:"+g, "x"); f["error"] != nil {
		t.Errorf("owner send = %v", f)
	}
	rows := b.auditRows(`action = 'mute.set' AND phase = 'result' AND result = 'success'`)
	if len(rows) != 1 || rows[0]["username"] != "kf1" || rows[0]["reason"] != "群内刷屏整顿" || !strings.Contains(rows[0]["target"].(string), g) {
		t.Errorf("audit = %v", rows)
	}
	intent := b.auditRows(`action = 'mute.set' AND phase = 'intent'`)
	if len(intent) != 1 || !strings.Contains(intent[0]["params"].(string), `"scope":"groupAll"`) || !strings.Contains(intent[0]["params"].(string), g) {
		t.Errorf("intent = %v", intent)
	}
	// 发给 im-server 的请求没有 userId 和时长（传了是 400）。
	for _, c := range b.im.find("POST", "/admin/mute") {
		if strings.Contains(c.Body, "userId") || strings.Contains(c.Body, "durationSeconds") {
			t.Errorf("im-server body = %s", c.Body)
		}
	}

	// 关闭。
	expect(t, "release no reason", kf.do("POST", releasePath, body(nil)), 400, 4000)
	allMuted("still muted", true)
	expect(t, "release", kf.do("POST", releasePath, body(map[string]any{"reason": "整顿结束恢复"})), 200, 0)
	allMuted("released", false)
	if f := memberConn.send("group:"+g, "y"); f["error"] != nil {
		t.Errorf("member send after release = %v", f)
	}
	if rows := b.auditRows(`action = 'mute.release' AND phase = 'result' AND reason = '整顿结束恢复' AND username = 'kf1'`); len(rows) != 1 {
		t.Errorf("release audit = %v", rows)
	}

	// 状态只用 im-server 返回的：绕过 console 开启，详情也是开着。
	if err := b.sysDo("POST", "/admin/mute", map[string]any{"scope": "groupAll", "groupId": g, "reason": "outside"}, nil); err != nil {
		t.Fatal(err)
	}
	allMuted("muted outside console", true)
	// 不存在的群：透传 404 / 4043。
	expect(t, "no such group", kf.do("POST", mutePath, map[string]any{"scope": "groupAll", "groupId": uniq("nog"), "reason": "群内刷屏整顿"}), 404, 4043)
}
