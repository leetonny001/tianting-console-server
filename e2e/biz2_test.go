package e2e

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// PRD-admin 第二批（CS-040 ～ CS-043）：console + 代理 + 真实 im-server。

// sendInto 让 uid 往群里发一条消息，返回 msgId。
func sendInto(t *testing.T, b *bizWorld, uid, group string) string {
	t.Helper()
	return sendText(t, b, uid, group, "matrix message")
}

func sendText(t *testing.T, b *bizWorld, uid, group, text string) string {
	t.Helper()
	c := b.dial(uid, "web")
	defer func() { _ = c.ws.CloseNow() }()
	f := c.send("group:"+group, text)
	d, _ := f["data"].(map[string]any)
	id, _ := d["msgId"].(string)
	if id == "" {
		t.Fatalf("send: %v", f)
	}
	return id
}

func (b *bizWorld) group(members ...string) string {
	b.t.Helper()
	g := uniq("bg")
	if err := b.sysDo("POST", "/admin/groups", map[string]any{"groupId": g, "name": "n", "members": members}, nil); err != nil {
		b.t.Fatal(err)
	}
	return g
}

func TestBatch2(t *testing.T) {
	b := newBizWorld(t)
	super := b.super("adm2")
	mod := super.create("mod2", "moderator")
	kf := super.create("kf2", "support")
	aud := super.create("aud2", "auditor")
	grantReq := func(c *user, conv string, extra map[string]any) map[string]any {
		b.tick()
		m := map[string]any{"convId": conv, "ticket": "T-100", "reason": "case review", "otp": c.otp()}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}

	// AC-ADM-13-1、13-5、13-10。
	t.Run("ban", func(t *testing.T) {
		u := uniq("bu")
		b.users(u)
		conn := b.dial(u, "web")
		path := "/console/api/users/" + u
		before := len(b.im.find("POST", "/admin/users/"+u+"/ban"))
		r := mod.do("POST", path+"/ban", map[string]any{"duration": "1d", "reason": "spam spam"})
		expect(t, "no step-up", r, 403, 4038)
		if len(b.im.find("POST", "/admin/users/"+u+"/ban")) != before {
			t.Error("reached im-server without step-up")
		}
		mod.stepUp()
		expect(t, "bad duration", mod.do("POST", path+"/ban", map[string]any{"duration": "2h", "reason": "spam spam"}), 400, 4000)
		expect(t, "bad reason", mod.do("POST", path+"/ban", map[string]any{"duration": "1d", "reason": "aaaa"}), 400, 4000)
		expect(t, "ban", mod.do("POST", path+"/ban", map[string]any{"duration": "1d", "reason": "spam spam"}), 200, 0)
		f := conn.wait("kicked")
		if d := f["data"].(map[string]any); d["reason"] != "suspended" || d["until"] == nil {
			t.Errorf("kicked = %v", f)
		}
		if st := conn.closed(); int(st) != 4012 {
			t.Errorf("close = %d", st)
		}
		// 详情显示的是 im-server 的值。
		got := mod.do("GET", path, nil)
		if ban, _ := got.body["ban"].(map[string]any); ban == nil || ban["reason"] != "spam spam" {
			t.Errorf("detail = %s", got.raw)
		}
		list := mod.do("GET", "/console/api/users?q="+u, nil)
		if !strings.Contains(list.raw, `"reason":"spam spam"`) {
			t.Errorf("list = %s", list.raw)
		}
		err := b.sysDo("POST", "/admin/users/token", map[string]any{"userId": u}, nil)
		if err == nil || !strings.Contains(err.Error(), "4034") {
			t.Errorf("issue while banned: %v", err)
		}
		expect(t, "unban", mod.do("POST", path+"/unban", map[string]any{"reason": "appeal accepted"}), 200, 0)
		if err := b.sysDo("POST", "/admin/users/token", map[string]any{"userId": u}, nil); err != nil {
			t.Errorf("issue after unban: %v", err)
		}
		if len(b.auditRows(`action = 'user.ban' AND phase = 'result' AND result = 'success' AND reason = 'spam spam'`)) == 0 ||
			len(b.auditRows(`action = 'user.unban' AND phase = 'result' AND result = 'success'`)) == 0 {
			t.Error("no audit")
		}
		expect(t, "support cannot ban", kf.do("POST", path+"/ban", map[string]any{"duration": "1d", "reason": "spam spam"}), 403, 4030)
		expect(t, "ghost", mod.do("POST", "/console/api/users/ghost-"+u+"/ban", map[string]any{"duration": "1d", "reason": "spam spam"}), 404, 4042)
	})

	// AC-ADM-40-4、40-7、41-4、41-5。
	t.Run("mute", func(t *testing.T) {
		u, u2 := uniq("mu"), uniq("mv")
		b.users(u, u2)
		g := b.group(u)
		expect(t, "support can mute", kf.do("POST", "/console/api/mutes", map[string]any{"scope": "user", "userId": u, "duration": "10m", "reason": "spam spam"}), 200, 0)
		conn := b.dial(u, "web")
		if e, _ := conn.sendOnce("group:"+g, "x")["error"].(map[string]any); e == nil || e["code"].(float64) != 4031 {
			t.Errorf("muted send: %v", e)
		}
		if d := kf.do("GET", "/console/api/users/"+u, nil); d.body["mutedUntil"] == nil {
			t.Errorf("detail = %s", d.raw)
		}
		expect(t, "release", kf.do("POST", "/console/api/mutes/release", map[string]any{"scope": "user", "userId": u, "reason": "appeal accepted"}), 200, 0)
		conn.wait("unmuted")
		if e, _ := conn.send("group:"+g, "ok")["error"].(map[string]any); e != nil {
			t.Errorf("after release: %v", e)
		}
		// 群内。
		expect(t, "not member", kf.do("POST", "/console/api/mutes", map[string]any{"scope": "group", "groupId": g, "userId": u2, "duration": "1h", "reason": "spam spam"}), 404, 4046)
		expect(t, "ghost", kf.do("POST", "/console/api/mutes", map[string]any{"scope": "user", "userId": "ghost-" + u, "duration": "1h", "reason": "spam spam"}), 404, 4042)
		expect(t, "custom too long", kf.do("POST", "/console/api/mutes", map[string]any{"scope": "user", "userId": u, "customSeconds": 2592001, "reason": "spam spam"}), 400, 4000)
		expect(t, "both", kf.do("POST", "/console/api/mutes", map[string]any{"scope": "user", "userId": u, "duration": "1h", "customSeconds": 600, "reason": "spam spam"}), 400, 4000)
		expect(t, "group mute", kf.do("POST", "/console/api/mutes", map[string]any{"scope": "group", "groupId": g, "userId": u, "customSeconds": 600, "reason": "spam spam"}), 200, 0)
		ms := kf.do("GET", "/console/api/groups/"+g+"/members", nil)
		if !strings.Contains(ms.raw, "mutedUntil") {
			t.Errorf("members = %s", ms.raw)
		}
		expect(t, "group release", kf.do("POST", "/console/api/mutes/release", map[string]any{"scope": "group", "groupId": g, "userId": u, "reason": "appeal accepted"}), 200, 0)
		if ms := kf.do("GET", "/console/api/groups/"+g+"/members", nil); strings.Contains(ms.raw, "mutedUntil") {
			t.Errorf("members after release = %s", ms.raw)
		}
		expect(t, "auditor cannot mute", aud.do("POST", "/console/api/mutes", map[string]any{"scope": "user", "userId": u, "duration": "1h", "reason": "spam spam"}), 403, 4030)
		if len(b.auditRows(`action = 'mute.set' AND phase = 'result' AND result = 'success'`)) < 2 || len(b.auditRows(`action = 'mute.release' AND phase = 'result' AND result = 'success'`)) < 2 {
			t.Error("no audit")
		}
	})

	// AC-ADM-08-1、08-2、08-3、08-4（换会话）、08-6、08-7、AC-CON-07-4。
	t.Run("body", func(t *testing.T) {
		const secret = "ZXQ-BODY-808"
		u := uniq("cu")
		b.users(u)
		g, g2 := b.group(u), b.group(u)
		for i := range 3 {
			sendText(t, b, u, g, fmt.Sprintf("%s-%d", secret, i))
		}
		conv := "group:" + g
		path := "/console/api/messages/grants"
		expect(t, "08-1 support", kf.do("POST", path, grantReq(kf, conv, nil)), 403, 4030)
		calls := len(b.im.find("POST", "/admin/msg-grants"))
		expect(t, "no ticket", mod.do("POST", path, grantReq(mod, conv, map[string]any{"ticket": ""})), 400, 4000)
		expect(t, "bad ticket", mod.do("POST", path, grantReq(mod, conv, map[string]any{"ticket": "a b"})), 400, 4000)
		expect(t, "no reason", mod.do("POST", path, grantReq(mod, conv, map[string]any{"reason": ""})), 400, 4000)
		// AC-CON-07-4：step-up 窗口不算数，每次都要动态码。
		mod.stepUp()
		expect(t, "no otp", mod.do("POST", path, grantReq(mod, conv, map[string]any{"otp": ""})), 403, 4038)
		expect(t, "bad otp", mod.do("POST", path, grantReq(mod, conv, map[string]any{"otp": "000000"})), 401, 4015)
		if n := len(b.im.find("POST", "/admin/msg-grants")); n != calls {
			t.Errorf("rejected requests reached im-server: %d", n-calls)
		}
		// 没有授权：4039。
		expect(t, "no grant", mod.do("POST", "/console/api/messages/body", map[string]any{"convId": conv}), 403, 4039)

		r := mod.do("POST", path, grantReq(mod, conv, nil))
		expect(t, "grant", r, 200, 0)
		if p, _ := r.body["grantPrefix"].(string); len(p) != 8 {
			t.Errorf("grant reply = %s", r.raw)
		}
		if r.body["grantId"] != nil {
			t.Errorf("full grant id sent to the browser: %s", r.raw)
		}
		page := func(extra map[string]any) reply {
			m := map[string]any{"convId": conv, "limit": 1}
			for k, v := range extra {
				m[k] = v
			}
			return mod.do("POST", "/console/api/messages/body", m)
		}
		p1 := page(nil)
		expect(t, "page 1", p1, 200, 0)
		if p1.header.Get("Cache-Control") != "no-store" || !strings.Contains(p1.raw, secret+"-2") {
			t.Errorf("page 1 = %v %s", p1.header.Get("Cache-Control"), p1.raw)
		}
		expect(t, "page 2", page(map[string]any{"beforeSeq": 3}), 200, 0)
		expect(t, "page 3", page(map[string]any{"beforeSeq": 2}), 200, 0)
		// 08-6：审计 1 + 3，全部字段搜不到正文。
		grants := b.auditRows(`action = 'msg.read.grant' AND phase = 'result' AND result = 'success' AND target LIKE '%' || $1 || '%'`, conv)
		pages := b.auditRows(`action = 'msg.read.page' AND phase = 'result' AND result = 'success' AND target LIKE '%' || $1 || '%'`, conv)
		if len(grants) != 1 || len(pages) != 3 {
			t.Errorf("audit: %d grants, %d pages", len(grants), len(pages))
		}
		if len(grants) == 1 && (grants[0]["reason"] != "case review") {
			t.Errorf("grant audit = %v", grants[0])
		}
		if len(b.auditRows(`action = 'msg.read.grant' AND ticket = 'T-100' AND target LIKE '%' || $1 || '%'`, conv)) != 2 {
			t.Error("ticket not in the grant audit")
		}
		for _, row := range append(grants, pages...) {
			if strings.Contains(fmt.Sprint(row), secret) {
				t.Errorf("audit has body text: %v", row)
			}
		}
		if len(pages) == 3 && !strings.Contains(fmt.Sprint(pages), "seqFrom") {
			t.Errorf("page audit has no seq range: %v", pages)
		}
		if strings.Contains(b.logs.String(), secret) {
			t.Error("body text in logs")
		}
		// 08-4：换会话。
		bodyCalls := b.im.count("POST", "/admin/convs/messages/body")
		expect(t, "other conv", mod.do("POST", "/console/api/messages/body", map[string]any{"convId": "group:" + g2}), 403, 4039)
		if b.im.count("POST", "/admin/convs/messages/body") != bodyCalls {
			t.Error("a grant for another conversation reached im-server") // console 自己就要拦住，不只靠 im-server
		}
		// 换浏览器会话：同一账号重新登录，授权不跟过去。
		other := b.client("mod2")
		other.seed = mod.seed
		b.tick()
		expect(t, "login again", other.login(), 200, 0)
		expect(t, "other session", other.do("POST", "/console/api/messages/body", map[string]any{"convId": conv}), 403, 4039)
		// 08-4：im-server 判定过期（[IM 钟]，真实时钟的 im-server 这里用注入）：透传 4039，绑定作废，再读不会再去问 im-server。
		b.im.mu.Lock()
		b.im.inject = func(c imCall) int {
			if c.Path == "/admin/convs/messages/body" {
				return 4039
			}
			return 0
		}
		b.im.mu.Unlock()
		expect(t, "im-server says expired", mod.do("POST", "/console/api/messages/body", map[string]any{"convId": conv}), 403, 4039)
		b.im.mu.Lock()
		b.im.inject = nil
		b.im.mu.Unlock()
		before := b.im.count("POST", "/admin/convs/messages/body")
		expect(t, "binding dropped", mod.do("POST", "/console/api/messages/body", map[string]any{"convId": conv}), 403, 4039)
		if b.im.count("POST", "/admin/convs/messages/body") != before {
			t.Error("asked im-server with a dead grant")
		}
		// 08-7：单聊开关关闭，透传 reason，未产生授权。
		c2c := "c2c:" + u + ":" + u + "z"
		r = mod.do("POST", path, grantReq(mod, c2c, nil))
		expect(t, "c2c", r, 403, 4030)
		if r.body["reason"] != "c2cBodyDisabled" {
			t.Errorf("c2c reason = %s", r.raw)
		}
		expect(t, "c2c no binding", mod.do("POST", "/console/api/messages/body", map[string]any{"convId": c2c}), 403, 4039)
	})

	// AC-ADM-31-1、31-7、32-2、32-5，元数据页的删除标记。
	t.Run("delete", func(t *testing.T) {
		const secret = "ZXQ-DEL-555"
		u := uniq("du")
		b.users(u)
		g := b.group(u)
		id := sendText(t, b, u, g, secret)
		conv := "group:" + g
		live := b.dial(u, "web")
		b.advance(6 * time.Minute) // 前面的 step-up 过了 5 分钟窗口
		expect(t, "no step-up", mod.do("POST", "/console/api/messages/delete", map[string]any{"convId": conv, "msgIds": []string{id}, "reason": "violation"}), 403, 4038)
		mod.stepUp()
		many := make([]string, 51)
		for i := range many {
			many[i] = fmt.Sprintf("m%d", i)
		}
		expect(t, "51", mod.do("POST", "/console/api/messages/delete", map[string]any{"convId": conv, "msgIds": many, "reason": "violation"}), 400, 4131)
		expect(t, "ghost", mod.do("POST", "/console/api/messages/delete", map[string]any{"convId": conv, "msgIds": []string{"ghost"}, "reason": "violation"}), 404, 4044)
		expect(t, "delete", mod.do("POST", "/console/api/messages/delete", map[string]any{"convId": conv, "msgIds": []string{id}, "reason": "violation"}), 200, 0)
		ev := live.wait("msgDeleted")
		if d := ev["data"].(map[string]any); d["convId"] != conv {
			t.Errorf("event = %v", ev)
		}
		rows := b.auditRows(`action = 'msg.delete' AND phase = 'result' AND result = 'success' AND target LIKE '%' || $1 || '%'`, conv)
		intents := b.auditRows(`action = 'msg.delete' AND phase = 'intent' AND target LIKE '%' || $1 || '%'`, conv)
		if len(rows) == 0 || rows[0]["reason"] != "violation" || !strings.Contains(fmt.Sprint(intents), id) {
			t.Errorf("audit: %v %v", rows, intents)
		}
		if strings.Contains(fmt.Sprint(rows, intents), secret) {
			t.Error("audit has body text")
		}
		// 元数据页：删除标记、删除时间、删除人是 im-server 的值。
		meta := mod.do("POST", "/console/api/messages/meta/query", map[string]any{"convId": conv})
		if !strings.Contains(meta.raw, `"deleted":true`) || !strings.Contains(meta.raw, `"deletedBy":"console:admin:`) || !strings.Contains(meta.raw, "deletedAt") {
			t.Errorf("meta = %s", meta.raw)
		}
		// 隔离原文。
		r := mod.do("POST", "/console/api/messages/grants", grantReq(mod, conv, map[string]any{"quarantine": true}))
		expect(t, "quarantine grant", r, 200, 0)
		q := mod.do("POST", "/console/api/messages/body", map[string]any{"convId": conv, "quarantine": true})
		expect(t, "quarantine read", q, 200, 0)
		if !strings.Contains(q.raw, secret) {
			t.Errorf("quarantine = %s", q.raw)
		}
		if len(b.auditRows(`action = 'msg.quarantine.grant' AND phase = 'result' AND result = 'success' AND target LIKE '%' || $1 || '%'`, conv)) != 1 {
			t.Error("no msg.quarantine.grant audit")
		}
		// 普通授权和隔离授权分开：普通的没申请过就是 4039。
		expect(t, "plain without grant", mod.do("POST", "/console/api/messages/body", map[string]any{"convId": conv}), 403, 4039)
		// 32-5：单聊隔离原文同样受开关控制。
		r = mod.do("POST", "/console/api/messages/grants", grantReq(mod, "c2c:a:b", map[string]any{"quarantine": true}))
		expect(t, "c2c quarantine", r, 403, 4030)
		if r.body["reason"] != "c2cBodyDisabled" {
			t.Errorf("reason = %s", r.raw)
		}
		expect(t, "support cannot delete", kf.do("POST", "/console/api/messages/delete", map[string]any{"convId": conv, "msgIds": []string{id}, "reason": "violation"}), 403, 4030)
	})

	// 正文凭证没有配置：明确 503，不退回到主凭证。
	t.Run("not configured", func(t *testing.T) {
		saved := b.a.MsgRead
		b.a.MsgRead = nil
		defer func() { b.a.MsgRead = saved }()
		u := uniq("nc")
		b.users(u)
		g := b.group(u)
		r := mod.do("POST", "/console/api/messages/grants", grantReq(mod, "group:"+g, nil))
		expect(t, "no credential", r, 503, 5030)
	})
}
