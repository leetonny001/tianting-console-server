package e2e

// CS-204（后台元数据和正文接口配合撤回）、CS-202（审核员经 console 代理查看文件）：PRD-chat F-RCL-04、第 11.6、14.1 节。
// 真实 im-server（IM_MSG_ACTIONS_ENABLED=1、IM_FILES_ENABLED=1、IM_V13_ADMIN_FEATURES=1）+ 假 S3 + 真实 Postgres。

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"tianting/console/internal/apierr"
	"tianting/console/internal/clock"
	"tianting/console/internal/imclient"
)

const rclQuarantineKey = "console-e2e-quarantine-key-0123456789abcdef"

// newRecallWorld：撤回、文件、后台第二批都打开。[C 钟] 从真实时间前 lead 开始（要在登录之前）：
// 隔离授权的到期时间是 im-server 的真实时间，console 取文件时要和自己的时钟比（CS-202），对账也要两边时间对得上。
// lead 抵消建账号、动态码把钟往前推的部分；默认 150 秒（super + 两个 create 共推进 5 个步长）。
func newRecallWorld(t *testing.T, lead ...time.Duration) *inviteWorld {
	t.Helper()
	s3 := newFakeS3(t)
	env := append(s3.env(), "IM_TRUSTED_PROXIES=127.0.0.1/32,::1/128", "IM_MSG_ACTIONS_ENABLED=1", "IM_QUARANTINE_KEY="+rclQuarantineKey)
	p := startIMProc(t, allConsoleScopes, env...)
	w := &inviteWorld{bizWorld: newBizWorldWith(t, p.admin, p.ws, p.key), proc: p}
	d := 150 * time.Second
	if len(lead) > 0 {
		d = lead[0]
	}
	w.realClock(d)
	return w
}

// recall 发 cmd=recall，等 ack（F-RCL-01）。
func (c *wsClient) recall(conv, msgID string) {
	c.t.Helper()
	id := fmt.Sprintf("r%d", time.Now().UnixNano())
	req, _ := json.Marshal(map[string]any{"id": id, "cmd": "recall", "data": map[string]any{"convId": conv, "msgId": msgID}})
	if err := c.ws.Write(context.Background(), websocket.MessageText, req); err != nil {
		c.t.Fatal(err)
	}
	for {
		if f := c.wait("ack"); f["id"] == id {
			if f["error"] != nil {
				c.t.Fatalf("recall: %v", f)
			}
			return
		}
	}
}

func msgIDOf(t *testing.T, ack map[string]any) string {
	t.Helper()
	d, _ := ack["data"].(map[string]any)
	id, _ := d["msgId"].(string)
	if id == "" {
		t.Fatalf("send: %v", ack)
	}
	return id
}

// recalledImage：u1 在群里发一张图片（带缩略图）然后撤回。返回 fileId、msgId、原图、缩略图。
func (w *inviteWorld) recalledImage(c *wsClient, uid, conv, name string) (fileID, msgID string, photo, thumb []byte) {
	w.t.Helper()
	photo, thumb = pngBytes(80, 60), pngBytes(20, 15)
	fileID = w.upload(w.userToken(uid), "image", name, photo, "image/png", thumb)
	msgID = msgIDOf(w.t, c.sendAttachment(conv, "image", map[string]any{"image": map[string]any{"fileId": fileID}}))
	c.recall(conv, msgID)
	return fileID, msgID, photo, thumb
}

func metaByID(t *testing.T, r reply) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	list, _ := r.body["messages"].([]any)
	for _, m := range list {
		mm := m.(map[string]any)
		out[mm["msgId"].(string)] = mm
	}
	return out
}

// TC-RCL-04-07（AC-RCL-04-7，console 一侧）：撤回的文本和文件消息，元数据两层（im-server 响应、console 响应）都有 recalled*，
// 没有 body、文件名、fileSize；console 的元数据结构是白名单，去掉字段时这里失败。
func TestTC_RCL_04_07_MetaRecalled(t *testing.T) {
	const mark = "ZXQ-RCL-META"
	w := newRecallWorld(t)
	super := w.super("adm1")
	kf := super.create("kf1", "support")
	p := uniq("rm")
	u1, u2 := p+"a", p+"b"
	w.users(u1, u2)
	g := w.group(u1, u2)
	conv := "group:" + g
	c := w.dial(u1, "web")
	textID := msgIDOf(t, c.send(conv, mark+"-text"))
	pdf := append([]byte("%PDF-1.4\n"), make([]byte, 2048)...)
	fileID := w.upload(w.userToken(u1), "file", mark+"-合同.pdf", pdf, "application/pdf", nil)
	fileMsg := msgIDOf(t, c.sendAttachment(conv, "file", map[string]any{"file": map[string]any{"fileId": fileID}}))
	keepID := msgIDOf(t, c.send(conv, mark+"-kept"))
	c.recall(conv, textID)
	c.recall(conv, fileMsg)

	before := len(w.im.find("POST", "/admin/convs/messages/query"))
	r := kf.do("POST", "/console/api/messages/meta/query", map[string]any{"convId": conv})
	expect(t, "meta", r, 200, 0)
	if len(w.im.find("POST", "/admin/convs/messages/query")) != before+1 {
		t.Fatal("meta query did not reach im-server")
	}
	if strings.Contains(r.raw, mark) || strings.Contains(r.raw, `"body"`) || strings.Contains(r.raw, fileID) {
		t.Errorf("body or file name in the console meta: %s", r.raw)
	}
	if strings.Contains(w.im.dump(), mark) {
		t.Error("body or file name in the im-server meta response")
	}
	got := metaByID(t, r)
	allowed := map[string]bool{"seq": true, "msgId": true, "from": true, "type": true, "bodyLength": true, "ts": true, "recalled": true, "recalledAt": true, "recalledBy": true}
	for _, id := range []string{textID, fileMsg} {
		m := got[id]
		if m == nil {
			t.Fatalf("%s missing from meta: %s", id, r.raw)
		}
		if m["recalled"] != true || m["recalledBy"] != u1 {
			t.Errorf("%s recalled* = %v", id, m)
		}
		if at, _ := m["recalledAt"].(float64); at <= 0 {
			t.Errorf("%s recalledAt = %v", id, m["recalledAt"])
		}
		if _, has := m["deleted"]; has {
			t.Errorf("%s is shown as deleted: %v", id, m)
		}
		for k := range m {
			if !allowed[k] {
				t.Errorf("%s meta has field %q (%v)", id, k, m)
			}
		}
	}
	if _, has := got[fileMsg]["fileSize"]; has {
		t.Errorf("recalled file has fileSize: %v", got[fileMsg])
	}
	if k := got[keepID]; k == nil || k["recalled"] != nil {
		t.Errorf("kept message = %v", k)
	}
	if strings.Contains(w.logs.String(), mark) {
		t.Error("body or file name in the console logs")
	}
}

// TC-RCL-04-03（AC-RCL-04-3，console 一侧）+ CS-204 第 2 条：普通正文授权读到撤回的消息 deleted=false、recalled=true、没有 body；
// 隔离授权读到原文。quote、mentions 原样透传；引用文字不进元数据、console 审计和日志。
func TestTC_RCL_04_03_BodyRecalled(t *testing.T) {
	const mark, quoted = "ZXQ-RCL-BODY", "ZXQ-RCL-QUOTED"
	w := newRecallWorld(t)
	super := w.super("adm1")
	mod := super.create("mod1", "moderator")
	kf := super.create("kf1", "support")
	p := uniq("rb")
	u1, u2 := p+"a", p+"b"
	w.users(u1, u2)
	g := w.group(u1, u2)
	conv := "group:" + g
	c := w.dial(u1, "web")
	target := msgIDOf(t, c.send(conv, quoted+" original"))
	withQuote := msgIDOf(t, c.sendAttachment(conv, "text", map[string]any{"text": "reply to it", "quote": map[string]any{"msgId": target}, "mentions": map[string]any{"userIds": []string{u2}}}))
	recalled := msgIDOf(t, c.send(conv, mark+" secret"))
	c.recall(conv, recalled)

	grant := func(quarantine bool, ticket string) {
		t.Helper()
		w.tick()
		expect(t, "grant "+ticket, mod.do("POST", "/console/api/messages/grants", map[string]any{"convId": conv, "ticket": ticket, "reason": "recall review", "otp": mod.otp(), "quarantine": quarantine}), 200, 0)
	}
	type msg struct {
		MsgID    string          `json:"msgId"`
		Deleted  *bool           `json:"deleted"`
		Recalled bool            `json:"recalled"`
		RecBy    string          `json:"recalledBy"`
		RecAt    int64           `json:"recalledAt"`
		Body     json.RawMessage `json:"body"`
	}
	read := func(quarantine bool) (map[string]msg, string) {
		t.Helper()
		r := mod.do("POST", "/console/api/messages/body", map[string]any{"convId": conv, "quarantine": quarantine})
		expect(t, fmt.Sprintf("body quarantine=%v", quarantine), r, 200, 0)
		var page struct {
			Messages []msg `json:"messages"`
		}
		if err := json.Unmarshal([]byte(r.raw), &page); err != nil {
			t.Fatal(err)
		}
		out := map[string]msg{}
		for _, m := range page.Messages {
			out[m.MsgID] = m
		}
		return out, r.raw
	}

	// 1. 普通正文授权：撤回的没有 body，recalled=true，deleted=false（后台版序列化，不是"已删除"）。
	grant(false, "T-RCL-1")
	normal, raw := read(false)
	m := normal[recalled]
	if !m.Recalled || m.RecBy != u1 || m.RecAt <= 0 || m.Deleted != nil || len(m.Body) != 0 {
		t.Errorf("recalled in the body page = %+v", m)
	}
	if strings.Contains(raw, mark) {
		t.Errorf("recalled text in the normal body page: %s", raw)
	}
	// quote、mentions 原样透传（引用的组装在 im-server）。
	var qb struct {
		Text  string `json:"text"`
		Quote struct {
			MsgID string `json:"msgId"`
			State string `json:"state"`
			Text  string `json:"text"`
		} `json:"quote"`
		Mentions struct {
			UserIDs []string `json:"userIds"`
		} `json:"mentions"`
	}
	if err := json.Unmarshal(normal[withQuote].Body, &qb); err != nil {
		t.Fatalf("quote body = %s", normal[withQuote].Body)
	}
	if qb.Quote.MsgID != target || !strings.Contains(qb.Quote.Text, quoted) || len(qb.Mentions.UserIDs) != 1 || qb.Mentions.UserIDs[0] != u2 {
		t.Errorf("quote / mentions not passed through: %s", normal[withQuote].Body)
	}

	// 2. 隔离授权：返回撤回的原文，仍然 deleted=false。
	grant(true, "T-RCL-2")
	q, raw := read(true)
	qm, ok := q[recalled]
	if !ok || !qm.Recalled || qm.Deleted != nil || !strings.Contains(string(qm.Body), mark) {
		t.Errorf("quarantine page = %s", raw)
	}

	// 3. 元数据里没有引用文字和原文；console 审计、日志里也没有。
	meta := kf.do("POST", "/console/api/messages/meta/query", map[string]any{"convId": conv})
	expect(t, "meta", meta, 200, 0)
	if strings.Contains(meta.raw, quoted) || strings.Contains(meta.raw, mark) || strings.Contains(meta.raw, `"quote"`) || strings.Contains(meta.raw, `"mentions"`) {
		t.Errorf("quote or body in the meta: %s", meta.raw)
	}
	for _, row := range w.auditRows(`action LIKE 'msg.%'`) {
		if s := fmt.Sprint(row); strings.Contains(s, quoted) || strings.Contains(s, mark) {
			t.Errorf("audit has message text: %v", row)
		}
	}
	if s := w.logs.String(); strings.Contains(s, quoted) || strings.Contains(s, mark) {
		t.Error("message text in the console logs")
	}
}

// TC-RCL-04-01（AC-RCL-04-1，经 console 的一次）+ CS-204 第 3 条：后台删除已撤回的消息 200，元数据仍是撤回、不是删除，
// 不发 msgDeleted；console 两阶段审计和 im-server 审计都有。响应丢失时对账把它记成成功，不是"状态不一致"。
func TestTC_RCL_04_01_DeleteRecalled(t *testing.T) {
	w := newRecallWorld(t)
	super := w.super("adm1")
	mod := super.create("mod1", "moderator")
	kf := super.create("kf1", "support")
	if d := w.now.Sub(time.Now()).Abs(); d > 30*time.Second {
		t.Fatalf("[C clock] is %v away from the real clock", d)
	}
	p := uniq("rd")
	u1, u2 := p+"a", p+"b"
	w.users(u1, u2)
	g := w.group(u1, u2)
	conv := "group:" + g
	c1, c2 := w.dial(u1, "web"), w.dial(u2, "web")
	m1 := msgIDOf(t, c1.send(conv, "to be recalled"))
	m2 := msgIDOf(t, c1.send(conv, "to be recalled too"))
	c1.recall(conv, m1)
	c1.recall(conv, m2)
	c2.wait("msgDeleted") // 撤回自己的事件
	c2.wait("msgDeleted")

	mod.stepUp()
	r := mod.do("POST", "/console/api/messages/delete", map[string]any{"convId": conv, "msgIds": []string{m1}, "reason": "recalled spam"})
	expect(t, "delete recalled", r, 200, 0)
	if d, _ := r.body["deleted"].([]any); len(d) != 0 {
		t.Errorf("delete reply = %s", r.raw) // 幂等：没有新删除的
	}
	// 没有 msgDeleted：哨兵消息先到。
	sentinel := msgIDOf(t, c1.send(conv, "sentinel"))
	for {
		f := c2.wait2()
		if f["cmd"] == "msg" {
			if d, _ := f["data"].(map[string]any); d["msgId"] != sentinel {
				continue
			}
			break
		}
		if d, _ := f["data"].(map[string]any); f["cmd"] == "event" && d["type"] == "msgDeleted" {
			t.Fatalf("unexpected msgDeleted after deleting a recalled message: %v", f)
		}
	}
	meta := metaByID(t, kf.do("POST", "/console/api/messages/meta/query", map[string]any{"convId": conv}))
	if m := meta[m1]; m["recalled"] != true || m["deleted"] != nil {
		t.Errorf("meta after delete = %v", m)
	}
	rows := w.auditRows(`action = 'msg.delete' AND target LIKE '%' || $1 || '%'`, conv)
	if len(rows) != 2 || rows[0]["phase"] != "intent" || rows[1]["phase"] != "result" || rows[1]["result"] != "success" {
		t.Fatalf("console audit = %v", rows)
	}
	if a := w.imAuditDump(); !strings.Contains(a, rows[0]["request_id"].(string)) {
		t.Error("no im-server audit for the delete")
	}

	// 响应丢了：504 / 5040、result unknown；对账查到 im-server 的成功记录，补 success。
	var drop atomic.Bool
	drop.Store(true)
	dropping, err := imclient.New(imclient.Config{BaseURL: w.im.srv.URL, Caller: "console", Key: w.key, Clock: clock.New(), DropResponse: &drop})
	if err != nil {
		t.Fatal(err)
	}
	normal := w.a.IM
	w.a.IM = dropping
	mod.stepUp()
	lost := mod.do("POST", "/console/api/messages/delete", map[string]any{"convId": conv, "msgIds": []string{m2}, "reason": "recalled spam"})
	w.a.IM = normal
	expect(t, "response lost", lost, 504, 5040)
	unknown := w.auditRows(`action = 'msg.delete' AND phase = 'result' AND result = 'unknown'`)
	if len(unknown) != 1 {
		t.Fatalf("unknown = %v", unknown)
	}
	w.advance(6 * time.Minute)
	if err := w.a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := w.auditRows(`request_id = $1 AND phase = 'result' AND params LIKE '%"reconciled"%'`, unknown[0]["request_id"])
	if len(got) != 1 || got[0]["result"] != "success" || !strings.Contains(got[0]["params"].(string), `"reconciled":true`) {
		t.Errorf("reconciled = %v", got)
	}
	if m := metaByID(t, kf.do("POST", "/console/api/messages/meta/query", map[string]any{"convId": conv}))[m2]; m["recalled"] != true || m["deleted"] != nil {
		t.Errorf("meta after the lost delete = %v", m)
	}
}

// wait2 等下一帧（任何 cmd）。
func (c *wsClient) wait2() map[string]any {
	c.t.Helper()
	select {
	case f, ok := <-c.in:
		if !ok {
			c.t.Fatal("connection closed")
		}
		return f
	case <-time.After(5 * time.Second):
		c.t.Fatal("no frame")
	}
	return nil
}

// TC-RCL-04-09 第 2 步（AC-RCL-04-9，console 一侧，CS-202）：经 console 代理取撤回的图片。
// 没有权限点 403 / 4030；没有这个会话的隔离授权（没申请、只有普通授权、换了浏览器会话、过期）403 / 4039，都不调用 im-server；
// 有授权 200，字节和原图、缩略图一致，固定 attachment、nosniff、no-store，CSP 不放宽；console 审计有 fileId、msgId、授权前 8 位，
// 两边审计、console 库、日志、URL 都没有文件名；普通调用方直接调 im-server 403 / 4030。
// grantId（PRD-chat v1.6 第 11.6 节，P-44 ④）：转给 im-server 的请求体带这个浏览器会话的 grantId，URL、日志、console 审计里没有完整的 grantId；
// console 记的 grantId 换成别的（im-server 那边同一操作人仍有有效隔离授权）时 im-server 403 / 4039，绑定作废。
func TestTC_RCL_04_09_FetchViaConsole(t *testing.T) {
	const mark = "ZXQ-RCL-FETCH"
	w := newRecallWorld(t)
	super := w.super("adm1")
	mod := super.create("mod1", "moderator")
	kf := super.create("kf1", "support")
	p := uniq("rf")
	u1, u2 := p+"a", p+"b"
	w.users(u1, u2)
	g := w.group(u1, u2)
	conv := "group:" + g
	c := w.dial(u1, "web")
	name := mark + "-证件照.png"
	fileID, msgID, photo, thumb := w.recalledImage(c, u1, conv, name)
	keepID := w.upload(w.userToken(u1), "image", mark+"-kept.png", pngBytes(8, 8), "image/png", pngBytes(4, 4))
	keepMsg := msgIDOf(t, c.sendAttachment(conv, "image", map[string]any{"image": map[string]any{"fileId": keepID}}))

	path := "/console/api/files/" + fileID + "/fetch"
	req := map[string]any{"convId": conv, "msgId": msgID}
	fetches := func() int { return w.im.count("POST", "/admin/files/"+fileID+"/fetch") }
	grant := func(u *user, quarantine bool) reply {
		t.Helper()
		w.tick()
		return u.do("POST", "/console/api/messages/grants", map[string]any{"convId": conv, "ticket": "T-FETCH", "reason": "evidence review", "otp": u.otp(), "quarantine": quarantine})
	}

	// 1. 没有权限点：console 拦（4030），不调用 im-server。
	expect(t, "support", kf.do("POST", path, req), 403, 4030)
	// 2. 没有授权、只有普通正文授权：4039，不调用 im-server。
	expect(t, "no grant", mod.do("POST", path, req), 403, 4039)
	expect(t, "normal grant", grant(mod, false), 200, 0)
	expect(t, "normal grant only", mod.do("POST", path, req), 403, 4039)
	if fetches() != 0 {
		t.Fatalf("rejected fetches reached im-server: %d", fetches())
	}
	// 参数校验在 console。
	expect(t, "bad variant", mod.do("POST", path, map[string]any{"convId": conv, "msgId": msgID, "variant": "big"}), 400, 4000)
	expect(t, "room", mod.do("POST", path, map[string]any{"convId": "room:" + g, "msgId": msgID}), 400, 4007)

	// 3. 隔离授权：原图、缩略图。
	expect(t, "quarantine grant", grant(mod, true), 200, 0)
	for _, tc := range []struct {
		variant string
		want    []byte
	}{{"", photo}, {"thumb", thumb}} {
		body := map[string]any{"convId": conv, "msgId": msgID}
		if tc.variant != "" {
			body["variant"] = tc.variant
		}
		r := mod.do("POST", path, body)
		if r.status != 200 || sha256.Sum256([]byte(r.raw)) != sha256.Sum256(tc.want) {
			t.Fatalf("fetch %q: %d, %d bytes (want %d)", tc.variant, r.status, len(r.raw), len(tc.want))
		}
		h := r.header
		if h.Get("Content-Disposition") != "attachment" || h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Cache-Control") != "no-store" {
			t.Errorf("fetch %q headers = %v", tc.variant, h)
		}
		if ct := h.Get("Content-Type"); ct != "image/png" {
			t.Errorf("fetch %q Content-Type = %q", tc.variant, ct)
		}
		if csp := h.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "unsafe-inline") {
			t.Errorf("fetch %q CSP = %q", tc.variant, csp)
		}
	}
	if fetches() != 2 {
		t.Errorf("im-server fetch calls = %d", fetches())
	}
	var gid string
	if err := w.db.QueryRow(context.Background(), `SELECT grant_id FROM biz.msg_grants WHERE conv_id = $1 AND quarantine`, conv).Scan(&gid); err != nil || len(gid) <= 8 {
		t.Fatalf("quarantine binding: %q %v", gid, err)
	}
	for _, call := range w.im.find("POST", "/admin/files/"+fileID+"/fetch") {
		var sent map[string]any
		if err := json.Unmarshal([]byte(call.Body), &sent); err != nil || sent["grantId"] != gid {
			t.Errorf("im-server fetch body = %s (want grantId %s)", call.Body, gid)
		}
		if strings.Contains(call.Path, gid) {
			t.Errorf("grantId in the im-server URL: %s", call.Path)
		}
	}
	// 没有撤回的文件：im-server 404 / 4048 透传。
	expect(t, "not recalled", mod.do("POST", "/console/api/files/"+keepID+"/fetch", map[string]any{"convId": conv, "msgId": keepMsg}), 404, 4048)
	// fileId 不属于 msgId：404 / 4048。
	expect(t, "wrong msg", mod.do("POST", path, map[string]any{"convId": conv, "msgId": keepMsg}), 404, 4048)

	// 4. 授权绑定浏览器会话：同一账号另一个会话没有授权（im-server 那边按操作人查得到，console 自己要拦）。
	other := w.client("mod1")
	other.seed = mod.seed
	w.tick()
	expect(t, "login again", other.login(), 200, 0)
	n := fetches()
	expect(t, "other session", other.do("POST", path, req), 403, 4039)
	// console 记的授权过期：4039，不调用 im-server，绑定作废。
	ownerExec(t, w.owner, `UPDATE biz.msg_grants SET expires_at = $1 WHERE conv_id = $2 AND quarantine`, w.now.Add(-time.Second).UnixMilli(), conv)
	expect(t, "expired", mod.do("POST", path, req), 403, 4039)
	if fetches() != n {
		t.Errorf("fetch without a live grant reached im-server: %d", fetches()-n)
	}
	var left int
	if err := w.db.QueryRow(context.Background(), `SELECT count(*) FROM biz.msg_grants WHERE conv_id = $1 AND quarantine`, conv).Scan(&left); err != nil || left != 0 {
		t.Errorf("expired binding kept: %d %v", left, err)
	}

	// 5. 审计：intent + result；fileId、msgId、授权前 8 位；没有文件名。
	rows := w.auditRows(`action = 'msg.file.fetch' AND phase = 'result' AND result = 'success'`)
	if len(rows) != 2 {
		t.Fatalf("fetch audit = %v", rows)
	}
	intent := w.auditRows(`action = 'msg.file.fetch' AND phase = 'intent' AND request_id = $1`, rows[0]["request_id"])
	if len(intent) != 1 {
		t.Fatalf("intent = %v", intent)
	}
	ip := intent[0]["params"].(string)
	if !strings.Contains(ip, fileID) || !strings.Contains(ip, msgID) || !strings.Contains(ip, `"grant":"`) || !strings.Contains(intent[0]["target"].(string), conv) {
		t.Errorf("intent params = %s target = %v", ip, intent[0]["target"])
	}
	if !strings.Contains(rows[0]["params"].(string), fmt.Sprintf(`"bytes":%d`, len(photo))) {
		t.Errorf("result params = %v", rows[0]["params"])
	}
	if strings.Contains(fmt.Sprint(w.auditRows(`action LIKE 'msg.%'`)), mark) {
		t.Error("file name in the console audit")
	}
	if strings.Contains(w.dumpDB(), mark) {
		t.Error("file name in the console database")
	}
	if a := w.imAuditDump(); strings.Contains(a, mark) {
		t.Error("file name in the im-server audit")
	} else if !strings.Contains(a, "/fetch") {
		t.Error("im-server audit has no fetch")
	}
	if strings.Contains(w.logs.String(), mark) || strings.Contains(w.proc.logs.String(), mark) {
		t.Error("file name in the logs")
	}
	for _, call := range w.im.find("POST", "/admin/files/"+fileID+"/fetch") {
		if strings.Contains(call.Body, mark) || strings.Contains(call.Path, mark) {
			t.Errorf("file name in the im-server request: %v", call)
		}
	}

	// 6. 普通调用方（主凭证 console，没有 msg.quarantine）直接调 im-server：403 / 4030。
	err := w.sys.Do(context.Background(), imclient.Call{Operator: "admin:test", RequestID: uniq("fx")}, "POST", "/admin/files/"+fileID+"/fetch", nil, req, nil)
	var ae *apierr.Error
	if !errors.As(err, &ae) || ae.Code != apierr.Forbidden {
		t.Errorf("main credential fetch = %v", err)
	}

	// 7. intent 写不进去：503 / 5031，不调用 im-server。
	expect(t, "regrant", grant(mod, true), 200, 0)
	n = fetches()
	w.a.SetAuditFault("fail")
	expect(t, "audit down", mod.do("POST", path, req), 503, 5031)
	w.a.SetAuditFault("ok")
	if fetches() != n {
		t.Error("fetch ran without an intent")
	}
	if r := mod.do("POST", path, req); r.status != http.StatusOK {
		t.Errorf("fetch after audit recovered = %d", r.status)
	}

	// 8. im-server 按 grantId 校验（v1.6）：console 记的 grantId 换成一个不存在的，im-server 那边 mod1 对这个会话仍有有效隔离授权，
	// 按会话查会放行；带 grantId 必须 403 / 4039。请求到了 im-server，绑定作废。
	var regrant string
	if err := w.db.QueryRow(context.Background(), `SELECT grant_id FROM biz.msg_grants WHERE conv_id = $1 AND quarantine`, conv).Scan(&regrant); err != nil {
		t.Fatal(err)
	}
	bogus := "0193a7c4-0000-7000-8000-00000000beef"
	ownerExec(t, w.owner, `UPDATE biz.msg_grants SET grant_id = $1 WHERE conv_id = $2 AND quarantine`, bogus, conv)
	n = fetches()
	expect(t, "wrong grantId", mod.do("POST", path, req), 403, 4039)
	if fetches() != n+1 {
		t.Errorf("wrong grantId did not reach im-server: %d", fetches()-n)
	}
	if calls := w.im.find("POST", "/admin/files/"+fileID+"/fetch"); !strings.Contains(calls[len(calls)-1].Body, bogus) {
		t.Errorf("last im-server fetch body = %s", calls[len(calls)-1].Body)
	}
	if err := w.db.QueryRow(context.Background(), `SELECT count(*) FROM biz.msg_grants WHERE conv_id = $1 AND quarantine`, conv).Scan(&left); err != nil || left != 0 {
		t.Errorf("binding kept after im-server 4039: %d %v", left, err)
	}
	// 完整的 grantId 不进日志和 console 审计（审计只有前 8 位）。
	for _, id := range []string{gid, regrant} {
		if strings.Contains(w.logs.String(), id) || strings.Contains(w.proc.logs.String(), id) {
			t.Errorf("grantId %s in the logs", id[:8])
		}
		if strings.Contains(fmt.Sprint(w.auditRows(`action = 'msg.file.fetch'`)), id) {
			t.Errorf("full grantId %s in the console fetch audit", id[:8])
		}
	}
}
