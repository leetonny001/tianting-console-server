package e2e

// CS-208：举报证据的授权、读取、文件代理（PRD-chat F-MOD-04 规则 3、4，第 11.6、14.1 节；console-chat 第 25、26 条；P-48 ①⑤）。
// AC-MOD-04-1 的整条流程（CS-207 + CS-208）也在这里。

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

var (
	evidenceFields    = []string{"messages", "note", "undecryptable", "grantPrefix", "expiresAt"}
	evidenceMsgFields = []string{"msgId", "seq", "from", "type", "ts", "body", "recalled", "recalledAt", "recalledBy"}
	evidenceBodyKeys  = []string{"text", "data", "image", "file", "quote", "mentions"}
)

func evidenceOf(u *user, id string) reply {
	u.w.t.Helper()
	return u.do("POST", reportsURL+"/"+id+"/evidence", map[string]any{})
}

// boundGrant 是 console 记的这条举报的完整 grantId（只有一个浏览器会话申请过时）。
func (w *inviteWorld) boundGrant(reportID string) string {
	w.t.Helper()
	var gid string
	if err := w.db.QueryRow(context.Background(), `SELECT grant_id FROM biz.report_grants WHERE report_id = $1`, reportID).Scan(&gid); err != nil || len(gid) <= 8 {
		w.t.Fatalf("report grant binding: %q %v", gid, err)
	}
	return gid
}

// TC-MOD-04-01（AC-MOD-04-1，经 console 的整条流程）+ TC-MOD-03-05（AC-MOD-03-5）+ TC-MOD-03-11（AC-MOD-03-11 的后端部分）：
// 审核员打开群消息举报（report.view）→ 填理由和动态码申请证据授权（report.evidence.grant；缺动态码 4038、理由不合法 4000）→
// 读证据（原文、note、水印用的授权前 8 位，响应只有白名单字段）→ 删除消息（msg.delete，消息被删）→ 结案（report.handle，状态 handled）；
// 审计依次有这 4 条。举报之后被撤回的群消息，证据是举报时的原文；看过之后被撤回再举报的，证据是隔离原文、recalled=true。
// 授权绑定这个浏览器会话和这条举报：别的举报、别的浏览器会话、过期都是 4039，不调用 im-server。
// 证据接口只经 console-msgread；完整的 grantId 不出现在响应、URL、console 审计和日志里；note、正文不进 console 审计、库和日志。
func TestTC_MOD_04_01_ReviewFlow(t *testing.T) {
	const mark0, mark1, mark2, note = "ZXQ-RPT-0", "ZXQ-RPT-1", "ZXQ-RPT-3", "ZXQ-NOTE-G"
	w := newModWorld(t, 300*time.Second)
	super := w.super("adm1")
	mod := super.create("mod1", "moderator")
	kf := super.create("kf1", "support")
	p := uniq("rf")
	u1, u2 := p+"a", p+"b"
	w.users(u1, u2)
	g := w.group(u1, u2)
	conv := "group:" + g
	c1, c2 := w.dial(u1, "web"), w.dial(u2, "web")
	m0 := msgIDOf(t, c1.send(conv, mark0+" body"))
	r0 := c2.reportMsg(conv, m0, "abuse", note)
	// AC-MOD-03-5：举报之后发送者撤回。
	m1 := msgIDOf(t, c1.send(conv, mark1+" body"))
	r1 := c2.reportMsg(conv, m1, "abuse", "")
	c1.recall(conv, m1)
	// AC-MOD-03-11：u2 看过（readSeq ≥ seq）之后被撤回，再从撤回提示行举报。
	ack := c1.send(conv, mark2+" body")
	m2 := msgIDOf(t, ack)
	c2.markRead(conv, seqOf(t, ack))
	c1.recall(conv, m2)
	r2 := c2.reportMsg(conv, m2, "porn", "")

	// 1. 打开举报单。
	expect(t, "view", reportView(mod, r0, ""), 200, 0)
	// 2. 申请证据授权。
	grantURL := reportsURL + "/" + r0 + "/evidence-grant"
	expect(t, "support grant", kf.do("POST", grantURL, map[string]any{"reason": "evidence review", "otp": kf.otp()}), 403, 4030)
	expect(t, "no otp", mod.do("POST", grantURL, map[string]any{"reason": "evidence review"}), 403, 4038)
	expect(t, "bad reason", mod.do("POST", grantURL, map[string]any{"reason": "x", "otp": mod.otp()}), 400, 4000)
	if n := w.im.count("POST", "/admin/report-grants"); n != 0 {
		t.Fatalf("rejected grants reached im-server %d times", n)
	}
	expect(t, "evidence before grant", evidenceOf(mod, r0), 403, 4039)
	if len(w.im.find("POST", "/admin/reports/"+r0+"/evidence")) != 0 {
		t.Fatal("evidence without a grant reached im-server")
	}
	gr := w.evidenceGrant(mod, r0)
	expect(t, "grant", gr, 200, 0)
	keysWithin(t, "grant", gr.body, "grantPrefix", "expiresAt")
	gid := w.boundGrant(r0)
	if gr.str("grantPrefix") != gid[:8] || fnum(gr.body["expiresAt"]) <= time.Now().UnixMilli() || strings.Contains(gr.raw, gid) {
		t.Errorf("grant = %s", gr.raw)
	}
	// 3. 读证据。
	w.im.mu.Lock()
	w.im.rewrite = func(path string, body []byte) []byte {
		if !strings.HasSuffix(path, "/evidence") {
			return body
		}
		return injectFields(body, "messages", map[string]any{"convId": "group:leak", "futureField": 1})
	}
	w.im.mu.Unlock()
	ev := evidenceOf(mod, r0)
	expect(t, "evidence", ev, 200, 0)
	w.im.mu.Lock()
	w.im.rewrite = nil
	w.im.mu.Unlock()
	keysWithin(t, "evidence", ev.body, evidenceFields...)
	if ev.str("note") != note || ev.str("grantPrefix") != gid[:8] || ev.body["undecryptable"] != nil || strings.Contains(ev.raw, gid) || ev.header.Get("Cache-Control") != "no-store" {
		t.Errorf("evidence = %s %v", ev.raw, ev.header)
	}
	msgs := asList(t, "messages", ev.body["messages"])
	if len(msgs) != 1 {
		t.Fatalf("evidence messages = %s", ev.raw)
	}
	em := asMap(t, "evidence message", msgs[0])
	keysWithin(t, "evidence message", em, evidenceMsgFields...)
	keysWithin(t, "evidence body", asMap(t, "body", em["body"]), evidenceBodyKeys...)
	if em["msgId"] != m0 || em["from"] != u1 || asMap(t, "body", em["body"])["text"] != mark0+" body" {
		t.Errorf("evidence message = %v", em)
	}
	// 4. 删除消息（现有接口，step-up）。
	mod.stepUp()
	expect(t, "delete", mod.do("POST", "/console/api/messages/delete", map[string]any{"convId": conv, "msgIds": []string{m0}, "reason": "violates the rules"}), 200, 0)
	if m := metaByID(t, kf.do("POST", "/console/api/messages/meta/query", map[string]any{"convId": conv}))[m0]; m["deleted"] != true {
		t.Errorf("message not deleted: %v", m)
	}
	// 5. 结案。
	expect(t, "resolve", mod.do("POST", reportsURL+"/"+r0+"/resolve", map[string]any{"result": "handled", "reason": "message deleted"}), 200, 0)
	if r := reportView(mod, r0, ""); r.body["state"] != "handled" {
		t.Errorf("state = %s", r.raw)
	}
	// 审计顺序：report.view、report.evidence.grant、msg.delete、report.handle（这个审核员成功的 intent，按 seq）。
	var order []string
	for _, row := range w.auditRows(`phase = 'intent' AND username = 'mod1' AND action IN ('report.view', 'report.evidence.grant', 'msg.delete', 'report.handle')
		AND request_id IN (SELECT request_id FROM audit.records WHERE phase = 'result' AND result = 'success')`) {
		order = append(order, row["action"].(string))
	}
	want := []string{"report.view", "report.evidence.grant", "msg.delete", "report.handle", "report.view"}
	if fmt.Sprint(order) != fmt.Sprint(want) {
		t.Errorf("audit order = %v, want %v", order, want)
	}
	for _, a := range []string{"report.evidence.grant", "report.evidence.view"} {
		rows := w.auditRows(`action = $1 AND phase = 'result' AND result = 'success'`, a)
		if len(rows) != 1 || !strings.Contains(fmt.Sprint(rows[0]["params"]), `"grant":"`+gid[:8]+`"`) || !strings.Contains(fmt.Sprint(rows[0]["target"]), r0) {
			t.Errorf("%s audit = %v", a, rows)
		}
	}
	if rows := w.auditRows(`action = 'report.evidence.grant' AND phase = 'intent'`); len(rows) != 1 || rows[0]["ticket"] != r0 || rows[0]["reason"] != "evidence review" {
		t.Errorf("grant intent = %v", rows) // 工单号自动用举报 ID
	}

	// AC-MOD-03-5：举报之后撤回的，证据是举报时的原文。
	expect(t, "r1 needs its own grant", evidenceOf(mod, r1), 403, 4039)
	expect(t, "grant r1", w.evidenceGrant(mod, r1), 200, 0)
	ev = evidenceOf(mod, r1)
	expect(t, "evidence r1", ev, 200, 0)
	em = asMap(t, "r1", asList(t, "messages", ev.body["messages"])[0])
	if asMap(t, "body", em["body"])["text"] != mark1+" body" {
		t.Errorf("r1 evidence = %s", ev.raw)
	}
	// AC-MOD-03-11：撤回之后举报的，证据是隔离原文、recalled=true。
	expect(t, "grant r2", w.evidenceGrant(mod, r2), 200, 0)
	ev = evidenceOf(mod, r2)
	expect(t, "evidence r2", ev, 200, 0)
	em = asMap(t, "r2", asList(t, "messages", ev.body["messages"])[0])
	if em["recalled"] != true || em["recalledBy"] != u1 || asMap(t, "body", em["body"])["text"] != mark2+" body" {
		t.Errorf("r2 evidence = %s", ev.raw)
	}

	// 授权绑定浏览器会话：同一账号另一个会话没有授权，4039，不调用 im-server。
	other := w.client("mod1")
	other.seed = mod.seed
	w.tick()
	expect(t, "login again", other.login(), 200, 0)
	n := len(w.im.callsWithPrefix("/admin/reports/" + r1 + "/evidence"))
	expect(t, "other session", evidenceOf(other, r1), 403, 4039)
	// console 记的授权过期：4039，不调用 im-server，绑定作废。
	ownerExec(t, w.owner, `UPDATE biz.report_grants SET expires_at = $1 WHERE report_id = $2`, w.now.Add(-time.Second).UnixMilli(), r1)
	expect(t, "expired", evidenceOf(mod, r1), 403, 4039)
	if len(w.im.callsWithPrefix("/admin/reports/"+r1+"/evidence")) != n {
		t.Error("rejected evidence reads reached im-server")
	}
	var left int
	if err := w.db.QueryRow(context.Background(), `SELECT count(*) FROM biz.report_grants WHERE report_id = $1`, r1).Scan(&left); err != nil || left != 0 {
		t.Errorf("expired binding kept: %d %v", left, err)
	}
	// im-server 说授权不对（console 记的换成了别的举报的）：4039 透传，绑定作废。
	ownerExec(t, w.owner, `UPDATE biz.report_grants SET grant_id = (SELECT grant_id FROM biz.report_grants WHERE report_id = $1) WHERE report_id = $2`, r0, r2)
	expect(t, "wrong grant", evidenceOf(mod, r2), 403, 4039)
	if err := w.db.QueryRow(context.Background(), `SELECT count(*) FROM biz.report_grants WHERE report_id = $1`, r2).Scan(&left); err != nil || left != 0 {
		t.Errorf("rejected binding kept: %d %v", left, err)
	}

	// 证据接口只经 console-msgread（AC-MOD-04-4 的 console 一侧）；grantId 只在请求体里。
	for _, c := range append(w.im.callsWithPrefix("/admin/report-grants"), w.im.callsWithPrefix("/admin/reports/"+r0+"/evidence")...) {
		if c.Caller != "console-msgread" {
			t.Errorf("%s %s called as %q", c.Method, c.Path, c.Caller)
		}
	}
	for _, c := range w.im.callsWithPrefix("/admin/reports") {
		if strings.HasSuffix(c.Path, "/evidence") || c.Caller == "console-msgread" {
			continue
		}
		if c.Caller != "console" {
			t.Errorf("%s %s called as %q", c.Method, c.Path, c.Caller)
		}
	}
	if strings.Contains(w.logs.String(), gid) || strings.Contains(fmt.Sprint(w.auditRows(`true`)), gid) {
		t.Error("full grantId in console logs or audit")
	}
	noneContains(t, "console logs, audit and database", w.logs.String()+w.dumpDB(), map[string]string{"note": note, "text0": mark0, "text1": mark1, "text2": mark2})
	noneContains(t, "im-server audit", w.imAuditDump(), map[string]string{"note": note, "text0": mark0})
}

// TC-MOD-04-03（AC-MOD-04-3）+ P-48 ①：IM_C2C_BODY_ACCESS=off 时单聊消息举报、用户举报申请证据授权 403 / 4030 c2cBodyDisabled
// （im-server 原样返回，页面显示"单聊正文查看未开启"），没有绑定；元数据照常可看（填理由）；用户举报的 note 因此也看不到。
func TestTC_MOD_04_03_C2COff(t *testing.T) {
	const mark, note = "ZXQ-RPT-2", "ZXQ-NOTE-U"
	w := newModWorld(t, 150*time.Second)
	mod := w.super("adm1").create("mod1", "moderator")
	p := uniq("ro")
	u1, u2 := p+"a", p+"b"
	w.users(u1, u2)
	c1, c2 := w.dial(u1, "web"), w.dial(u2, "web")
	m := msgIDOf(t, c1.send("c2c:"+u2, mark))
	rm := c2.reportMsg(c2cConv(u1, u2), m, "abuse", "")
	ru := c2.reportUser(u1, "abuse", note)
	r := reportView(mod, rm, "check the reported chat")
	expect(t, "metadata", r, 200, 0)
	if r.body["targetUser"] != u1 || fnum(r.body["targetReportCount"]) != 2 {
		t.Errorf("metadata = %s", r.raw)
	}
	expect(t, "user report metadata", reportView(mod, ru, ""), 200, 0)
	for _, id := range []string{rm, ru} {
		r := w.evidenceGrant(mod, id)
		expect(t, "grant "+id, r, 403, 4030)
		if r.reason() != "c2cBodyDisabled" {
			t.Errorf("grant %s reason = %q", id, r.reason())
		}
		expect(t, "evidence "+id, evidenceOf(mod, id), 403, 4039)
	}
	var n int
	if err := w.db.QueryRow(context.Background(), `SELECT count(*) FROM biz.report_grants`).Scan(&n); err != nil || n != 0 {
		t.Errorf("bindings = %d %v", n, err)
	}
	if rows := w.auditRows(`action = 'report.evidence.grant' AND phase = 'result' AND code = 4030`); len(rows) != 2 {
		t.Errorf("grant audit = %v", rows)
	}
}

// TC-MOD-04-04（AC-MOD-04-4）、TC-MOD-04-09（AC-MOD-04-9）：
// 主凭证 console 直接调 report.evidence 的接口 403 / 4030（console 自己只用 console-msgread）；
// 超管没有应急授权时申请授权、读证据、取证据文件都是 403 / 4030，不调用 im-server；应急授权 moderator 之后可以。
func TestTC_MOD_04_04_09_EvidenceCallers(t *testing.T) {
	w := newModWorld(t, 300*time.Second)
	super := w.super("adm1")
	p := uniq("rs")
	u1, u2 := p+"a", p+"b"
	w.users(u1, u2)
	g := w.group(u1, u2)
	conv := "group:" + g
	c1, c2 := w.dial(u1, "web"), w.dial(u2, "web")
	id := c2.reportMsg(conv, msgIDOf(t, c1.send(conv, "ZXQ-RPT-S")), "spam", "")

	// AC-MOD-04-4：主凭证。
	for _, call := range []struct {
		path string
		body map[string]any
	}{
		{"/admin/report-grants", map[string]any{"reportId": id, "reason": "main credential"}},
		{"/admin/reports/" + id + "/evidence", map[string]any{"grantId": "00000000-0000-0000-0000-000000000000"}},
		{"/admin/files/f_x/fetch", map[string]any{"convId": conv, "msgId": "m_x", "grantId": "00000000-0000-0000-0000-000000000000"}},
	} {
		err := w.sysDo("POST", call.path, call.body, nil)
		if err == nil || !strings.HasPrefix(err.Error(), "4030 ") {
			t.Errorf("main credential %s: %v", call.path, err)
		}
	}

	// AC-MOD-04-9：超管没有应急授权。
	before := w.im.total()
	expect(t, "super grant", w.evidenceGrant(super, id), 403, 4030)
	expect(t, "super evidence", evidenceOf(super, id), 403, 4030)
	expect(t, "super file", super.do("POST", reportsURL+"/"+id+"/files/f_x/fetch", map[string]any{"msgId": "m_x"}), 403, 4030)
	expect(t, "super view", reportView(super, id, ""), 403, 4030)
	if n := w.im.total(); n != before {
		t.Errorf("denied requests reached im-server: %d", n-before)
	}
	// 应急授权（只能给自己，审核角色，F-CON-06 规则 6）之后可以。
	super.stepUp()
	expect(t, "emergency", super.do("POST", "/console/api/me/emergency-grants", map[string]any{"role": "moderator", "minutes": 15, "reason": "urgent report review"}), 200, 0)
	expect(t, "emergency grant", w.evidenceGrant(super, id), 200, 0)
	expect(t, "emergency evidence", evidenceOf(super, id), 200, 0)
}

// TC-MOD-04-12（AC-MOD-04-12 的 console 一侧）+ TC-MOD-04-16（AC-MOD-04-16 经 console）：被举报的群图片、群文件。
// 没有这个浏览器会话对这条举报的授权 403 / 4039，不调用 im-server；有授权 200：
// 图片原图、缩略图都能取，字节一致，im-server 记录的类型在白名单里、文件头也对得上才 inline（固定 Content-Type、nosniff、no-store），
// 页面同源显示；声称是图片、内容对不上（im-server 返回被改）按 application/octet-stream 附件；pdf、html 只有 attachment；
// 后台 CSP 没有放宽（img-src 仍是 'self' data:）。转给 im-server 的请求体带这个会话的举报授权 grantId 和举报所在的会话；
// 举报所在会话第一次取文件时查一次（requestId 带 .conv 后缀），之后不再查。这条举报没有引用的文件 im-server 403 / 4039 透传。
// 审计 report.file.fetch 记 fileId、msgId、variant、授权前 8 位，result 记字节数和是否内联；文件名不进审计、库、日志。
func TestTC_MOD_04_12_16_EvidenceFiles(t *testing.T) {
	const fileName = "ZXQ-FN-2-报价.pdf"
	w := newModWorld(t, 300*time.Second)
	super := w.super("adm1")
	mod := super.create("mod1", "moderator")
	kf := super.create("kf1", "support")
	p := uniq("rx")
	u1, u2 := p+"a", p+"b"
	w.users(u1, u2)
	g := w.group(u1, u2)
	conv := "group:" + g
	c1, c2 := w.dial(u1, "web"), w.dial(u2, "web")
	photo, thumb := pngBytes(80, 60), pngBytes(20, 15)
	imgID := w.upload(w.userToken(u1), "image", "ZXQ-FN-IMG.png", photo, "image/png", thumb)
	imgMsg := msgIDOf(t, c1.sendAttachment(conv, "image", map[string]any{"image": map[string]any{"fileId": imgID}}))
	pdf := append([]byte("%PDF-1.4\n"), make([]byte, 2048)...)
	pdfID := w.upload(w.userToken(u1), "file", fileName, pdf, "application/pdf", nil)
	pdfMsg := msgIDOf(t, c1.sendAttachment(conv, "file", map[string]any{"file": map[string]any{"fileId": pdfID}}))
	rImg := c2.reportMsg(conv, imgMsg, "porn", "")
	rPdf := c2.reportMsg(conv, pdfMsg, "fraud", "")

	imgURL := reportsURL + "/" + rImg + "/files/" + imgID + "/fetch"
	fetches := func(fileID string) int { return w.im.count("POST", "/admin/files/"+fileID+"/fetch") }
	expect(t, "support", kf.do("POST", imgURL, map[string]any{"msgId": imgMsg}), 403, 4030)
	expect(t, "no grant", mod.do("POST", imgURL, map[string]any{"msgId": imgMsg}), 403, 4039)
	if fetches(imgID) != 0 {
		t.Fatal("fetch without a grant reached im-server")
	}
	expect(t, "grant img", w.evidenceGrant(mod, rImg), 200, 0)
	expect(t, "bad variant", mod.do("POST", imgURL, map[string]any{"msgId": imgMsg, "variant": "big"}), 400, 4000)
	gid := w.boundGrant(rImg)

	csp := func(label string, h http.Header) {
		t.Helper()
		v := h.Get("Content-Security-Policy")
		if !strings.Contains(v, "img-src 'self' data:;") || strings.Contains(v, "blob:") || !strings.Contains(v, "default-src 'self'") ||
			!strings.Contains(v, "frame-ancestors 'none'") || strings.Contains(v, "unsafe-inline") {
			t.Errorf("%s CSP = %q", label, v)
		}
	}
	for _, tc := range []struct {
		variant string
		want    []byte
	}{{"", photo}, {"thumb", thumb}} {
		body := map[string]any{"msgId": imgMsg}
		if tc.variant != "" {
			body["variant"] = tc.variant
		}
		r := mod.do("POST", imgURL, body)
		if r.status != 200 || sha256.Sum256([]byte(r.raw)) != sha256.Sum256(tc.want) {
			t.Fatalf("fetch %q: %d %d bytes (want %d) %s", tc.variant, r.status, len(r.raw), len(tc.want), r.raw)
		}
		h := r.header
		if h.Get("Content-Disposition") != "inline" || h.Get("Content-Type") != "image/png" || h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Cache-Control") != "no-store" {
			t.Errorf("fetch %q headers = %v", tc.variant, h)
		}
		csp("image "+tc.variant, h)
	}
	calls := w.im.find("POST", "/admin/files/"+imgID+"/fetch")
	if len(calls) != 2 {
		t.Fatalf("im-server fetch calls = %d", len(calls))
	}
	for _, call := range calls {
		var sent map[string]any
		if err := json.Unmarshal([]byte(call.Body), &sent); err != nil || sent["grantId"] != gid || sent["convId"] != conv || sent["msgId"] != imgMsg || call.Caller != "console-msgread" {
			t.Errorf("im-server fetch = %s as %s", call.Body, call.Caller)
		}
		if strings.Contains(call.Path, gid) {
			t.Errorf("grantId in the URL: %s", call.Path)
		}
	}
	lookups := w.im.find("GET", "/admin/reports/"+rImg)
	if len(lookups) != 1 || !strings.HasSuffix(lookups[0].RequestID, ".conv") || lookups[0].Caller != "console" {
		t.Errorf("conv lookups = %+v", lookups)
	}

	// 声称是图片、内容对不上：附件 + application/octet-stream。
	w.im.mu.Lock()
	w.im.rewrite = func(path string, body []byte) []byte {
		if path == "/admin/files/"+imgID+"/fetch" {
			return []byte("<html><script>alert(1)</script></html>")
		}
		return body
	}
	w.im.mu.Unlock()
	r := mod.do("POST", imgURL, map[string]any{"msgId": imgMsg})
	if r.status != 200 || r.header.Get("Content-Disposition") != "attachment" || r.header.Get("Content-Type") != "application/octet-stream" || r.header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("spoofed image = %d %v", r.status, r.header)
	}

	// pdf：attachment，类型按 im-server 的记录。html（im-server 返回被改成 text/html）：同样只有 attachment。
	pdfURL := reportsURL + "/" + rPdf + "/files/" + pdfID + "/fetch"
	expect(t, "grant pdf", w.evidenceGrant(mod, rPdf), 200, 0)
	w.im.mu.Lock()
	w.im.rewrite = nil
	w.im.mu.Unlock()
	r = mod.do("POST", pdfURL, map[string]any{"msgId": pdfMsg})
	if r.status != 200 || r.raw != string(pdf) || r.header.Get("Content-Disposition") != "attachment" || r.header.Get("Content-Type") != "application/pdf" {
		t.Errorf("pdf = %d %v", r.status, r.header)
	}
	w.im.mu.Lock()
	w.im.rewriteHeader = func(path string, h http.Header) {
		if path == "/admin/files/"+pdfID+"/fetch" {
			h.Set("Content-Type", "text/html; charset=utf-8")
		}
	}
	w.im.rewrite = func(path string, body []byte) []byte {
		if path == "/admin/files/"+pdfID+"/fetch" {
			return []byte("<html><script>alert(1)</script></html>")
		}
		return body
	}
	w.im.mu.Unlock()
	r = mod.do("POST", pdfURL, map[string]any{"msgId": pdfMsg})
	if r.status != 200 || r.header.Get("Content-Disposition") != "attachment" || r.header.Get("Content-Type") != "text/html" || r.header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("html = %d %v", r.status, r.header)
	}
	csp("html", r.header)
	w.im.mu.Lock()
	w.im.rewrite, w.im.rewriteHeader = nil, nil
	w.im.mu.Unlock()
	// 证据里有文件名（凭授权，F-MOD-04 规则 3）。
	ev := evidenceOf(mod, rPdf)
	if f := asMap(t, "file", asMap(t, "body", asMap(t, "msg", asList(t, "messages", ev.body["messages"])[0])["body"])["file"]); f["name"] != fileName || f["fileId"] != pdfID {
		t.Errorf("pdf evidence = %s", ev.raw)
	}
	// 这条举报没有引用的文件：im-server 403 / 4039 透传（绑定不解除，下一次照常）。
	expect(t, "unrelated file", mod.do("POST", reportsURL+"/"+rPdf+"/files/"+imgID+"/fetch", map[string]any{"msgId": imgMsg}), 403, 4039)
	expect(t, "pdf again", mod.do("POST", pdfURL, map[string]any{"msgId": pdfMsg}), 200, 0)
	// 群举报：证据里没有消息、也就没有文件。
	rg := c2.report(map[string]any{"targetType": "group", "groupId": g, "reason": "spam"})
	expect(t, "grant group report", w.evidenceGrant(mod, rg), 200, 0)
	expect(t, "group report file", mod.do("POST", reportsURL+"/"+rg+"/files/"+imgID+"/fetch", map[string]any{"msgId": imgMsg}), 404, 4040)

	rows := w.auditRows(`action = 'report.file.fetch' AND phase = 'result' AND result = 'success'`)
	if len(rows) < 5 {
		t.Fatalf("fetch audit = %v", rows)
	}
	if ps := fmt.Sprint(rows[0]["params"]); !strings.Contains(ps, `"inline":true`) || !strings.Contains(ps, fmt.Sprintf(`"bytes":%d`, len(photo))) {
		t.Errorf("first fetch result = %v", rows[0])
	}
	intents := w.auditRows(`action = 'report.file.fetch' AND phase = 'intent'`)
	if ps := fmt.Sprint(intents[0]["params"]); !strings.Contains(ps, imgID) || !strings.Contains(ps, imgMsg) || !strings.Contains(ps, `"grant":"`+gid[:8]+`"`) || strings.Contains(ps, gid) {
		t.Errorf("fetch intent = %v", intents[0])
	}
	needles := map[string]string{"file name": "ZXQ-FN-2", "image name": "ZXQ-FN-IMG"}
	noneContains(t, "console logs and database", w.logs.String()+w.dumpDB(), needles)
	noneContains(t, "im-server audit", w.imAuditDump(), needles)
}

// TC-MOD-04-13（AC-MOD-04-13 经 console）+ P-48 ①⑤：IM_C2C_BODY_ACCESS=on 时单聊证据只要 report.evidence 的授权流程：
// 单聊图片举报的证据、文件照常；用户举报的 note 能看到。im-server 改成 off 重启后，同一个授权取文件、读证据都是 403 / 4030 c2cBodyDisabled
// （原样透传，绑定不解除）。
func TestTC_MOD_04_13_C2CFileOff(t *testing.T) {
	const note = "ZXQ-NOTE-U2"
	w := newModWorld(t, 150*time.Second, "IM_C2C_BODY_ACCESS=on")
	mod := w.super("adm1").create("mod1", "moderator")
	p := uniq("rt")
	u1, u2 := p+"a", p+"b"
	w.users(u1, u2)
	c1, c2 := w.dial(u1, "web"), w.dial(u2, "web")
	photo := pngBytes(30, 30)
	imgID := w.upload(w.userToken(u1), "image", "c2c.png", photo, "image/png", pngBytes(10, 10))
	imgMsg := msgIDOf(t, c1.sendAttachment("c2c:"+u2, "image", map[string]any{"image": map[string]any{"fileId": imgID}}))
	rm := c2.reportMsg(c2cConv(u1, u2), imgMsg, "porn", "")
	ru := c2.reportUser(u1, "abuse", note)
	expect(t, "view", reportView(mod, rm, "check the reported chat"), 200, 0)
	expect(t, "grant", w.evidenceGrant(mod, rm), 200, 0)
	ev := evidenceOf(mod, rm)
	expect(t, "evidence", ev, 200, 0)
	if img := asMap(t, "image", asMap(t, "body", asMap(t, "msg", asList(t, "messages", ev.body["messages"])[0])["body"])["image"]); img["fileId"] != imgID {
		t.Errorf("c2c evidence = %s", ev.raw)
	}
	fileURL := reportsURL + "/" + rm + "/files/" + imgID + "/fetch"
	r := mod.do("POST", fileURL, map[string]any{"msgId": imgMsg})
	if r.status != 200 || r.raw != string(photo) || r.header.Get("Content-Disposition") != "inline" {
		t.Fatalf("c2c file = %d %v", r.status, r.header)
	}
	// 用户举报的 note 按单聊对待（P-48 ①）：开关开时凭授权能看到。
	expect(t, "grant user report", w.evidenceGrant(mod, ru), 200, 0)
	if ev := evidenceOf(mod, ru); ev.str("note") != note || len(asList(t, "messages", ev.body["messages"])) != 0 {
		t.Errorf("user report evidence = %s", ev.raw)
	}

	w.restartIM("IM_C2C_BODY_ACCESS=off")
	r = mod.do("POST", fileURL, map[string]any{"msgId": imgMsg})
	expect(t, "file off", r, 403, 4030)
	if r.reason() != "c2cBodyDisabled" {
		t.Errorf("file off reason = %q", r.reason())
	}
	for _, id := range []string{rm, ru} {
		r = evidenceOf(mod, id)
		expect(t, "evidence off "+id, r, 403, 4030)
		if r.reason() != "c2cBodyDisabled" {
			t.Errorf("evidence off reason = %q", r.reason())
		}
	}
	var n int
	if err := w.db.QueryRow(context.Background(), `SELECT count(*) FROM biz.report_grants`).Scan(&n); err != nil || n != 2 {
		t.Errorf("bindings after 4030 = %d %v", n, err)
	}
	if rows := w.auditRows(`action = 'report.file.fetch' AND phase = 'result' AND code = 4030`); len(rows) != 1 {
		t.Errorf("fetch audit = %v", rows)
	}
}

// TC-MOD-04-14 前半（AC-MOD-04-14 经 console）：证据密钥不匹配（im-server 换了 IM_REPORT_KEY 重启）时读证据 200、undecryptable=true、
// messages 为空（页面显示"证据无法解密"），审计记 undecryptable；元数据只剩 msgId；照常可以结案。
func TestTC_MOD_04_14_Undecryptable(t *testing.T) {
	w := newModWorld(t, 150*time.Second)
	mod := w.super("adm1").create("mod1", "moderator")
	p := uniq("ru")
	u1, u2 := p+"a", p+"b"
	w.users(u1, u2)
	g := w.group(u1, u2)
	c1, c2 := w.dial(u1, "web"), w.dial(u2, "web")
	m := msgIDOf(t, c1.send("group:"+g, "ZXQ-RPT-K"))
	id := c2.reportMsg("group:"+g, m, "spam", "ZXQ-NOTE-K")
	w.restartIM("IM_REPORT_KEY=" + modReportKey2)
	expect(t, "grant", w.evidenceGrant(mod, id), 200, 0)
	ev := evidenceOf(mod, id)
	expect(t, "evidence", ev, 200, 0)
	keysWithin(t, "evidence", ev.body, evidenceFields...)
	if ev.body["undecryptable"] != true || len(asList(t, "messages", ev.body["messages"])) != 0 || ev.body["note"] != nil {
		t.Errorf("evidence = %s", ev.raw)
	}
	if rows := w.auditRows(`action = 'report.evidence.view' AND phase = 'result' AND result = 'success'`); len(rows) != 1 || !strings.Contains(fmt.Sprint(rows[0]["params"]), `"undecryptable":true`) {
		t.Errorf("evidence audit = %v", rows)
	}
	r := reportView(mod, id, "")
	expect(t, "view", r, 200, 0)
	if mm := asMap(t, "message", asList(t, "messages", r.body["messages"])[0]); len(mm) != 1 || mm["msgId"] != m {
		t.Errorf("metadata without the key = %v", mm)
	}
	expect(t, "resolve", mod.do("POST", reportsURL+"/"+id+"/resolve", map[string]any{"result": "rejected", "reason": "cannot read the evidence"}), 200, 0)
}
