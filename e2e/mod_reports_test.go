package e2e

// CS-207：举报队列、详情、结案（PRD-chat F-MOD-04 规则 1、2、5，PRD-admin 5.2、5.3 节；console-chat 第 20、22 条的白名单做法）。

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

const reportsURL = "/console/api/reports"

var (
	reportItemFields   = []string{"targetKey", "targetType", "convType", "convId", "msgIds", "userId", "groupId", "count", "latestAt", "reports"}
	reportBriefFields  = []string{"reportId", "reason", "state", "createdAt"}
	reportDetailFields = []string{"reportId", "targetType", "convType", "convId", "msgIds", "userId", "groupId", "reporter", "targetUser", "targetReportCount",
		"reason", "state", "createdAt", "messages", "handledBy", "handledAt", "conclusion"}
	reportMsgFields = []string{"msgId", "seq", "from", "type", "bodyLength", "fileSize"}
)

func reportView(u *user, id string, reason string) reply {
	u.w.t.Helper()
	body := map[string]any{}
	if reason != "" {
		body["reason"] = reason
	}
	return u.do("POST", reportsURL+"/"+id+"/view", body)
}

// nextNonPong 等下一帧（pong 除外）。
func (c *wsClient) nextNonPong() map[string]any {
	c.t.Helper()
	for {
		f := c.wait2()
		if f["cmd"] != "pong" {
			return f
		}
	}
}

// waitText 等到一条正文是 text 的 msg 帧。
func (c *wsClient) waitText(text string) {
	c.t.Helper()
	for {
		f := c.wait2()
		if d, ok := f["data"].(map[string]any); ok && f["cmd"] == "msg" {
			if b, ok := d["body"].(map[string]any); ok && b["text"] == text {
				return
			}
		}
	}
}

// TC-MOD-03-01（AC-MOD-03-1 经 console）+ AC-MOD-04-6 的后端部分：u2 举报 u1 的群消息（abuse）后，审核员经 console 的队列看到它；
// u1 收不到任何帧（哨兵法：举报之后 u1 收到的下一帧就是哨兵）。3 人举报同一用户聚合成 1 项、count=3、点开看到每条。
// 单聊消息举报只有 convType，没有 convId、msgIds（即使 im-server 多给也不透传）。响应只有白名单字段：没有举报人、note 和正文。
// 筛选、翻页参数照转；limit 只接受 20 / 50 / 100。
func TestTC_MOD_03_01_QueueViaConsole(t *testing.T) {
	const mark, note = "ZXQ-RPT-Q", "ZXQ-NOTE-Q"
	w := newModWorld(t, 150*time.Second)
	mod := w.super("adm1").create("mod1", "moderator")
	p := uniq("rq")
	u1, u2, u3, u4 := p+"a", p+"b", p+"c", p+"d"
	w.users(u1, u2, u3, u4)
	g := w.group(u1, u2, u3, u4)
	conv := "group:" + g
	c1, c2, c3, c4 := w.dial(u1, "web"), w.dial(u2, "web"), w.dial(u3, "web"), w.dial(u4, "web")
	m := msgIDOf(t, c1.send(conv, mark+" hello"))
	c3.send(conv, "pre-sentinel")
	c1.waitText("pre-sentinel") // u1 之前的帧都收完了
	// 举报，然后 u3 发哨兵：u1 下一帧就是哨兵（被举报人收不到任何通知，F-MOD-03 规则 7）。
	rm := c2.reportMsg(conv, m, "abuse", note)
	time.Sleep(300 * time.Millisecond)
	c3.send(conv, "sentinel-1")
	if f := c1.nextNonPong(); f["cmd"] != "msg" || asMap(t, "sentinel", asMap(t, "data", f["data"])["body"])["text"] != "sentinel-1" {
		t.Errorf("u1 got a frame before the sentinel: %v", f)
	}
	// 3 人举报 u1（用户举报，都和 u1 在同一个群）。
	ru := []string{c2.reportUser(u1, "spam", ""), c3.reportUser(u1, "spam", ""), c4.reportUser(u1, "fraud", "")}
	// 单聊消息举报。
	cm := msgIDOf(t, c1.send("c2c:"+u2, mark+" c2c"))
	c2.reportMsg(c2cConv(u1, u2), cm, "porn", "")

	// im-server 多返回的字段（举报人、note、单聊的 convId）不透传。
	w.im.mu.Lock()
	w.im.rewrite = func(path string, body []byte) []byte {
		if path != "/admin/reports" {
			return body
		}
		var page map[string]any
		if json.Unmarshal(body, &page) != nil {
			return body
		}
		page["futureField"] = 1
		for _, it := range page["items"].([]any) {
			item := it.(map[string]any)
			item["reporter"], item["note"], item["futureField"] = u2, "ZXQ-LEAK", 1
			if item["convType"] == "c2c" {
				item["convId"], item["msgIds"] = c2cConv(u1, u2), []string{cm}
			}
		}
		out, _ := json.Marshal(page)
		return out
	}
	w.im.mu.Unlock()
	r := mod.do("GET", reportsURL+"?state=pending&limit=20", nil)
	expect(t, "queue", r, 200, 0)
	keysWithin(t, "queue", r.body, "items", "nextCursor")
	byType := map[string]map[string]any{}
	for _, it := range asList(t, "items", r.body["items"]) {
		item := asMap(t, "item", it)
		keysWithin(t, "item", item, reportItemFields...)
		key := fmt.Sprint(item["targetType"], "/", item["convType"])
		byType[key] = item
		for _, b := range asList(t, "reports", item["reports"]) {
			keysWithin(t, "brief", asMap(t, "brief", b), reportBriefFields...)
		}
	}
	msgItem, userItem, c2cItem := byType["message/group"], byType["user/<nil>"], byType["message/c2c"]
	if msgItem == nil || userItem == nil || c2cItem == nil {
		t.Fatalf("queue = %s", r.raw)
	}
	if msgItem["convId"] != "group:"+g || fmt.Sprint(msgItem["msgIds"]) != fmt.Sprint([]any{m}) || fnum(msgItem["count"]) != 1 {
		t.Errorf("message item = %v", msgItem)
	}
	if b := asMap(t, "brief", asList(t, "reports", msgItem["reports"])[0]); b["reportId"] != rm || b["reason"] != "abuse" || b["state"] != "pending" {
		t.Errorf("message brief = %v", b)
	}
	if userItem["userId"] != u1 || fnum(userItem["count"]) != 3 || len(asList(t, "reports", userItem["reports"])) != 3 {
		t.Errorf("user item = %v", userItem)
	}
	for _, id := range ru {
		if !strings.Contains(fmt.Sprint(userItem["reports"]), id) {
			t.Errorf("user item misses %s", id)
		}
	}
	if _, has := c2cItem["convId"]; has {
		t.Errorf("c2c item has convId: %v", c2cItem)
	}
	if _, has := c2cItem["msgIds"]; has {
		t.Errorf("c2c item has msgIds: %v", c2cItem)
	}
	for _, leak := range []string{mark, note, "ZXQ-LEAK", `"` + u2 + `"`, `"` + u3 + `"`} {
		if strings.Contains(r.raw, leak) {
			t.Errorf("queue contains %s: %s", leak, r.raw)
		}
	}
	w.im.mu.Lock()
	w.im.rewrite = nil
	w.im.mu.Unlock()

	// 筛选照转。
	r = mod.do("GET", reportsURL+"?reason=abuse&targetType=message", nil)
	if l := asList(t, "items", r.body["items"]); len(l) != 1 || asMap(t, "item", l[0])["convId"] != conv {
		t.Errorf("abuse filter = %s", r.raw)
	}
	r = mod.do("GET", fmt.Sprintf("%s?from=%d", reportsURL, time.Now().Add(time.Hour).UnixMilli()), nil)
	if l := asList(t, "items", r.body["items"]); len(l) != 0 {
		t.Errorf("future filter = %s", r.raw)
	}
	expect(t, "bad limit", mod.do("GET", reportsURL+"?limit=7", nil), 400, 4000)
	expect(t, "bad state", mod.do("GET", reportsURL+"?state=closed", nil), 400, 4000) // im-server 的 4000 透传
	// 翻页：每页 20 时只有 3 项，nextCursor 为空。
	if r = mod.do("GET", reportsURL+"?limit=20", nil); r.body["nextCursor"] != "" {
		t.Errorf("nextCursor = %v", r.body["nextCursor"])
	}
	_ = c4
}

func c2cConv(a, b string) string {
	if a > b {
		a, b = b, a
	}
	return "c2c:" + a + ":" + b
}

// TC-MOD-04-02（AC-MOD-04-2）：support、operator 读队列、看举报单、结案都是 403 / 4030，超管默认也没有；都不调用 im-server。
func TestTC_MOD_04_02_ReportRoles(t *testing.T) {
	w := newModWorld(t, 150*time.Second)
	super := w.super("adm1")
	kf := super.create("kf1", "support")
	op := super.create("op1", "operator")
	p := uniq("rr")
	u1, u2 := p+"a", p+"b"
	w.users(u1, u2)
	g := w.group(u1, u2)
	c1, c2 := w.dial(u1, "web"), w.dial(u2, "web")
	id := c2.reportMsg("group:"+g, msgIDOf(t, c1.send("group:"+g, "x")), "spam", "")
	for name, u := range map[string]*user{"support": kf, "operator": op, "super_admin": super} {
		expect(t, name+" queue", u.do("GET", reportsURL, nil), 403, 4030)
		expect(t, name+" view", reportView(u, id, ""), 403, 4030)
		expect(t, name+" resolve", u.do("POST", reportsURL+"/"+id+"/resolve", map[string]any{"result": "handled", "reason": "not allowed"}), 403, 4030)
	}
	if calls := w.im.callsWithPrefix("/admin/reports"); len(calls) != 0 {
		t.Errorf("denied requests reached im-server: %v", calls)
	}
}

// TC-MOD-04-10（AC-MOD-04-10）、TC-MOD-04-11（AC-MOD-04-11）经 console：
// 单聊消息举报不填理由看元数据 400 / 4000，响应里没有任何元数据；填了理由 200，只有白名单字段，没有 note 和正文；
// 配额每天 50 个，和单聊元数据查询合并（同一个单聊会话只算一次，两边互相算）：第 51 个 429 / 4292，没有数据。
// 群里的文件消息被举报：客服的 msg.meta 两层响应、审核员看举报单的两层响应都搜不到文件名，只有类型和大小。
func TestTC_MOD_04_10_11_ReportMeta(t *testing.T) {
	const mark, note, fileName = "ZXQ-RPT-C", "ZXQ-NOTE-C", "ZXQ-FN-1-合同.pdf"
	w := newModWorld(t, 150*time.Second)
	super := w.super("adm1")
	mod := super.create("mod1", "moderator")
	kf := super.create("kf1", "support")
	p := uniq("rc")
	u1, u2, u3, u4 := p+"a", p+"b", p+"c", p+"d"
	w.users(u1, u2, u3, u4)
	c1, c2, c3, c4 := w.dial(u1, "web"), w.dial(u2, "web"), w.dial(u3, "web"), w.dial(u4, "web")
	m1 := msgIDOf(t, c1.send("c2c:"+u2, mark+" one"))
	r1 := c2.reportMsg(c2cConv(u1, u2), m1, "abuse", note)
	m2 := msgIDOf(t, c3.send("c2c:"+u2, mark+" two"))
	r2 := c2.reportMsg(c2cConv(u2, u3), m2, "abuse", "")
	m3 := msgIDOf(t, c4.send("c2c:"+u2, mark+" three"))
	r3 := c2.reportMsg(c2cConv(u2, u4), m3, "spam", "")

	// 不填理由：400 / 4000，没有元数据；审计有这次打开（失败）。
	r := reportView(mod, r1, "")
	expect(t, "no reason", r, 400, 4000)
	keysWithin(t, "no reason", r.body, "code", "msg", "reason")
	expect(t, "short reason", reportView(mod, r1, "abc"), 400, 4000)
	if rows := w.auditRows(`action = 'report.view' AND phase = 'result' AND code = 4000`); len(rows) != 1 {
		t.Errorf("failed view audit = %v", rows)
	}
	// 填了理由：200。im-server 以后多返回的字段（note、文件名、未知字段）不透传。
	w.im.mu.Lock()
	w.im.rewrite = func(path string, body []byte) []byte {
		if !strings.HasPrefix(path, "/admin/reports/") {
			return body
		}
		return injectFields(body, "messages", map[string]any{"note": "ZXQ-LEAK", "name": "ZXQ-LEAK.pdf", "futureField": 1})
	}
	w.im.mu.Unlock()
	r = reportView(mod, r1, "check the reported chat")
	w.im.mu.Lock()
	w.im.rewrite = nil
	w.im.mu.Unlock()
	if strings.Contains(r.raw, "ZXQ-LEAK") {
		t.Errorf("injected fields passed through: %s", r.raw)
	}
	expect(t, "view", r, 200, 0)
	keysWithin(t, "detail", r.body, reportDetailFields...)
	if r.body["convType"] != "c2c" || r.body["convId"] != c2cConv(u1, u2) || r.body["reporter"] != u2 || r.body["targetUser"] != u1 ||
		r.body["reason"] != "abuse" || r.body["state"] != "pending" || fnum(r.body["targetReportCount"]) != 1 || r.body["reportId"] != r1 {
		t.Errorf("detail = %s", r.raw)
	}
	msgs := asList(t, "messages", r.body["messages"])
	if len(msgs) != 1 {
		t.Fatalf("messages = %s", r.raw)
	}
	mm := asMap(t, "message", msgs[0])
	keysWithin(t, "message", mm, reportMsgFields...)
	if mm["msgId"] != m1 || mm["type"] != "text" || mm["from"] != u1 || fnum(mm["bodyLength"]) != int64(len(mark+" one")) {
		t.Errorf("message meta = %v", mm)
	}
	for _, leak := range []string{mark, note} {
		if strings.Contains(r.raw, leak) || strings.Contains(w.im.dump(), leak) {
			t.Errorf("%s in the report detail", leak)
		}
	}
	if rows := w.auditRows(`action = 'report.view' AND phase = 'intent' AND reason = 'check the reported chat'`); len(rows) != 1 || !strings.Contains(fmt.Sprint(rows[0]["target"]), r1) {
		t.Errorf("view intent = %v", rows)
	}

	// 配额：r1 的会话已算 1 个。再查 48 个不同的单聊元数据（会话不存在也算），共 49；看 r2 是第 50 个。
	for i := range 48 {
		expect(t, "meta", mod.do("POST", "/console/api/messages/meta/query", map[string]any{"convId": fmt.Sprintf("c2c:qa%d%s:qb%d%s", i, p, i, p), "reason": "quota filling"}), 200, 0)
	}
	expect(t, "50th", reportView(mod, r2, "check the reported chat"), 200, 0)
	// 第 51 个：举报单 429 / 4292，没有数据；单聊元数据也 429（合并）。
	r = reportView(mod, r3, "check the reported chat")
	expect(t, "51st report", r, 429, 4292)
	if strings.Contains(r.raw, u4) || strings.Contains(r.raw, m3) {
		t.Errorf("data in a rejected view: %s", r.raw)
	}
	expect(t, "51st meta", mod.do("POST", "/console/api/messages/meta/query", map[string]any{"convId": "c2c:zz1" + p + ":zz2" + p, "reason": "quota filling"}), 429, 4292)
	// 已经算过的不再算：r1 再看一次、r1 的会话查元数据都照常。
	expect(t, "r1 again", reportView(mod, r1, "check the reported chat"), 200, 0)
	expect(t, "meta of r1's chat", mod.do("POST", "/console/api/messages/meta/query", map[string]any{"convId": c2cConv(u1, u2), "reason": "same chat as the report"}), 200, 0)

	// AC-MOD-04-11：群里带特征串文件名的文件消息。
	g := w.group(u1, u2)
	conv := "group:" + g
	pdf := append([]byte("%PDF-1.4\n"), make([]byte, 1024)...)
	fileID := w.upload(w.userToken(u1), "file", fileName, pdf, "application/pdf", nil)
	fm := msgIDOf(t, c1.sendAttachment(conv, "file", map[string]any{"file": map[string]any{"fileId": fileID}}))
	rf := c2.reportMsg(conv, fm, "illegal", "")
	before := len(w.im.dump())
	r = kf.do("POST", "/console/api/messages/meta/query", map[string]any{"convId": conv})
	expect(t, "support meta", r, 200, 0)
	r2v := reportView(mod, rf, "")
	expect(t, "group file report", r2v, 200, 0)
	if strings.Contains(r.raw, "ZXQ-FN-1") || strings.Contains(r2v.raw, "ZXQ-FN-1") || strings.Contains(w.im.dump()[before:], "ZXQ-FN-1") {
		t.Errorf("file name in meta: %s\n%s", r.raw, r2v.raw)
	}
	fmeta := asMap(t, "file message", asList(t, "messages", r2v.body["messages"])[0])
	if fmeta["type"] != "file" || fnum(fmeta["fileSize"]) != int64(len(pdf)) {
		t.Errorf("file report meta = %v", fmeta)
	}
	if r2v.body["convId"] != conv { // 群举报不要理由，不占配额（配额已经满了也能看）
		t.Errorf("group report = %s", r2v.raw)
	}
	noneContains(t, "console logs and database", w.logs.String()+w.dumpDB(), map[string]string{"note": note, "file name": "ZXQ-FN-1", "text": mark})
}

// TC-MOD-04-05（AC-MOD-04-5）、TC-MOD-04-14 后半（AC-MOD-04-14，console 的 5031）：
// 审计写失败时结案 503 / 5031，不调用 im-server，举报还是 pending；两个审核员同时结案，一个 200、一个 409 / 4098（im-server 原样返回），
// 状态和结论是成功的那个；结论、理由不合法 400 / 4000，不调用 im-server。
func TestTC_MOD_04_05_14_Resolve(t *testing.T) {
	w := newModWorld(t, 150*time.Second)
	super := w.super("adm1")
	modA := super.create("moda", "moderator")
	modB := super.create("modb", "moderator")
	p := uniq("rv")
	u1, u2 := p+"a", p+"b"
	w.users(u1, u2)
	g := w.group(u1, u2)
	c1, c2 := w.dial(u1, "web"), w.dial(u2, "web")
	id := c2.reportMsg("group:"+g, msgIDOf(t, c1.send("group:"+g, "x")), "spam", "")
	resolveURL := reportsURL + "/" + id + "/resolve"
	calls := func() int { return w.im.count("POST", "/admin/reports/"+id+"/resolve") }

	w.a.SetAuditFault("fail")
	expect(t, "audit down", modA.do("POST", resolveURL, map[string]any{"result": "handled", "reason": "violates the rules"}), 503, 5031)
	w.a.SetAuditFault("ok")
	expect(t, "bad result", modA.do("POST", resolveURL, map[string]any{"result": "done", "reason": "violates the rules"}), 400, 4000)
	expect(t, "bad reason", modA.do("POST", resolveURL, map[string]any{"result": "handled", "reason": "x"}), 400, 4000)
	if calls() != 0 {
		t.Fatalf("resolve reached im-server %d times", calls())
	}
	if r := reportView(modA, id, ""); r.body["state"] != "pending" {
		t.Fatalf("after the audit failure: %s", r.raw)
	}

	var wg sync.WaitGroup
	results := map[string]reply{}
	var mu sync.Mutex
	for name, u := range map[string]*user{"a": modA, "b": modB} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := u.do("POST", resolveURL, map[string]any{"result": "handled", "reason": "concluded by " + name})
			mu.Lock()
			results[name] = r
			mu.Unlock()
		}()
	}
	wg.Wait()
	winner, loser := "a", "b"
	if results["a"].status != 200 {
		winner, loser = "b", "a"
	}
	expect(t, "winner", results[winner], 200, 0)
	expect(t, "loser", results[loser], 409, 4098)
	r := reportView(modA, id, "")
	if r.body["state"] != "handled" || r.body["conclusion"] != "concluded by "+winner || fnum(r.body["handledAt"]) <= 0 {
		t.Errorf("after resolve = %s", r.raw)
	}
	winnerID := map[string]string{"a": modA.id, "b": modB.id}[winner]
	if hb, _ := r.body["handledBy"].(string); !strings.Contains(hb, winnerID) {
		t.Errorf("handledBy = %v, want %s", r.body["handledBy"], winnerID)
	}
	expect(t, "rejected later", modB.do("POST", resolveURL, map[string]any{"result": "rejected", "reason": "too late now"}), 409, 4098)
	if rows := w.auditRows(`action = 'report.handle' AND phase = 'result' AND result = 'success'`); len(rows) != 1 {
		t.Errorf("success results = %v", rows)
	}
	if rows := w.auditRows(`action = 'report.handle' AND phase = 'result' AND code = 4098`); len(rows) != 2 {
		t.Errorf("4098 results = %v", rows)
	}
	expect(t, "unknown report", modA.do("POST", reportsURL+"/rp_nothing/resolve", map[string]any{"result": "handled", "reason": "no such report"}), 404, 4040)
}
