package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// relogin 重新登录（测试推进时钟之后）。
func relogin(t *testing.T, users ...*user) {
	t.Helper()
	for _, u := range users {
		u.w.tick()
		expect(t, "login "+u.name, u.login(), 200, 0)
	}
}

// browserJSON 和 JSON.stringify 一样不转义 < > &。
func browserJSON(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func shaHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func pushUserReq(data any, users ...string) map[string]any {
	return map[string]any{"userIds": users, "type": "notice", "data": data, "reason": "系统通知测试"}
}

// PRD-admin F-ADM-50：按用户推送（CS-044）。
func TestPushToUsers(t *testing.T) {
	w := newPushWorld(t)
	super := w.super("adm5")
	op := super.create("op5", "operator")
	kf := super.create("kf5", "support")
	aud := super.create("aud5", "auditor")

	t.Run("templates and preview", func(t *testing.T) {
		r := op.do("GET", "/console/api/push/templates", nil)
		expect(t, "templates", r, 200, 0)
		if !strings.Contains(r.raw, `"type":"notice"`) || !strings.Contains(r.raw, `"type":"activity"`) || !strings.Contains(r.raw, `"schema"`) {
			t.Errorf("templates = %s", r.raw)
		}
		before := w.imPushes()
		r = op.do("POST", "/console/api/push/preview", map[string]any{"target": "user", "userIds": []string{"a1", "a1", "a2"}, "type": "notice", "data": notice("预览内容")})
		expect(t, "preview", r, 200, 0)
		if r.body["targetCount"] != float64(2) || r.body["type"] != "notice" || !strings.Contains(r.str("data"), "\n  \"text\": \"预览内容\"") {
			t.Errorf("preview = %s", r.raw)
		}
		r = op.do("POST", "/console/api/push/preview", map[string]any{"target": "all", "type": "notice", "data": notice("预览内容")})
		expect(t, "preview all", r, 200, 0)
		if r.body["target"] != "all" {
			t.Errorf("preview all = %s", r.raw)
		}
		expect(t, "bad target", op.do("POST", "/console/api/push/preview", map[string]any{"target": "room", "type": "notice", "data": notice("x")}), 400, 4000)
		if w.imPushes() != before {
			t.Error("preview reached im-server")
		}
	})

	// AC-ADM-50-1：两人在线，3 秒内收到，type 和 data 一致。
	t.Run("AC-ADM-50-1", func(t *testing.T) {
		u1, u2 := uniq("pa"), uniq("pb")
		w.users(u1, u2)
		c1, c2 := w.dial(u1, "web"), w.dial(u2, "web")
		const secret = "ZXQ-PUSH-SECRET-501"
		start := time.Now()
		r := op.do("POST", "/console/api/push/user", pushUserReq(notice(secret), u1, u2))
		expect(t, "send", r, 200, 0)
		if r.body["created"] != true || r.body["accepted"] != float64(2) {
			t.Errorf("send = %s", r.raw)
		}
		for _, c := range []*wsClient{c1, c2} {
			d := c.waitPush()
			if d["type"] != "notice" || d["pushId"] != r.str("pushId") || d["target"] != "user" || !reflect.DeepEqual(d["data"], notice(secret)) {
				t.Errorf("frame = %v", d)
			}
		}
		if took := time.Since(start); took > 3*time.Second {
			t.Errorf("took %v", took)
		}
		// pushId 就是 console 生成的 UUID（AC-ADM-50-8 的 im_push_id）。
		rec := w.pushRecord(secret)
		if rec.PushID != r.str("pushId") || rec.Status != "success" || rec.Created == nil || !*rec.Created {
			t.Errorf("record = %+v", rec)
		}
		// 审计和日志都没有正文。
		rows := w.auditRows(`action = 'push.user' AND request_id = $1`, rec.RequestID)
		if len(rows) != 2 || rows[1]["result"] != "success" {
			t.Errorf("audit = %v", rows)
		}
		all := fmt.Sprint(w.auditRows(`action LIKE 'push.%'`))
		if strings.Contains(all, secret) {
			t.Error("notification text in audit")
		}
		if strings.Contains(w.logs.String(), secret) {
			t.Error("notification text in logs")
		}
		for _, call := range w.im.find("POST", "/admin/push") {
			if strings.Contains(call.Path, secret) {
				t.Error("notification text in URL")
			}
		}
	})

	// AC-ADM-50-2 [IM 钟]：第 6 天补收；推进 8 天收不到。
	t.Run("AC-ADM-50-2", func(t *testing.T) {
		u3, u4 := uniq("pc"), uniq("pd")
		w.users(u3, u4)
		expect(t, "u3", op.do("POST", "/console/api/push/user", pushUserReq(notice("第六天"), u3)), 200, 0)
		w.advance(6 * 24 * time.Hour)
		c3 := w.dial(u3, "web")
		got := c3.pushSync(0)
		if len(got) != 1 || !strings.Contains(fmt.Sprint(got[0]), "第六天") {
			t.Errorf("u3 pushes = %v", got)
		}
		relogin(t, op) // 会话 12 小时绝对过期
		expect(t, "u4", op.do("POST", "/console/api/push/user", pushUserReq(notice("第八天"), u4)), 200, 0)
		w.advance(8 * 24 * time.Hour)
		c4 := w.dial(u4, "web")
		if got := c4.pushSync(0); len(got) != 0 {
			t.Errorf("u4 pushes after 8 days = %v", got)
		}
		relogin(t, op, kf, aud, super)
	})

	// AC-ADM-50-4：Schema 不符或超过 4KB：400，不投递。
	t.Run("AC-ADM-50-4", func(t *testing.T) {
		u := uniq("pe")
		w.users(u)
		before := w.imPushes()
		for name, data := range map[string]any{
			"missing":   map[string]any{"title": "x"},
			"wrongType": map[string]any{"title": 1, "text": "x"},
			"extra":     map[string]any{"title": "x", "text": "x", "evil": true},
			"tooLong":   map[string]any{"title": strings.Repeat("长", 65), "text": "x"},
			"notObject": []string{"x"},
		} {
			r := op.do("POST", "/console/api/push/user", pushUserReq(data, u))
			expect(t, name, r, 400, 4000)
			if r.reason() != "dataInvalid" {
				t.Errorf("%s: %s", name, r.raw)
			}
		}
		// 模板 notice 限制了 text 长度：超长的 data 先按字节挡住。
		r := op.do("POST", "/console/api/push/user", pushUserReq(map[string]any{"title": "x", "text": strings.Repeat("a", 4097)}, u))
		expect(t, "4097", r, 400, 4000)
		if r.reason() != "dataTooLarge" {
			t.Errorf("4097: %s", r.raw)
		}
		expect(t, "unknown type", op.do("POST", "/console/api/push/user", map[string]any{"userIds": []string{u}, "type": "nope", "data": notice("x"), "reason": "系统通知测试"}), 400, 4000)
		expect(t, "no reason", op.do("POST", "/console/api/push/user", map[string]any{"userIds": []string{u}, "type": "notice", "data": notice("x")}), 400, 4000)
		if w.imPushes() != before {
			t.Error("invalid push reached im-server")
		}
	})

	// AC-ADM-50-6：ghost 透传 details，整批不发送；1001 个 400 / 4131。
	t.Run("AC-ADM-50-6", func(t *testing.T) {
		u := uniq("pf")
		w.users(u)
		conn := w.dial(u, "web")
		g1, g2 := "ghost1"+u, "ghost2"+u
		r := op.do("POST", "/console/api/push/user", pushUserReq(notice("幽灵"), u, g1, g2))
		expect(t, "ghost", r, 404, 4042)
		details, _ := r.body["details"].(map[string]any)
		if !reflect.DeepEqual(details["userIds"], []any{g1, g2}) {
			t.Errorf("details = %s", r.raw)
		}
		conn.noPush("ghost")
		if got := conn.pushSync(0); len(got) != 0 {
			t.Errorf("sent to a real user: %v", got)
		}
		if rec := w.pushRecord("幽灵"); rec.Status != "failed" || rec.ErrorCode != 4042 {
			t.Errorf("record = %+v", rec)
		}
		before := w.imPushes()
		expect(t, "1001", op.do("POST", "/console/api/push/user", pushUserReq(notice("x"), numbered("n", 1001)...)), 400, 4131)
		if w.imPushes() != before {
			t.Error("1001 reached im-server")
		}
		// 恰好 1000 个（都不存在，到 im-server 才知道）：能发到 im-server。64KB 请求体上限不能挡住它。
		expect(t, "1000", op.do("POST", "/console/api/push/user", pushUserReq(notice("x"), numbered(strings.Repeat("z", 60), 1000)...)), 404, 4042)
		if w.imPushes() != before+1 {
			t.Error("1000 did not reach im-server")
		}
	})

	// CSV 目标：importToken 只能用一次。
	t.Run("csv targets", func(t *testing.T) {
		u1, u2 := uniq("pg"), uniq("ph")
		w.users(u1, u2)
		c1 := w.dial(u1, "web")
		v := op.upload("/console/api/push/targets/validate", "userId\n"+u1+"\n"+u2+"\n"+u1+"\n", nil)
		expect(t, "validate", v, 200, 0)
		if v.body["total"] != float64(2) {
			t.Errorf("validate = %s", v.raw)
		}
		token := v.str("importToken")
		req := map[string]any{"importToken": token, "type": "notice", "data": notice("CSV"), "reason": "系统通知测试"}
		p := op.do("POST", "/console/api/push/preview", map[string]any{"target": "user", "importToken": token, "type": "notice", "data": notice("CSV")})
		if p.body["targetCount"] != float64(2) {
			t.Errorf("preview = %s", p.raw)
		}
		expect(t, "send", op.do("POST", "/console/api/push/user", req), 200, 0)
		c1.waitPush()
		expect(t, "reuse", op.do("POST", "/console/api/push/user", req), 400, 4000)
		expect(t, "both", op.do("POST", "/console/api/push/user", map[string]any{"importToken": token, "userIds": []string{u1}, "type": "notice", "data": notice("x"), "reason": "系统通知测试"}), 400, 4000)
		expect(t, "bad header", op.upload("/console/api/push/targets/validate", "uid\nx\n", nil), 400, 4000)
		var many strings.Builder
		many.WriteString("userId\n")
		for _, id := range numbered("m", 1001) {
			many.WriteString(id + "\n")
		}
		expect(t, "csv 1001", op.upload("/console/api/push/targets/validate", many.String(), nil), 400, 4131)
		bad := op.upload("/console/api/push/targets/validate", "userId\nbad id\n", nil)
		if bad.status != 200 || bad.body["valid"] != false {
			t.Errorf("bad csv = %s", bad.raw)
		}
	})

	t.Run("permissions", func(t *testing.T) {
		expect(t, "support", kf.do("POST", "/console/api/push/user", pushUserReq(notice("x"), "a1")), 403, 4030)
		expect(t, "auditor", aud.do("POST", "/console/api/push/user", pushUserReq(notice("x"), "a1")), 403, 4030)
		expect(t, "support preview", kf.do("POST", "/console/api/push/preview", map[string]any{"target": "all", "type": "notice", "data": notice("x")}), 403, 4030)
		expect(t, "operator records", op.do("GET", "/console/api/push/records", nil), 403, 4030)
	})

	// 数字原文不能丢精度，< 不能被改写：存库、哈希、下发都是同一份字节。
	t.Run("big number and html characters", func(t *testing.T) {
		u := uniq("pi")
		w.users(u)
		c := w.dial(u, "web")
		const big = "9007199254740993"
		marker := strings.Repeat("<", 40) + "数字"
		data := fmt.Sprintf(`{"title":%q,"url":"https://x/","endAt":%s}`, marker, big)
		req := map[string]any{"userIds": []string{u}, "type": "activity", "reason": "系统通知测试", "data": json.RawMessage(data)}
		expect(t, "send", op.do("POST", "/console/api/push/user", browserJSON(req)), 200, 0)
		if d := c.waitPush(); !strings.Contains(fmt.Sprint(d["data"]), marker) {
			t.Errorf("frame = %v", d)
		}
		rec := w.pushRecord(marker)
		if rec.Data != data || rec.Sha != sha256Text(data) {
			t.Errorf("stored = %s", rec.Data)
		}
	})
}

// 全部用 < 填满到 4096 字节：console 和 im-server 算出来的长度必须一样。模板不限制长度。
func TestPushByteLimitMatchesIMServer(t *testing.T) {
	w := newPushWorldTemplates(t, `{"notice":{"type":"object","required":["text"],"properties":{"text":{"type":"string"}}}}`)
	super := w.super("adm5")
	op := super.create("op5", "operator")
	u := uniq("pj")
	w.users(u)
	overhead := len(`{"text":""}`)
	expect(t, "4096", op.do("POST", "/console/api/push/user", browserJSON(map[string]any{"userIds": []string{u}, "type": "notice", "reason": "系统通知测试",
		"data": map[string]any{"text": strings.Repeat("<", 4096-overhead)}})), 200, 0)
	r := op.do("POST", "/console/api/push/user", browserJSON(map[string]any{"userIds": []string{u}, "type": "notice", "reason": "系统通知测试",
		"data": map[string]any{"text": strings.Repeat("<", 4097-overhead)}}))
	expect(t, "4097", r, 400, 4000)
	if r.reason() != "dataTooLarge" {
		t.Errorf("4097 = %s", r.raw)
	}
}

// PRD-admin F-ADM-50 规则 5：全员（CS-045）。
func TestPushAll(t *testing.T) {
	w := newPushWorld(t)
	super := w.super("adm5")
	super2 := super.create("adm6", "super_admin")
	op := super.create("op5", "operator")
	aud := super.create("aud5", "auditor")
	kf := super.create("kf5", "support")
	both := super.create("opadm", "operator", "super_admin")

	// AC-ADM-50-7：发起人同时是超管，也不能批准。
	t.Run("AC-ADM-50-7", func(t *testing.T) {
		id := draft(t, both, notice("自批"))
		before := w.imPushes()
		r := approve(both, id)
		expect(t, "self", r, 403, 4030)
		if w.imPushes() != before {
			t.Error("self approval reached im-server")
		}
		expect(t, "support", kf.do("POST", "/console/api/push/all/drafts/"+id+"/approve", map[string]any{"confirmText": pushApprove}), 403, 4030)
		expect(t, "operator", op.do("POST", "/console/api/push/all/drafts/"+id+"/approve", map[string]any{"confirmText": pushApprove}), 403, 4030)
	})

	t.Run("approval gates", func(t *testing.T) {
		id := draft(t, op, notice("门禁"))
		w.advance(6 * time.Minute) // step-up 窗口过了
		expect(t, "no step-up", super.do("POST", "/console/api/push/all/drafts/"+id+"/approve", map[string]any{"confirmText": pushApprove}), 403, 4038)
		super.stepUp()
		r := super.do("POST", "/console/api/push/all/drafts/"+id+"/approve", map[string]any{"confirmText": "确认"})
		expect(t, "wrong text", r, 400, 4000)
		if r.reason() != "confirmMismatch" {
			t.Errorf("reason = %s", r.raw)
		}
		expect(t, "unknown draft", super.do("POST", "/console/api/push/all/drafts/nope/approve", map[string]any{"confirmText": pushApprove}), 404, 4040)
		// 草稿校验和发送一样严格。
		expect(t, "bad schema", op.do("POST", "/console/api/push/all/drafts", map[string]any{"type": "notice", "data": map[string]any{"title": "x"}, "reason": "全员通知复核"}), 400, 4000)
		expect(t, "no reason", op.do("POST", "/console/api/push/all/drafts", map[string]any{"type": "notice", "data": notice("x")}), 400, 4000)
		if pending := super.do("GET", "/console/api/push/all/drafts/pending", nil); !strings.Contains(pending.raw, id) || !strings.Contains(pending.raw, "门禁") {
			t.Errorf("pending = %s", pending.raw)
		}
		// 24 小时作废，读取时判断：T+24h 那一刻已经不能批准（[C 钟]）。
		w.advance(24 * time.Hour)
		relogin(t, op, super, super2, aud, kf, both)
		r = approve(super, id)
		expect(t, "expired", r, 400, 4000)
		if r.reason() != "draftExpired" {
			t.Errorf("expired = %s", r.raw)
		}
		if l := super.do("GET", "/console/api/push/all/drafts/pending", nil); strings.Contains(l.raw, id) {
			t.Errorf("expired draft still pending: %s", l.raw)
		}
		if l := op.do("GET", "/console/api/push/all/drafts", nil); !strings.Contains(l.raw, `"status":"expired"`) {
			t.Errorf("drafts = %s", l.raw)
		}
	})

	// AC-ADM-50-3、50-5、50-8：5 人在线都收到，u9 上线收不到；T+4 分钟 429，T+5 分钟成功；记录全文，审计只有长度和哈希。
	t.Run("AC-ADM-50-3 5 8", func(t *testing.T) {
		const secret = "ZXQ-ALL-SECRET-503"
		var online []*wsClient
		for range 5 {
			u := uniq("on")
			w.users(u)
			online = append(online, w.dial(u, "web"))
		}
		u9 := uniq("off")
		w.users(u9)
		id := draft(t, op, notice(secret))
		before := w.imPushes()
		r := approve(super, id)
		expect(t, "approve", r, 200, 0)
		if r.body["created"] != true {
			t.Errorf("approve = %s", r.raw)
		}
		if _, has := r.body["accepted"]; has {
			t.Errorf("accepted on target=all: %s", r.raw)
		}
		t0 := w.now
		for _, c := range online {
			d := c.waitPush()
			if d["target"] != "all" || !reflect.DeepEqual(d["data"], notice(secret)) {
				t.Errorf("frame = %v", d)
			}
			c.noPush("once")
		}
		c9 := w.dial(u9, "web")
		c9.noPush("u9 was offline")
		if got := c9.pushSync(0); len(got) != 0 {
			t.Errorf("u9 pushes = %v", got)
		}
		// 再批准同一份：不会发第二次。
		again := approve(super, id)
		expect(t, "double approve", again, 400, 4000)
		if again.reason() != "draftClosed" {
			t.Errorf("double approve = %s", again.raw)
		}
		// AC-ADM-50-5。
		id2 := draft(t, op, notice("第二条全员"))
		// approve 里的 step-up 会把两边的钟推进 30 秒。
		w.now = t0.Add(4*time.Minute - 30*time.Second)
		w.a.Clock.Freeze(w.now)
		w.syncIMClock(w.now)
		r = approve(super2, id2)
		expect(t, "T+4", r, 429, 4290)
		if r.reason() != "pushAllInterval" {
			t.Errorf("T+4 = %s", r.raw)
		}
		if w.imPushes() != before+1 {
			t.Error("T+4 reached im-server")
		}
		// 刚好 5 分钟：放行。429 没有消耗草稿，另一位超管可以再批。
		w.now = t0.Add(5*time.Minute - 30*time.Second)
		w.a.Clock.Freeze(w.now)
		w.syncIMClock(w.now)
		r = approve(super2, id2)
		expect(t, "T+5", r, 200, 0)
		w.tick()

		// AC-ADM-50-8。
		recs := aud.do("GET", "/console/api/push/records", nil)
		expect(t, "auditor records", recs, 200, 0)
		var page struct {
			Records []struct {
				Data, DataSha256, DataPretty, CreatedByName, Kind, PushID string
				ApprovedByName                                            *string
				SentAt                                                    int64
			} `json:"records"`
		}
		if err := json.Unmarshal([]byte(recs.raw), &page); err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, x := range page.Records {
			if !strings.Contains(x.Data, secret) {
				continue
			}
			found = true
			if x.CreatedByName != op.name || x.ApprovedByName == nil || *x.ApprovedByName != super.name || x.Kind != "all" || x.SentAt == 0 {
				t.Errorf("record = %+v", x)
			}
			if x.DataSha256 != sha256Text(x.Data) {
				t.Errorf("sha = %s", x.DataSha256)
			}
			rows := w.auditRows(`action = 'push.all.approve' AND phase = 'intent' AND params LIKE '%' || $1 || '%' AND params LIKE '%' || $2 || '%'`, x.DataSha256, x.PushID)
			if len(rows) != 1 {
				t.Fatalf("audit rows = %v", rows)
			}
			if !strings.Contains(rows[0]["params"].(string), fmt.Sprintf(`"dataLength":%d`, len(x.Data))) {
				t.Errorf("audit params = %v", rows[0]["params"])
			}
		}
		if !found {
			t.Errorf("no record: %s", recs.raw)
		}
		if strings.Contains(fmt.Sprint(w.auditRows(`action LIKE 'push.%'`)), secret) {
			t.Error("notification text in audit")
		}
		if strings.Contains(w.logs.String(), secret) {
			t.Error("notification text in logs")
		}
		if len(w.auditRows(`action = 'push.records.read' AND username = $1`, aud.name)) == 0 {
			t.Error("reading the full text left no audit")
		}
		expect(t, "super records", super.do("GET", "/console/api/push/records", nil), 200, 0)
		expect(t, "operator records", op.do("GET", "/console/api/push/records", nil), 403, 4030)
	})

	// 发送记录、草稿的保留期跟审计：在线 1 年 + 归档 3 年。
	t.Run("retention", func(t *testing.T) {
		count := func() (n int) {
			if err := w.db.QueryRow(t.Context(), `SELECT count(*) FROM biz.push_records`).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		}
		before := count()
		if before == 0 {
			t.Fatal("no records")
		}
		w.a.Clock.Freeze(w.now.Add(3 * 366 * 24 * time.Hour))
		if err := w.a.Housekeeping(t.Context()); err != nil {
			t.Fatal(err)
		}
		if count() != before {
			t.Error("deleted within the retention")
		}
		w.a.Clock.Freeze(w.now.Add(5 * 366 * 24 * time.Hour))
		if err := w.a.Housekeeping(t.Context()); err != nil {
			t.Fatal(err)
		}
		if count() != 0 {
			t.Error("not deleted after the retention")
		}
		w.a.Clock.Freeze(w.now)
	})
}

// PRD-live 4.7 节 5040 对账表，逐行（AC-PUSH-06-6、06-13、06-15）。
func TestPushReconcile(t *testing.T) {
	w := newPushWorld(t)
	super := w.super("adm5")
	super2 := super.create("adm6", "super_admin")
	op := super.create("op5", "operator")
	fresh := func() { // 对账要推进时钟，会话要跟上
		t.Helper()
		relogin(t, op, super, super2)
	}
	send5040 := func(t *testing.T, marker string, users ...string) {
		t.Helper()
		r := op.do("POST", "/console/api/push/user", pushUserReq(notice(marker), users...))
		expect(t, "send", r, 504, 5040)
	}
	replays := func(rec pushRow) []map[string]any {
		return w.auditRows(`action = 'push.replay' AND params LIKE '%' || $1 || '%'`, rec.PushID)
	}
	inbox := func(uid string) int {
		c := w.dial(uid, "web")
		defer func() { _ = c.ws.CloseNow() }()
		return len(c.pushSync(0))
	}
	drop := func(on bool) { w.a.IMDropResponse.Store(on) }
	latency := func(ms int64) { w.a.IMLatencyMs.Store(ms) }

	// 第一行：result 2xx → success，不重放（AC-PUSH-06-6）。
	t.Run("2xx user", func(t *testing.T) {
		fresh()
		u := uniq("ra")
		w.users(u)
		conn := w.dial(u, "web")
		drop(true)
		send5040(t, "第一行用户", u)
		drop(false)
		rec := w.pushRecord("第一行用户")
		if rec.Status != "unknown" {
			t.Errorf("before reconcile = %+v", rec)
		}
		conn.waitPush()
		before := w.imPushes()
		w.reconcile() // 不到 5 分钟：不动
		if w.pushRecord("第一行用户").Status != "unknown" {
			t.Error("reconciled too early")
		}
		w.settle()
		w.reconcile()
		rec = w.pushRecord("第一行用户")
		if rec.Status != "success" || w.imPushes() != before || len(replays(rec)) != 0 {
			t.Errorf("record = %+v, pushes %d, replays %v", rec, w.imPushes()-before, replays(rec))
		}
		conn.noPush("only once")
		if inbox(u) != 1 {
			t.Errorf("inbox = %d", inbox(u))
		}
		rows := w.auditRows(`request_id = $1 AND phase = 'result' AND params LIKE '%reconciled%'`, rec.RequestID)
		if len(rows) != 1 || rows[0]["result"] != "success" {
			t.Errorf("audit = %v", rows)
		}
	})

	t.Run("2xx all", func(t *testing.T) {
		fresh()
		u := uniq("rb")
		w.users(u)
		conn := w.dial(u, "web")
		id := draft(t, op, notice("第一行全员"))
		drop(true)
		expect(t, "approve", approve(super, id), 504, 5040)
		drop(false)
		conn.waitPush()
		before := w.imPushes()
		w.settle()
		w.reconcile()
		rec := w.pushRecord("第一行全员")
		if rec.Status != "success" || w.imPushes() != before || len(replays(rec)) != 0 {
			t.Errorf("record = %+v", rec)
		}
		conn.noPush("only once")
	})

	// 第二行：4xx、5xx → failed，不重放。console 只拿到 5040，结论来自 im-server 的审计。
	t.Run("4xx", func(t *testing.T) {
		fresh()
		ghost := "ghost" + uniq("rc")
		drop(true)
		send5040(t, "第二行四百", ghost)
		drop(false)
		before := w.imPushes()
		w.settle()
		w.reconcile()
		rec := w.pushRecord("第二行四百")
		if rec.Status != "failed" || rec.ErrorCode != 4042 || w.imPushes() != before || len(replays(rec)) != 0 {
			t.Errorf("record = %+v", rec)
		}
		rows := w.auditRows(`request_id = $1 AND phase = 'result' AND params LIKE '%reconciled%'`, rec.RequestID)
		if len(rows) != 1 || rows[0]["result"] != "failure" || rows[0]["code"].(int32) != 4042 {
			t.Errorf("audit = %v", rows)
		}
	})

	t.Run("5xx", func(t *testing.T) {
		fresh()
		u := uniq("rd")
		w.users(u)
		w.imTest("/admin/test/faults/push-fail-at", map[string]any{"index": 0})
		drop(true)
		send5040(t, "第二行五百", u)
		drop(false)
		before := w.imPushes()
		w.settle()
		w.reconcile()
		rec := w.pushRecord("第二行五百")
		if rec.Status != "failed" || rec.ErrorCode != 5000 || w.imPushes() != before || len(replays(rec)) != 0 {
			t.Errorf("record = %+v", rec)
		}
		if inbox(u) != 0 {
			t.Error("delivered")
		}
	})

	// 第三行：只有 intent → unknown，用同一 pushId 重放，created=false，在线用户收到（AC-PUSH-06-15）。
	t.Run("intent only", func(t *testing.T) {
		fresh()
		u := uniq("re")
		w.users(u)
		// pushId 是 console 生成的：在转发之前按请求里的 pushId 打开故障。
		w.im.mu.Lock()
		w.im.inject = func(c imCall) int {
			if c.Path == "/admin/push" {
				var req struct {
					PushID string `json:"pushId"`
				}
				_ = json.Unmarshal([]byte(c.Body), &req)
				w.imTest("/admin/test/faults/push-exit-before-broadcast", map[string]any{"pushId": req.PushID})
			}
			return 0
		}
		w.im.mu.Unlock()
		id := draft(t, op, notice("第三行全员"))
		expect(t, "approve", approve(super, id), 504, 5040)
		w.im.mu.Lock()
		w.im.inject = nil
		w.im.mu.Unlock()
		w.proc.waitExit()
		w.proc.start()
		w.settle() // 重启后 [IM 钟] 要重新拨，settle 会拨
		rec := w.pushRecord("第三行全员")
		if rec.Status != "unknown" {
			t.Errorf("before reconcile = %+v", rec)
		}
		conn := w.dial(u, "web")
		approvals := len(w.auditRows(`action = 'push.all.approve' AND phase = 'intent'`))
		before := w.imPushes()
		w.reconcile()
		got := w.pushRecord("第三行全员")
		if got.Status != "success" || got.ReplayCreated == nil || *got.ReplayCreated || got.PushID != rec.PushID || got.SentAt != rec.SentAt {
			t.Errorf("record = %+v", got)
		}
		if w.imPushes() != before+1 {
			t.Errorf("pushes = %d", w.imPushes()-before)
		}
		d := conn.waitPush()
		if d["pushId"] != rec.PushID || int64(d["ts"].(float64)) >= w.now.UnixMilli() {
			t.Errorf("frame = %v, now %d", d, w.now.UnixMilli())
		}
		if len(w.auditRows(`action = 'push.all.approve' AND phase = 'intent'`)) != approvals {
			t.Error("replay went through approval again")
		}
		rows := w.auditRows(`request_id = $1 AND phase = 'result' AND params LIKE '%imIntentOnly%'`, rec.RequestID)
		if len(rows) != 1 || rows[0]["result"] != "unknown" {
			t.Errorf("original audit = %v", rows)
		}
		rs := replays(rec)
		if len(rs) != 2 || !strings.Contains(rs[0]["params"].(string), rec.RequestID) || !strings.Contains(rs[1]["params"].(string), `"created":false`) || rs[1]["result"] != "success" {
			t.Errorf("replay audit = %v", rs)
		}
		// 再跑一轮也不会再重放。
		w.settle()
		w.reconcile()
		if w.imPushes() != before+1 {
			t.Error("replayed twice")
		}
	})

	// 第四行：没有 intent → notExecuted，用同一 pushId 重放，created=true，用户收到一次（AC-PUSH-06-13）。
	t.Run("no intent user", func(t *testing.T) {
		fresh()
		u := uniq("rf")
		w.users(u)
		conn := w.dial(u, "web")
		latency(6000)
		before := w.imPushes()
		send5040(t, "第四行用户", u)
		latency(0)
		if w.imPushes() != before {
			t.Fatal("the request reached im-server")
		}
		rec := w.pushRecord("第四行用户")
		w.settle()
		w.reconcile()
		got := w.pushRecord("第四行用户")
		if got.Status != "success" || got.ReplayCreated == nil || !*got.ReplayCreated || got.PushID != rec.PushID {
			t.Errorf("record = %+v", got)
		}
		if conn.waitPush()["pushId"] != rec.PushID {
			t.Error("wrong pushId")
		}
		conn.noPush("once")
		if inbox(u) != 1 {
			t.Errorf("inbox = %d", inbox(u))
		}
		rows := w.auditRows(`request_id = $1 AND phase = 'result' AND params LIKE '%notExecuted%'`, rec.RequestID)
		if len(rows) != 1 {
			t.Errorf("original audit = %v", rows)
		}
		rs := replays(rec)
		if len(rs) != 2 || !strings.Contains(rs[1]["params"].(string), `"created":true`) {
			t.Errorf("replay audit = %v", rs)
		}
	})

	// 全员：不重走复核，不受 5 分钟间隔约束，也不写"最近一次全员发送时间"。
	t.Run("no intent all ignores interval", func(t *testing.T) {
		fresh()
		u := uniq("rg")
		w.users(u)
		conn := w.dial(u, "web")
		a := draft(t, op, notice("第四行全员甲"))
		b := draft(t, op, notice("第四行全员乙"))
		c := draft(t, op, notice("第四行全员丙"))
		latency(6000)
		expect(t, "A", approve(super, a), 504, 5040)
		latency(0)
		recA := w.pushRecord("第四行全员甲")
		t0 := time.UnixMilli(recA.SentAt)
		// B 在 A 之后刚好 5 分钟成功：现在起 5 分钟之内都是"间隔内"。
		w.now = t0.Add(5*time.Minute - 30*time.Second)
		w.a.Clock.Freeze(w.now)
		w.syncIMClock(w.now)
		expect(t, "B", approve(super2, b), 200, 0)
		conn.waitPush()
		// T+9:30：离 B 只有 4 分半，A 的重放不受影响。
		w.now = t0.Add(9*time.Minute + 30*time.Second)
		w.a.Clock.Freeze(w.now)
		w.syncIMClock(w.now)
		w.reconcile()
		got := w.pushRecord("第四行全员甲")
		if got.Status != "success" || got.ReplayCreated == nil || !*got.ReplayCreated || got.SentAt != recA.SentAt {
			t.Errorf("A = %+v", got)
		}
		if d := conn.waitPush(); d["pushId"] != recA.PushID {
			t.Errorf("frame = %v", d)
		}
		// T+10：离 B 正好 5 分钟。如果重放算一次"全员发送"，这里会是 429。
		w.now = t0.Add(10*time.Minute - 30*time.Second)
		w.a.Clock.Freeze(w.now)
		w.syncIMClock(w.now)
		expect(t, "C", approve(super, c), 200, 0)
		conn.waitPush()
	})

	// 超过时限：不重放，标 unknown。正好 1 小时还重放。
	t.Run("expired", func(t *testing.T) {
		fresh()
		u := uniq("rh")
		w.users(u)
		latency(6000)
		send5040(t, "超时用户", u)
		id := draft(t, op, notice("超时全员"))
		w.advance(5*time.Minute + time.Second) // 和上一个子测试的全员间隔错开
		expect(t, "approve", approve(super, id), 504, 5040)
		latency(0)
		rec := w.pushRecord("超时全员")
		before := w.imPushes()
		w.advance(time.Hour + time.Second)
		w.reconcile()
		if w.imPushes() != before {
			t.Error("replayed after the limit")
		}
		for _, marker := range []string{"超时用户", "超时全员"} {
			got := w.pushRecord(marker)
			if got.Status != "unknown" || !got.ReplayExpired || got.ReplayRequestID != nil {
				t.Errorf("%s = %+v", marker, got)
			}
			if len(replays(got)) != 0 {
				t.Errorf("%s replay audit = %v", marker, replays(got))
			}
		}
		if rows := w.auditRows(`action = 'push.replay.expired' AND params LIKE '%' || $1 || '%'`, rec.PushID); len(rows) != 1 {
			t.Errorf("expired audit = %v", rows)
		}
		if inbox(u) != 0 {
			t.Error("delivered")
		}
		// 不会之后再补一次。
		w.settle()
		w.reconcile()
		if w.imPushes() != before {
			t.Error("replayed later")
		}
	})

	t.Run("exactly one hour replays", func(t *testing.T) {
		fresh()
		u := uniq("ri")
		w.users(u)
		latency(6000)
		send5040(t, "正好一小时", u)
		latency(0)
		rec := w.pushRecord("正好一小时")
		w.now = time.UnixMilli(rec.SentAt).Add(time.Hour)
		w.a.Clock.Freeze(w.now)
		w.syncIMClock(w.now)
		w.reconcile()
		if got := w.pushRecord("正好一小时"); got.Status != "success" {
			t.Errorf("record = %+v", got)
		}
	})

	// 重放本身也可能结果未知：只有一次，之后靠对账确认。
	t.Run("replay is unknown too", func(t *testing.T) {
		fresh()
		u := uniq("rj")
		w.users(u)
		latency(6000)
		send5040(t, "重放未知", u)
		latency(0)
		w.settle()
		drop(true)
		before := w.imPushes()
		w.reconcile()
		drop(false)
		if w.imPushes() != before+1 {
			t.Fatalf("pushes = %d", w.imPushes()-before)
		}
		if got := w.pushRecord("重放未知"); got.Status != "unknown" || got.ReplayRequestID == nil {
			t.Errorf("after replay = %+v", got)
		}
		w.settle()
		w.reconcile()
		got := w.pushRecord("重放未知")
		if got.Status != "success" || w.imPushes() != before+1 {
			t.Errorf("after second reconcile = %+v, pushes %d", got, w.imPushes()-before)
		}
		if inbox(u) != 1 {
			t.Errorf("inbox = %d", inbox(u))
		}
	})

	// im-server 不可用时：这一轮跳过，不算 notExecuted，也不重放。
	t.Run("im-server down during reconcile", func(t *testing.T) {
		fresh()
		u := uniq("rk")
		w.users(u)
		latency(6000)
		send5040(t, "对账时宕机", u)
		latency(0)
		w.settle()
		w.im.mu.Lock()
		w.im.inject = func(c imCall) int {
			if c.Path == "/admin/audit" {
				return 5000
			}
			return 0
		}
		w.im.mu.Unlock()
		before := w.imPushes()
		if err := w.a.Reconcile(t.Context()); err == nil {
			t.Error("reconcile hid the failure")
		}
		w.im.mu.Lock()
		w.im.inject = nil
		w.im.mu.Unlock()
		if w.imPushes() != before {
			t.Error("replayed without a conclusion")
		}
		if got := w.pushRecord("对账时宕机"); got.Status != "unknown" {
			t.Errorf("record = %+v", got)
		}
		w.reconcile()
		if got := w.pushRecord("对账时宕机"); got.Status != "success" {
			t.Errorf("record = %+v", got)
		}
	})

	// console 在 result 之前崩溃（这里用 failResult 模拟）：im-server 已受理，不重放。
	t.Run("result never written", func(t *testing.T) {
		fresh()
		u := uniq("rl")
		w.users(u)
		conn := w.dial(u, "web")
		w.a.SetAuditFault("failResult")
		r := op.do("POST", "/console/api/push/user", pushUserReq(notice("没有结果"), u))
		w.a.SetAuditFault("ok")
		expect(t, "send", r, 200, 0)
		conn.waitPush()
		before := w.imPushes()
		w.settle()
		w.reconcile()
		if got := w.pushRecord("没有结果"); got.Status != "success" || w.imPushes() != before {
			t.Errorf("record = %+v", got)
		}
		conn.noPush("once")
	})

	// 全员草稿只写 console 自己的库：im-server 查不到不等于没执行（localOnly），也不会误判成要重放。
	t.Run("draft is local", func(t *testing.T) {
		fresh()
		w.a.SetAuditFault("failResult")
		id := draft(t, op, notice("本地草稿"))
		w.a.SetAuditFault("ok")
		before := w.imPushes()
		w.settle()
		w.reconcile()
		rows := w.auditRows(`action = 'push.all.request' AND phase = 'result' AND params LIKE '%localOnly%' AND target LIKE '%' || $1 || '%'`, id)
		if len(rows) != 1 || rows[0]["result"] != "unknown" || w.imPushes() != before {
			t.Errorf("audit = %v", rows)
		}
	})

	// 正文不进审计和日志，重放也一样。
	if strings.Contains(fmt.Sprint(w.auditRows(`action LIKE 'push.%'`)), "第四行用户") || strings.Contains(w.logs.String(), "第四行用户") {
		t.Error("notification text leaked")
	}
}
