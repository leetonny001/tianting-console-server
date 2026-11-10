package e2e

// CS-205（C5）：后台查询不受用户"删除会话"、置顶、免打扰影响。PRD-chat F-CVS-03 规则 2"后台查询不受影响"，
// 没有单独的 AC，挂 AC-CVS-03-1，在 TC-CVS-03-01 第 4 步验（console-chat 问题 19、backend-chat 第 87 条）。
// 真实 im-server（IM_CONV_SETTINGS_ENABLED=1、IM_MSG_ACTIONS_ENABLED=1、IM_FILES_ENABLED=1、IM_C2C_BODY_ACCESS=on）+ 假 S3 + 真实 Postgres。

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// newCvsWorld 在 newRecallWorld 的基础上打开会话设置和单聊正文（单聊的正文、隔离原文、文件也要验）。
// 比撤回用例多 4 次申请授权（每次 tick 30 秒），lead 相应加大。
func newCvsWorld(t *testing.T) *inviteWorld {
	t.Helper()
	s3 := newFakeS3(t)
	env := append(s3.env(), "IM_TRUSTED_PROXIES=127.0.0.1/32,::1/128", "IM_MSG_ACTIONS_ENABLED=1", "IM_QUARANTINE_KEY="+rclQuarantineKey,
		"IM_CONV_SETTINGS_ENABLED=1", "IM_C2C_BODY_ACCESS=on")
	p := startIMProc(t, allConsoleScopes, env...)
	w := &inviteWorld{bizWorld: newBizWorldWith(t, p.admin, p.ws, p.key), proc: p}
	w.realClock(300 * time.Second)
	return w
}

// cmd 发一个带 id 的上行命令，等它的 ack，返回 data；ack 带 error 时失败。
func (c *wsClient) cmd(name string, data map[string]any) map[string]any {
	c.t.Helper()
	id := fmt.Sprintf("%s%d", name, time.Now().UnixNano())
	req, _ := json.Marshal(map[string]any{"id": id, "cmd": name, "data": data})
	if err := c.ws.Write(context.Background(), websocket.MessageText, req); err != nil {
		c.t.Fatal(err)
	}
	for {
		f := c.wait("ack")
		if f["id"] != id {
			continue
		}
		if f["error"] != nil {
			c.t.Fatalf("%s: %v", name, f)
		}
		d, _ := f["data"].(map[string]any)
		return d
	}
}

// adminView 是客服、审核员经 console 看到的一个会话：元数据、普通正文、隔离原文、撤回文件的字节。
type adminView struct {
	metaSeqs   []int64           // 元数据里的 seq（升序）
	meta       map[string]bool   // 元数据里的 msgId
	body       map[string]string // 普通正文：msgId → body 原文
	quarantine map[string]string // 隔离原文：msgId → body 原文
	photo      [32]byte          // 撤回图片经 console 代理取到的原图
	thumb      [32]byte
	raws       []string // 各个响应的原文（查置顶、免打扰有没有透传）
}

// TC-CVS-03-01 第 4 步（console 一侧，CS-205）：u1 删除和 u2 的单聊（10 条，第 3 条有特征串）、删除群 g1 的会话之后，
// 客服的元数据查询、审核员的正文授权读取、隔离读取、经 console 取撤回的文件、用户会话列表都和删除前完全一样（全部消息都在），
// console 审计照写；u1 自己这边确实已经删掉（convs 的 deleted、sync 空）。u1 的置顶、免打扰不出现在用户详情、元数据、会话列表。
// 反证：im-server 的后台查询错误地套用 u1 的 minSeq（clearedSeq + 1）时这里失败（见 console-chat CS-205 一行）。
func TestTC_CVS_03_01_AdminQueriesUnaffected(t *testing.T) {
	const mark = "ZXQ-CVS-1"
	w := newCvsWorld(t)
	super := w.super("adm1")
	kf := super.create("kf1", "support")
	mod := super.create("mod1", "moderator")
	if d := w.now.Sub(time.Now()).Abs(); d > 5*time.Minute {
		t.Fatalf("[C clock] is %v away from the real clock", d)
	}
	p := uniq("cv")
	u1, u2 := p+"a", p+"b"
	w.users(u1, u2)
	g1 := "group:" + w.group(u1, u2)
	g2 := "group:" + w.group(u1, u2) // 只置顶、免打扰，不删除
	c2c := "c2c:" + u1 + ":" + u2
	c1, c2 := w.dial(u1, "web"), w.dial(u2, "web")

	// 单聊 10 条：第 3 条有特征串，第 9 条是撤回的图片（隔离原文、文件代理都要有东西可看）。
	var c2cIDs []string
	var c2cFile string
	var c2cPhoto, c2cThumb []byte
	for i := 1; i <= 10; i++ {
		from := c1
		if i%2 == 0 {
			from = c2
		}
		switch i {
		case 3:
			c2cIDs = append(c2cIDs, msgIDOf(t, c1.send("c2c:"+u2, mark+" c2c 第 3 条")))
		case 9:
			// recalledImage 的 conv 同时用于发送和撤回；单聊发送用 c2c:<对方>，撤回用完整的会话 ID，这里分开写。
			c2cPhoto, c2cThumb = pngBytes(80, 60), pngBytes(20, 15)
			c2cFile = w.upload(w.userToken(u1), "image", "cvs-c2c.png", c2cPhoto, "image/png", c2cThumb)
			id := msgIDOf(t, c1.sendAttachment("c2c:"+u2, "image", map[string]any{"image": map[string]any{"fileId": c2cFile}}))
			c1.recall(c2c, id)
			c2cIDs = append(c2cIDs, id)
		default:
			to := "c2c:" + u2
			if from == c2 {
				to = "c2c:" + u1
			}
			c2cIDs = append(c2cIDs, msgIDOf(t, from.send(to, fmt.Sprintf("c2c 第 %d 条", i))))
		}
	}
	// 群：普通文本、特征串、撤回的文本、撤回的图片。
	var groupIDs []string
	groupIDs = append(groupIDs, msgIDOf(t, c1.send(g1, "group 1")))
	groupIDs = append(groupIDs, msgIDOf(t, c2.send(g1, mark+" group")))
	recalledText := msgIDOf(t, c1.send(g1, mark+" group recalled"))
	c1.recall(g1, recalledText)
	groupIDs = append(groupIDs, recalledText)
	gFile, gImg, gPhoto, gThumb := w.recalledImage(c1, u1, g1, "cvs-group.png")
	groupIDs = append(groupIDs, gImg)
	groupIDs = append(groupIDs, msgIDOf(t, c2.send(g1, "group last")))
	msgIDOf(t, c2.send(g2, "g2 only"))

	type grantKey struct {
		conv       string
		quarantine bool
	}
	granted := map[grantKey]bool{}
	grant := func(conv string, quarantine bool) {
		t.Helper()
		k := grantKey{conv, quarantine}
		if granted[k] {
			return
		}
		w.tick()
		expect(t, fmt.Sprintf("grant %s quarantine=%v", conv, quarantine),
			mod.do("POST", "/console/api/messages/grants", map[string]any{"convId": conv, "ticket": "T-CVS-1", "reason": "conversation deleted review", "otp": mod.otp(), "quarantine": quarantine}), 200, 0)
		granted[k] = true
	}
	read := func(conv string, quarantine bool) (map[string]string, string) {
		t.Helper()
		grant(conv, quarantine)
		r := mod.do("POST", "/console/api/messages/body", map[string]any{"convId": conv, "quarantine": quarantine})
		expect(t, fmt.Sprintf("body %s quarantine=%v", conv, quarantine), r, 200, 0)
		var page struct {
			Messages []struct {
				MsgID string          `json:"msgId"`
				Body  json.RawMessage `json:"body"`
			} `json:"messages"`
			HasMore bool `json:"hasMore"`
		}
		if err := json.Unmarshal([]byte(r.raw), &page); err != nil {
			t.Fatal(err)
		}
		if page.HasMore {
			t.Fatalf("body page of %s has more: %s", conv, r.raw)
		}
		out := map[string]string{}
		for _, m := range page.Messages {
			out[m.MsgID] = string(m.Body)
		}
		return out, r.raw
	}
	fetch := func(conv, fileID, msgID, variant string) [32]byte {
		t.Helper()
		r := mod.do("POST", "/console/api/files/"+fileID+"/fetch", map[string]any{"convId": conv, "msgId": msgID, "variant": variant})
		if r.status != 200 {
			t.Fatalf("fetch %s %s: %d %s", conv, variant, r.status, r.raw)
		}
		return sha256.Sum256([]byte(r.raw))
	}
	view := func(conv, fileID, msgID string) adminView {
		t.Helper()
		v := adminView{meta: map[string]bool{}}
		q := map[string]any{"convId": conv}
		if strings.HasPrefix(conv, "c2c:") {
			q["reason"] = goodReason // 单聊元数据每次重新打开都填理由
		}
		r := kf.do("POST", "/console/api/messages/meta/query", q)
		expect(t, "meta "+conv, r, 200, 0)
		if more, _ := r.body["hasMore"].(bool); more {
			t.Fatalf("meta of %s has more: %s", conv, r.raw)
		}
		for id, m := range metaByID(t, r) {
			v.meta[id] = true
			v.metaSeqs = append(v.metaSeqs, int64(m["seq"].(float64)))
		}
		slices.Sort(v.metaSeqs)
		var rawBody, rawQ string
		v.body, rawBody = read(conv, false)
		v.quarantine, rawQ = read(conv, true)
		v.photo, v.thumb = fetch(conv, fileID, msgID, "original"), fetch(conv, fileID, msgID, "thumb")
		v.raws = append(v.raws, r.raw, rawBody, rawQ)
		return v
	}
	userConvIDs := func() (map[string]bool, string) {
		t.Helper()
		r := userConvsQuery(kf, u1, userConvsReason, "")
		expect(t, "user convs", r, 200, 0)
		out := map[string]bool{}
		list, _ := r.body["convs"].([]any)
		for _, c := range list {
			out[c.(map[string]any)["convId"].(string)] = true
		}
		return out, r.raw
	}

	// 删除前的基线。
	beforeC2C := view(c2c, c2cFile, c2cIDs[8])
	beforeGroup := view(g1, gFile, gImg)
	beforeConvs, _ := userConvIDs()
	if len(beforeC2C.metaSeqs) != 10 || beforeC2C.metaSeqs[0] != 1 || beforeC2C.metaSeqs[9] != 10 {
		t.Fatalf("c2c meta before = %v", beforeC2C.metaSeqs)
	}
	for _, conv := range []string{c2c, g1, g2} {
		if !beforeConvs[conv] {
			t.Fatalf("%s missing from the user convs before deleting: %v", conv, beforeConvs)
		}
	}

	// u1：g1 置顶 + 免打扰后删除（删除清置顶、留免打扰），单聊免打扰后删除，g2 置顶 + 免打扰（不删）。
	for _, s := range []struct {
		conv string
		set  map[string]any
	}{{g1, map[string]any{"pinned": true, "notifyOff": true}}, {c2c, map[string]any{"notifyOff": true}}, {g2, map[string]any{"pinned": true, "notifyOff": true}}} {
		s.set["convId"] = s.conv
		c1.cmd("convSet", s.set)
	}
	if got := c1.cmd("convDelete", map[string]any{"convId": c2c, "upToSeq": 10}); got["clearedSeq"] != float64(10) {
		t.Fatalf("convDelete c2c = %v", got)
	}
	gMax := beforeGroup.metaSeqs[len(beforeGroup.metaSeqs)-1]
	if got := c1.cmd("convDelete", map[string]any{"convId": g1, "upToSeq": gMax}); got["clearedSeq"] != float64(gMax) {
		t.Fatalf("convDelete g1 = %v (max seq %d)", got, gMax)
	}

	// u1 这边确实删掉了：convs 里没有、deleted 里有；sync 空（否则下面的"照常"说明不了什么）。
	convs := c1.cmd("convs", map[string]any{})
	rawConvs, _ := json.Marshal(convs)
	deleted := map[string]float64{}
	if list, _ := convs["deleted"].([]any); list != nil {
		for _, d := range list {
			m := d.(map[string]any)
			deleted[m["convId"].(string)] = m["clearedSeq"].(float64)
		}
	}
	if deleted[c2c] != 10 || deleted[g1] != float64(gMax) {
		t.Fatalf("u1 convs.deleted = %v", deleted)
	}
	for _, c := range convs["convs"].([]any) {
		if id := c.(map[string]any)["convId"]; id == c2c || id == g1 {
			t.Fatalf("u1 still lists %v: %s", id, rawConvs)
		}
	}
	for _, conv := range []string{c2c, g1} {
		if msgs, _ := c1.cmd("sync", map[string]any{"convId": conv, "afterSeq": 0})["messages"].([]any); len(msgs) != 0 {
			t.Fatalf("u1 sync %s after deleting = %v", conv, msgs)
		}
	}

	// 删除后：后台看到的和删除前完全一样。
	auditBefore := len(w.auditRows(`action = 'msg.read.page' AND phase = 'result' AND result = 'success'`))
	fetchesBefore := len(w.auditRows(`action = $1 AND phase = 'result' AND result = 'success'`, "msg.file.fetch"))
	afterC2C := view(c2c, c2cFile, c2cIDs[8])
	afterGroup := view(g1, gFile, gImg)
	afterConvs, rawUserConvs := userConvIDs()
	for _, tc := range []struct {
		name          string
		before, after adminView
		ids           []string
		photo, thumb  []byte
	}{{"c2c", beforeC2C, afterC2C, c2cIDs, c2cPhoto, c2cThumb}, {"group", beforeGroup, afterGroup, groupIDs, gPhoto, gThumb}} {
		b, a := tc.before, tc.after
		if !slices.Equal(a.metaSeqs, b.metaSeqs) {
			t.Errorf("%s meta seqs after deleting = %v, before %v", tc.name, a.metaSeqs, b.metaSeqs)
		}
		for _, id := range tc.ids {
			if !a.meta[id] {
				t.Errorf("%s meta lost %s after deleting", tc.name, id)
			}
			if _, ok := a.body[id]; !ok {
				t.Errorf("%s body page lost %s after deleting", tc.name, id)
			}
		}
		if len(a.body) != len(b.body) || len(a.quarantine) != len(b.quarantine) || len(a.quarantine) == 0 {
			t.Errorf("%s body / quarantine after deleting = %d / %d, before %d / %d", tc.name, len(a.body), len(a.quarantine), len(b.body), len(b.quarantine))
		}
		for id, body := range b.body {
			if a.body[id] != body {
				t.Errorf("%s body of %s changed: %s → %s", tc.name, id, body, a.body[id])
			}
		}
		for id, body := range b.quarantine {
			if a.quarantine[id] != body {
				t.Errorf("%s quarantine of %s changed: %s → %s", tc.name, id, body, a.quarantine[id])
			}
		}
		if a.photo != sha256.Sum256(tc.photo) || a.thumb != sha256.Sum256(tc.thumb) {
			t.Errorf("%s recalled image via console changed after deleting", tc.name)
		}
	}
	if n := len(afterC2C.meta); n != 10 {
		t.Errorf("c2c meta after deleting = %d messages, want 10", n)
	}
	if !strings.Contains(afterC2C.body[c2cIDs[2]], mark) {
		t.Errorf("c2c message 3 body after deleting = %s", afterC2C.body[c2cIDs[2]])
	}
	if !strings.Contains(afterGroup.quarantine[recalledText], mark) {
		t.Errorf("recalled group text in the quarantine page = %s", afterGroup.quarantine[recalledText])
	}
	for _, conv := range []string{c2c, g1, g2} {
		if !afterConvs[conv] {
			t.Errorf("%s missing from the admin user convs after deleting: %s", conv, rawUserConvs)
		}
	}
	// console 审计照写（2 个会话 × 普通、隔离 = 4 页；4 次取文件）。
	if n := len(w.auditRows(`action = 'msg.read.page' AND phase = 'result' AND result = 'success'`)) - auditBefore; n != 4 {
		t.Errorf("msg.read.page audit after deleting = %d, want 4", n)
	}
	if n := len(w.auditRows(`action = $1 AND phase = 'result' AND result = 'success'`, "msg.file.fetch")) - fetchesBefore; n != 4 {
		t.Errorf("file fetch audit after deleting = %d, want 4", n)
	}

	// u1 的置顶、免打扰、清除位置不出现在用户详情、元数据、正文页、用户会话列表（第 14.1 节没有列）。
	ud := kf.do("GET", "/console/api/users/"+u1, nil)
	expect(t, "user detail", ud, 200, 0)
	g2Meta := kf.do("POST", "/console/api/messages/meta/query", map[string]any{"convId": g2})
	expect(t, "meta g2", g2Meta, 200, 0)
	raws := append([]string{ud.raw, g2Meta.raw, rawUserConvs}, afterC2C.raws...)
	raws = append(raws, afterGroup.raws...)
	for _, raw := range raws {
		for _, leak := range []string{`"pinned`, `"notifyOff"`, `"clearedSeq"`} {
			if strings.Contains(raw, leak) {
				t.Errorf("conversation settings leaked (%s): %.300s", leak, raw)
			}
		}
	}
}
