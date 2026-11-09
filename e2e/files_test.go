package e2e

// CS-201：元数据和正文接口配合文件消息（PRD-chat 第 14.1 节，R-CS-14，TC-FILE-91-01 / AC-ADM-30-7 的 C2 扩展）。
// 真实 im-server（IM_FILES_ENABLED=1）+ 假 S3（fakes3_test.go）+ 真实 Postgres。

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func newFilesWorld(t *testing.T) *inviteWorld {
	t.Helper()
	s3 := newFakeS3(t)
	env := append(s3.env(), "IM_TRUSTED_PROXIES=127.0.0.1/32,::1/128")
	p := startIMProc(t, allConsoleScopes, env...)
	return &inviteWorld{bizWorld: newBizWorldWith(t, p.admin, p.ws, p.key), proc: p}
}

func (w *inviteWorld) userToken(uid string) string {
	w.t.Helper()
	var tok struct {
		Token string `json:"token"`
	}
	if err := w.sysDo("POST", "/admin/users/token", map[string]any{"userId": uid}, &tok); err != nil {
		w.t.Fatal(err)
	}
	return tok.Token
}

// upload 走 /v1/files/uploads、PUT、complete（F-FILE-01），返回 fileId。
func (w *inviteWorld) upload(token, kind, name string, data []byte, mime string, thumb []byte) string {
	w.t.Helper()
	req := map[string]any{"kind": kind, "name": name, "size": len(data), "mime": mime}
	if thumb != nil {
		req["thumb"] = map[string]any{"size": len(thumb), "mime": "image/png"}
	}
	code, m, raw := w.imPost("/v1/files/uploads", token, req)
	if code != 200 {
		w.t.Fatalf("uploads: %d %s", code, raw)
	}
	put := func(p map[string]any, body []byte) {
		r, _ := http.NewRequest(http.MethodPut, p["url"].(string), bytes.NewReader(body))
		if hs, ok := p["headers"].(map[string]any); ok {
			for k, v := range hs {
				if !strings.EqualFold(k, "content-length") && !strings.EqualFold(k, "host") {
					r.Header.Set(k, fmt.Sprint(v))
				}
			}
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil || resp.StatusCode != 200 {
			w.t.Fatalf("put: %v %v", err, resp)
		}
		_ = resp.Body.Close()
	}
	put(m["put"].(map[string]any), data)
	if thumb != nil {
		put(m["thumbPut"].(map[string]any), thumb)
	}
	id := m["fileId"].(string)
	if code, _, raw := w.imPost("/v1/files/"+id+"/complete", token, map[string]any{}); code != 200 {
		w.t.Fatalf("complete: %d %s", code, raw)
	}
	return id
}

// sendAttachment 发一条 image / file 消息，等 ack。
func (c *wsClient) sendAttachment(to, typ string, body map[string]any) map[string]any {
	c.t.Helper()
	id := fmt.Sprintf("f%d", time.Now().UnixNano())
	convType, target, _ := strings.Cut(to, ":")
	req, _ := json.Marshal(map[string]any{"id": id, "cmd": "send", "data": map[string]any{"convType": convType, "to": target, "type": typ, "body": body, "clientMsgId": id}})
	if err := c.ws.Write(context.Background(), websocket.MessageText, req); err != nil {
		c.t.Fatal(err)
	}
	for {
		if f := c.wait("ack"); f["id"] == id {
			return f
		}
	}
}

func pngBytes(w, h int) []byte {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for x := range w {
		for y := range h {
			img.Set(x, y, color.RGBA{uint8(x), uint8(y), 99, 255})
		}
	}
	var b bytes.Buffer
	_ = png.Encode(&b, img)
	return b.Bytes()
}

// TC-FILE-91-01（AC-ADM-30-7 的 C2 扩展）：客服的元数据查询两层响应都搜不到文件名，只有类型和大小；
// 有正文授权的正文接口有文件名（后台版序列化能处理 image、file）；两边审计、console 库、两边日志搜不到文件名。
func TestTC_FILE_91_01_MetaHasNoFileName(t *testing.T) {
	const mark = "ZXQ-FILE-META"
	w := newFilesWorld(t)
	super := w.super("adm9")
	kf := super.create("kf9", "support")
	mod := super.create("mod9", "moderator")
	p := uniq("fm")
	u1, u2 := p+"a", p+"b"
	w.users(u1, u2)
	g := w.group(u1, u2)
	conv := "group:" + g
	tok := w.userToken(u1)
	fileName := mark + "-季度报告.pdf"
	pdf := append([]byte("%PDF-1.4\n"), bytes.Repeat([]byte{7}, 4096)...)
	fileID := w.upload(tok, "file", fileName, pdf, "application/pdf", nil)
	photo := pngBytes(64, 48)
	imgID := w.upload(tok, "image", mark+"-photo.png", photo, "image/png", pngBytes(32, 24))
	c := w.dial(u1, "web")
	if f := c.sendAttachment(conv, "file", map[string]any{"file": map[string]any{"fileId": fileID}}); f["error"] != nil {
		t.Fatalf("send file: %v", f)
	}
	if f := c.sendAttachment(conv, "image", map[string]any{"image": map[string]any{"fileId": imgID}}); f["error"] != nil {
		t.Fatalf("send image: %v", f)
	}
	sendText(t, w.bizWorld, u2, g, "after the files")

	// 1. 元数据：console 的响应和它调用 im-server 拿到的响应都没有文件名，也没有 body 字段；类型和长度照常。
	before := len(w.im.find("POST", "/admin/convs/messages/query"))
	r := kf.do("POST", "/console/api/messages/meta/query", map[string]any{"convId": conv})
	expect(t, "meta", r, 200, 0)
	if len(w.im.find("POST", "/admin/convs/messages/query")) != before+1 {
		t.Fatal("meta query did not reach im-server")
	}
	if strings.Contains(r.raw, mark) || strings.Contains(r.raw, `"body"`) || strings.Contains(r.raw, fileID) {
		t.Errorf("file name or body in the console response: %s", r.raw)
	}
	if strings.Contains(w.im.dump(), mark) {
		t.Error("file name in the im-server meta response")
	}
	types := map[string]map[string]any{}
	for _, m := range r.body["messages"].([]any) {
		mm := m.(map[string]any)
		types[mm["type"].(string)] = mm
	}
	for _, typ := range []string{"file", "image", "text"} {
		m := types[typ]
		if m == nil {
			t.Fatalf("no %s message in meta: %s", typ, r.raw)
		}
		if n, _ := m["bodyLength"].(float64); n <= 0 {
			t.Errorf("%s bodyLength = %v", typ, m["bodyLength"])
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		for _, k := range keys {
			if k == "fileSize" && typ != "text" {
				continue // 图片、文件的原文件字节数（PRD-chat v1.4 第 14.1 节，P-37 ③）
			}
			if k != "seq" && k != "msgId" && k != "from" && k != "type" && k != "bodyLength" && k != "ts" {
				t.Errorf("%s meta has field %q", typ, k)
			}
		}
	}
	// v1.4：console 透传 im-server 的 fileSize（原文件字节数，不含缩略图）；文本消息没有。
	if n, _ := types["file"]["fileSize"].(float64); n != float64(len(pdf)) {
		t.Errorf("file fileSize = %v, want %d", types["file"]["fileSize"], len(pdf))
	}
	if n, _ := types["image"]["fileSize"].(float64); n != float64(len(photo)) {
		t.Errorf("image fileSize = %v, want %d", types["image"]["fileSize"], len(photo))
	}
	if _, has := types["text"]["fileSize"]; has {
		t.Errorf("text meta has fileSize: %v", types["text"])
	}

	// 2. 正文（msg.read.group，授权后）：文件消息带文件名和大小，图片带类型和宽高。
	mod.stepUp()
	w.tick()
	g1 := mod.do("POST", "/console/api/messages/grants", map[string]any{"convId": conv, "ticket": "T-201", "reason": "file review", "otp": mod.otp()})
	expect(t, "grant", g1, 200, 0)
	body := mod.do("POST", "/console/api/messages/body", map[string]any{"convId": conv})
	expect(t, "body", body, 200, 0)
	var got struct {
		Messages []struct {
			Type string         `json:"type"`
			Body map[string]any `json:"body"`
		} `json:"messages"`
	}
	if err := json.Unmarshal([]byte(body.raw), &got); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, m := range got.Messages {
		switch m.Type {
		case "file":
			f, _ := m.Body["file"].(map[string]any)
			if f["name"] != fileName || f["size"] != float64(len(pdf)) || f["mime"] != "application/pdf" {
				t.Errorf("file body = %v", m.Body)
			}
			seen["file"] = true
		case "image":
			i, _ := m.Body["image"].(map[string]any)
			if i["mime"] != "image/png" || i["width"] != float64(64) || i["height"] != float64(48) {
				t.Errorf("image body = %v", m.Body)
			}
			if _, has := i["name"]; has {
				t.Errorf("image body has a name: %v", m.Body)
			}
			seen["image"] = true
		}
	}
	if !seen["file"] || !seen["image"] {
		t.Fatalf("body page = %s", body.raw)
	}
	if body.header.Get("Cache-Control") != "no-store" {
		t.Error("body page is cacheable")
	}

	// 3. 文件名不进审计（两边）、console 库和两边日志。
	for _, where := range []string{"msg.meta.query", "msg.read.grant", "msg.read.page"} {
		rows := w.auditRows(`action = $1`, where)
		if len(rows) == 0 {
			t.Errorf("no %s audit", where)
		}
		for _, row := range rows {
			if strings.Contains(fmt.Sprint(row), mark) {
				t.Errorf("%s audit has the file name: %v", where, row)
			}
		}
	}
	if strings.Contains(w.dumpDB(), mark) {
		t.Error("file name in the console database")
	}
	if a := w.imAuditDump(); strings.Contains(a, mark) {
		t.Error("file name in the im-server audit")
	} else if !strings.Contains(a, "/admin/convs/messages/body") {
		t.Error("im-server audit has no body read")
	}
	if strings.Contains(w.logs.String(), mark) || strings.Contains(w.proc.logs.String(), mark) {
		t.Error("file name in the logs")
	}
}
