package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"tianting/console/internal/imclient"
	"tianting/console/internal/pushtpl"
)

const (
	pushLegacyKey = "tianting-e2e-push-legacy-key-0123456789"
	pushApprove   = "全员发送"
)

// pushWorld：console + 代理 + 真实 im-server（测试模式），[C 钟] 和 [IM 钟] 一起走。
// 对账按 [C 钟] 算时间窗去查 im-server 审计，两边的钟必须一致。
type pushWorld struct {
	*bizWorld
	proc *imProc
}

func newPushWorld(t *testing.T) *pushWorld {
	t.Helper()
	proc := startIMProc(t, allConsoleScopes, "IM_TEST_MODE=1", "IM_ADMIN_KEY="+pushLegacyKey, "IM_JWT_SECRET=tianting-e2e-push-jwt-secret-0123456789", "IM_TEST_DISABLE_JOBS=push_purge")
	b := newBizWorldWith(t, proc.admin, proc.ws, proc.key)
	w := &pushWorld{bizWorld: b, proc: proc}
	// 签名时间戳用 [C 钟]，和测试模式的 console 一样；故障注入只在这个客户端上开。
	im, err := imclient.New(imclient.Config{BaseURL: b.im.srv.URL, Caller: "console", Key: proc.key, Clock: b.a.Clock, Timeout: 3 * time.Second, Latency: &b.a.IMLatencyMs, DropResponse: &b.a.IMDropResponse})
	if err != nil {
		t.Fatal(err)
	}
	b.a.IM = im
	if b.sys, err = imclient.New(imclient.Config{BaseURL: "http://" + proc.admin, Caller: "console", Key: proc.key, Clock: b.a.Clock}); err != nil {
		t.Fatal(err)
	}
	b.onClock = w.syncIMClock
	w.syncIMClock(b.now)
	return w
}

func (w *pushWorld) imTest(path string, body any) {
	w.t.Helper()
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", "http://"+w.proc.admin+path, strings.NewReader(string(raw)))
	if err != nil {
		w.t.Fatal(err)
	}
	req.Header.Set("X-Admin-Key", pushLegacyKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		w.t.Fatalf("%s: %v", path, err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		w.t.Fatalf("%s = %d", path, resp.StatusCode)
	}
}

func (w *pushWorld) syncIMClock(now time.Time) {
	w.t.Helper()
	w.imTest("/admin/test/clock", map[string]any{"nowMs": now.UnixMilli()})
}

// settle 推进到对账能看到这条 intent（超过 5 分钟）。
func (w *pushWorld) settle() {
	w.t.Helper()
	w.advance(5*time.Minute + time.Second)
}

func (w *pushWorld) reconcile() {
	w.t.Helper()
	if err := w.a.Reconcile(context.Background()); err != nil {
		w.t.Fatalf("reconcile: %v", err)
	}
}

// pushRow 是 biz.push_records 的一行。
type pushRow struct {
	ID, Kind, Type, Data, Sha, Status, PushID, RequestID, CreatedBy string
	ApprovedBy                                                      *string
	SentAt                                                          int64
	ErrorCode                                                       int
	Created, ReplayCreated                                          *bool
	ReplayRequestID                                                 *string
	ReplayExpired                                                   bool
}

// pushRecord 按通知内容里的标记找一行。
func (w *pushWorld) pushRecord(marker string) pushRow {
	w.t.Helper()
	ctx := context.Background()
	c, err := pgx.Connect(ctx, w.owner)
	if err != nil {
		w.t.Fatal(err)
	}
	defer c.Close(ctx)
	var r pushRow
	err = c.QueryRow(ctx, `SELECT id::text, kind, type, data, data_sha256, status, im_push_id, request_id, created_by_name, approved_by_name, sent_at, error_code, im_created, replay_created, replay_request_id, replay_expired
		FROM biz.push_records WHERE position($1 in data) > 0`, marker).Scan(&r.ID, &r.Kind, &r.Type, &r.Data, &r.Sha, &r.Status, &r.PushID, &r.RequestID, &r.CreatedBy, &r.ApprovedBy, &r.SentAt, &r.ErrorCode, &r.Created, &r.ReplayCreated, &r.ReplayRequestID, &r.ReplayExpired)
	if err != nil {
		w.t.Fatalf("record %s: %v", marker, err)
	}
	return r
}

// imPushes 数 console 发给 im-server 的 POST /admin/push。
func (w *pushWorld) imPushes() int { return w.im.count("POST", "/admin/push") }

func notice(marker string) map[string]any {
	return map[string]any{"title": "系统公告", "text": marker}
}

// waitPush 等一个 push 帧。
func (c *wsClient) waitPush() map[string]any {
	c.t.Helper()
	return c.wait("push")["data"].(map[string]any)
}

// noPush 确认一段时间内没有 push 帧。
func (c *wsClient) noPush(label string) {
	c.t.Helper()
	deadline := time.After(300 * time.Millisecond)
	for {
		select {
		case f, ok := <-c.in:
			if !ok {
				return
			}
			if f["cmd"] == "push" {
				c.t.Errorf("%s: unexpected push frame %v", label, f)
			}
		case <-deadline:
			return
		}
	}
}

// pushSync 走协议的 pushSync，返回 pushes。
func (c *wsClient) pushSync(afterSeq int) []any {
	c.t.Helper()
	id := fmt.Sprintf("s%d", time.Now().UnixNano())
	req, _ := json.Marshal(map[string]any{"id": id, "cmd": "pushSync", "data": map[string]any{"afterSeq": afterSeq, "limit": 50}})
	if err := c.ws.Write(context.Background(), 1, req); err != nil {
		c.t.Fatal(err)
	}
	for {
		f := c.wait("ack")
		if f["id"] != id {
			continue
		}
		if f["error"] != nil {
			c.t.Fatalf("pushSync: %v", f)
		}
		d := f["data"].(map[string]any)
		list, _ := d["pushes"].([]any)
		return list
	}
}

// draft 让运营建一份全员草稿，返回草稿 ID。
func draft(t *testing.T, op *user, data map[string]any) string {
	t.Helper()
	r := op.do("POST", "/console/api/push/all/drafts", map[string]any{"type": "notice", "data": data, "reason": "全员通知复核"})
	expect(t, "draft", r, 200, 0)
	return r.str("draftId")
}

func approve(c *user, id string) reply {
	c.stepUp()
	return c.do("POST", "/console/api/push/all/drafts/"+id+"/approve", map[string]any{"confirmText": pushApprove})
}

func sha256Text(s string) string { return shaHex([]byte(s)) }

// newPushWorldTemplates 用指定的模板文件。
func newPushWorldTemplates(t *testing.T, templates string) *pushWorld {
	t.Helper()
	path := t.TempDir() + "/templates.json"
	if err := os.WriteFile(path, []byte(templates), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := pushtpl.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	w := newPushWorld(t)
	w.a.Cfg.PushTemplates = set
	return w
}
