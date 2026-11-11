package e2e

// C6（CS-206～CS-208）e2e 的公共设施：真实 im-server（IM_MOD_ENABLED=1、IM_V13_ADMIN_FEATURES=1、IM_MSG_ACTIONS_ENABLED=1、
// IM_FILES_ENABLED=1 + 假 S3）+ 真实 Postgres。主凭证 console 带 moderation.words、report.read、report.handle，
// console-msgread 带 report.evidence（e2e_test.go 的 startIMProc）。
// **只用特征词和特征串**（PRD-chat F-MOD-01 规则 5）：ZXQWORD、ZXQ-*。本地结果，CI 不运行。

import (
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
)

// modReportKey 是测试用的 IM_REPORT_KEY：解码后是一眼就能看出是假的 32 字节；modReportKey2 用来造"换了一把密钥"（AC-MOD-04-14）。
var (
	modReportKey  = base64.StdEncoding.EncodeToString([]byte("fake-report-key-for-console-e2e!"))
	modReportKey2 = base64.StdEncoding.EncodeToString([]byte("fake-report-key-for-console-e2e2"))
)

// newModWorld：撤回、文件、后台第二批、敏感词和举报都打开。[C 钟] 从真实时间前 lead 开始（同 newRecallWorld）：
// 证据授权的到期时间是 im-server 的真实时间，console 先拿自己的钟比一次。extra 是额外的 im-server 环境变量（后面的覆盖前面的）。
func newModWorld(t *testing.T, lead time.Duration, extra ...string) *inviteWorld {
	t.Helper()
	s3 := newFakeS3(t)
	env := append(s3.env(), "IM_TRUSTED_PROXIES=127.0.0.1/32,::1/128", "IM_MSG_ACTIONS_ENABLED=1", "IM_QUARANTINE_KEY="+rclQuarantineKey,
		"IM_MOD_ENABLED=1", "IM_REPORT_KEY="+modReportKey)
	env = append(env, extra...)
	p := startIMProc(t, allConsoleScopes, env...)
	w := &inviteWorld{bizWorld: newBizWorldWith(t, p.admin, p.ws, p.key), proc: p}
	w.realClock(lead)
	return w
}

// restartIM 用同一个库、同样的地址重启 im-server，kv 是要改的环境变量（追加在后面，覆盖原来的值）。
func (w *inviteWorld) restartIM(kv ...string) {
	w.t.Helper()
	_ = w.proc.cmd.Process.Kill()
	<-w.proc.exited
	w.proc.env = append(w.proc.env, kv...)
	w.proc.start()
}

// report 发 cmd=report（F-MOD-03 规则 1），返回 reportId。
func (c *wsClient) report(data map[string]any) string {
	c.t.Helper()
	d := c.cmd("report", data)
	id, _ := d["reportId"].(string)
	if id == "" {
		c.t.Fatalf("report: %v", d)
	}
	return id
}

// reportMsg 举报一条消息；note 为空时不带。
func (c *wsClient) reportMsg(conv, msgID, reason, note string) string {
	c.t.Helper()
	d := map[string]any{"targetType": "message", "convId": conv, "msgIds": []string{msgID}, "reason": reason}
	if note != "" {
		d["note"] = note
	}
	return c.report(d)
}

// reportUser 举报一个用户。
func (c *wsClient) reportUser(uid, reason, note string) string {
	c.t.Helper()
	d := map[string]any{"targetType": "user", "userId": uid, "reason": reason}
	if note != "" {
		d["note"] = note
	}
	return c.report(d)
}

// markRead 标记已读到 seq（举报撤回的消息要 readSeq ≥ seq，F-MOD-03 规则 2a）。
func (c *wsClient) markRead(conv string, seq int64) {
	c.t.Helper()
	c.cmd("read", map[string]any{"convId": conv, "seq": seq})
}

func seqOf(t *testing.T, ack map[string]any) int64 {
	t.Helper()
	d, _ := ack["data"].(map[string]any)
	s, _ := d["seq"].(float64)
	if s <= 0 {
		t.Fatalf("send: %v", ack)
	}
	return int64(s)
}

// keysWithin：m 的键都在 allowed 里（console 是白名单结构，不透传 im-server 多返回的字段）。
func keysWithin(t *testing.T, label string, m map[string]any, allowed ...string) {
	t.Helper()
	for k := range m {
		if !slices.Contains(allowed, k) {
			t.Errorf("%s has field %q: %v", label, k, m)
		}
	}
}

// asMap、asList 把 JSON 解出来的值转成 map、列表，类型不对时失败。
func asMap(t *testing.T, label string, v any) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("%s is not an object: %v", label, v)
	}
	return m
}

func asList(t *testing.T, label string, v any) []any {
	t.Helper()
	l, ok := v.([]any)
	if !ok {
		t.Fatalf("%s is not a list: %v", label, v)
	}
	return l
}

// injectFields 往 im-server 的 JSON 响应里加字段（顶层和 listKey 下每一行），模拟 im-server 以后多返回的东西。
func injectFields(body []byte, listKey string, extra map[string]any) []byte {
	var top map[string]any
	if json.Unmarshal(body, &top) != nil {
		return body
	}
	for k, v := range extra {
		top[k] = v
	}
	if listKey != "" {
		if rows, ok := top[listKey].([]any); ok {
			for _, r := range rows {
				if m, ok := r.(map[string]any); ok {
					for k, v := range extra {
						m[k] = v
					}
				}
			}
		}
	}
	out, _ := json.Marshal(top)
	return out
}

// evidenceGrant 申请这条举报的证据授权（理由 + 当次动态码，每次换一个 TOTP 步长）。
func (w *inviteWorld) evidenceGrant(u *user, reportID string) reply {
	w.t.Helper()
	w.tick()
	return u.do("POST", "/console/api/reports/"+reportID+"/evidence-grant", map[string]any{"reason": "evidence review", "otp": u.otp()})
}

// callsWithPrefix 是路径以 prefix 开头的 im-server 调用。
func (p *imProxy) callsWithPrefix(prefix string) []imCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []imCall
	for _, c := range p.calls {
		if strings.HasPrefix(c.Path, prefix) {
			out = append(out, c)
		}
	}
	return out
}

// total 是到现在为止的调用次数。
func (p *imProxy) total() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.calls)
}

func fnum(v any) int64 {
	f, _ := v.(float64)
	return int64(f)
}
