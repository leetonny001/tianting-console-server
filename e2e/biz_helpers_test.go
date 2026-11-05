package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"tianting/console/internal/clock"
	"tianting/console/internal/imclient"
)

// imCall 是 console 发给 im-server 的一次请求。
type imCall struct {
	Method, Path, RequestID, Body string
}

// imProxy 夹在 console 和真实 im-server 之间：记录请求和响应，可以注入失败。签名不含 Host，转发不影响校验。
type imProxy struct {
	srv     *httptest.Server
	mu      sync.Mutex
	calls   []imCall
	replies []string
	// inject 返回非 0 时不转发，直接回这个错误码。
	inject func(c imCall) int
	// delay 是收到 im-server 响应之后再等多久：请求已经执行，console 却等不到结果。
	delay time.Duration
}

func newIMProxy(t *testing.T, adminAddr string) *imProxy {
	target, _ := url.Parse("http://" + adminAddr)
	p := &imProxy{}
	rp := httputil.NewSingleHostReverseProxy(target)
	// im-server 中途退出：console 看到的是连接断开，不是一个 502（直连时就是这样）。
	rp.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		if conn, _, err := http.NewResponseController(w).Hijack(); err == nil {
			_ = conn.Close()
		}
	}
	rp.ModifyResponse = func(r *http.Response) error {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			return err
		}
		r.Body = io.NopCloser(bytes.NewReader(data))
		p.mu.Lock()
		p.replies = append(p.replies, string(data))
		delay := p.delay
		p.mu.Unlock()
		if delay > 0 {
			time.Sleep(delay)
		}
		return nil
	}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		c := imCall{r.Method, r.URL.Path, r.Header.Get("X-Request-Id"), string(body)}
		p.mu.Lock()
		p.calls = append(p.calls, c)
		inject := p.inject
		p.mu.Unlock()
		if inject != nil {
			if code := inject(c); code != 0 {
				w.WriteHeader(code / 10)
				fmt.Fprintf(w, `{"code":%d,"msg":"injected"}`, code)
				return
			}
		}
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(p.srv.Close)
	return p
}

// count 数匹配的调用。
func (p *imProxy) count(method, path string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, c := range p.calls {
		if c.Method == method && c.Path == path {
			n++
		}
	}
	return n
}

func (p *imProxy) find(method, path string) []imCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []imCall
	for _, c := range p.calls {
		if c.Method == method && c.Path == path {
			out = append(out, c)
		}
	}
	return out
}

func (p *imProxy) dump() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return strings.Join(p.replies, "\n")
}

// bizWorld 是 console + 代理 + 真实 im-server。
type bizWorld struct {
	*world
	key ed25519.PrivateKey
	im  *imProxy
	sys *imclient.Client // 测试自己用：造数据、签 token
	ws  string
}

func newBizWorld(t *testing.T) *bizWorld {
	t.Helper()
	admin, ws, priv := startRealIMWS(t)
	return newBizWorldWith(t, admin, ws, priv)
}

func newBizWorldWith(t *testing.T, admin, ws string, priv ed25519.PrivateKey) *bizWorld {
	t.Helper()
	proxy := newIMProxy(t, admin)
	w := newWorld(t, map[string]string{"CON_IM_ADMIN_URL": proxy.srv.URL, "CON_IM_SIGNING_KEY": base64.StdEncoding.EncodeToString(priv.Seed()), "CON_IM_MSGREAD_KEY": base64.StdEncoding.EncodeToString(msgReadKey.Seed()), "CON_PUSH_TEMPLATES": "../deploy/push-templates.example.json"})
	// [C 钟] 被冻结在 2027 年并手动推进；签名时间戳要和 im-server 的真实时钟一致。
	real, err := imclient.New(imclient.Config{BaseURL: proxy.srv.URL, Caller: "console", Key: priv, Clock: clock.New()})
	if err != nil {
		t.Fatal(err)
	}
	w.a.IM = real
	if w.a.MsgRead, err = imclient.New(imclient.Config{BaseURL: proxy.srv.URL, Caller: "console-msgread", Key: msgReadKey, Clock: clock.New()}); err != nil {
		t.Fatal(err)
	}
	sys, err := imclient.New(imclient.Config{BaseURL: "http://" + admin, Caller: "console", Key: priv})
	if err != nil {
		t.Fatal(err)
	}
	return &bizWorld{world: w, im: proxy, sys: sys, ws: ws, key: priv}
}

var sysSeq struct {
	sync.Mutex
	n int
}

func (b *bizWorld) sysDo(method, path string, in, out any) error {
	sysSeq.Lock()
	sysSeq.n++
	id := fmt.Sprintf("sys-%d", sysSeq.n)
	sysSeq.Unlock()
	return b.sys.Do(context.Background(), imclient.Call{Operator: "test", RequestID: id}, method, path, nil, in, out)
}

// users 导入一批用户（昵称可选：id 或 id=昵称）。
func (b *bizWorld) users(ids ...string) {
	b.t.Helper()
	for _, batch := range chunkStrings(ids, 500) {
		list := make([]map[string]any, 0, len(batch))
		for _, id := range batch {
			u := map[string]any{"userId": id}
			if name, nick, ok := strings.Cut(id, "="); ok {
				u = map[string]any{"userId": name, "nickname": nick}
			}
			list = append(list, u)
		}
		if err := b.sysDo("POST", "/admin/users/import", map[string]any{"users": list}, nil); err != nil {
			b.t.Fatal(err)
		}
	}
}

func chunkStrings(in []string, n int) [][]string {
	var out [][]string
	for len(in) > n {
		out = append(out, in[:n])
		in = in[n:]
	}
	return append(out, in)
}

func numbered(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s%04d", prefix, i)
	}
	return out
}

// wsClient 是真实的客户端连接。
type wsClient struct {
	t  *testing.T
	ws *websocket.Conn
	in chan map[string]any
	// closeStatus 在 in 关闭之前写好。
	closeStatus websocket.StatusCode
}

func (b *bizWorld) dial(uid, platform string) *wsClient {
	b.t.Helper()
	var tok struct {
		Token string `json:"token"`
	}
	if err := b.sysDo("POST", "/admin/users/token", map[string]any{"userId": uid}, &tok); err != nil {
		b.t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws://"+b.ws+"/ws?platform="+platform, nil)
	if err != nil {
		b.t.Fatal(err)
	}
	ws.SetReadLimit(16 << 20)
	c := &wsClient{t: b.t, ws: ws, in: make(chan map[string]any, 256)}
	b.t.Cleanup(func() { _ = ws.CloseNow() })
	go func() {
		defer close(c.in)
		for {
			_, data, err := ws.Read(context.Background())
			if err != nil {
				c.closeStatus = websocket.CloseStatus(err)
				return
			}
			var f map[string]any
			if json.Unmarshal(data, &f) == nil {
				c.in <- f
			}
		}
	}()
	auth, _ := json.Marshal(map[string]any{"id": "auth", "cmd": "auth", "data": map[string]any{"token": tok.Token}})
	if err := ws.Write(ctx, websocket.MessageText, auth); err != nil {
		b.t.Fatal(err)
	}
	f := c.wait("ack")
	if f["error"] != nil {
		b.t.Fatalf("auth: %v", f)
	}
	return c
}

// send 发一条文本消息，等 ack。发送限流（4290）时等一下再发。
func (c *wsClient) send(to, text string) map[string]any {
	c.t.Helper()
	for {
		f := c.sendOnce(to, text)
		if e, _ := f["error"].(map[string]any); e != nil && e["code"].(float64) == 4290 {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		return f
	}
}

func (c *wsClient) sendOnce(to, text string) map[string]any {
	c.t.Helper()
	id := fmt.Sprintf("m%d", time.Now().UnixNano())
	convType, target, _ := strings.Cut(to, ":")
	req, _ := json.Marshal(map[string]any{"id": id, "cmd": "send", "data": map[string]any{"convType": convType, "to": target, "type": "text", "body": map[string]any{"text": text}, "clientMsgId": id}})
	if err := c.ws.Write(context.Background(), websocket.MessageText, req); err != nil {
		c.t.Fatal(err)
	}
	for {
		f := c.wait("ack")
		if f["id"] == id {
			return f
		}
	}
}

// wait 等一个 cmd 的帧。
func (c *wsClient) wait(cmd string) map[string]any {
	c.t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case f, ok := <-c.in:
			if !ok {
				c.t.Fatalf("connection closed while waiting for %s", cmd)
			}
			if f["cmd"] == cmd {
				return f
			}
			if d, ok := f["data"].(map[string]any); ok && f["cmd"] == "event" && d["type"] == cmd {
				return f
			}
		case <-deadline:
			c.t.Fatalf("no %s frame", cmd)
		}
	}
}

// closed 等连接被服务端关闭，返回关闭码。
func (c *wsClient) closed() websocket.StatusCode {
	c.t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case _, ok := <-c.in:
			if !ok {
				return c.closeStatus
			}
		case <-deadline:
			c.t.Fatal("connection not closed")
		}
	}
}

// upload 发 multipart：file + 表单字段。
func (u *user) upload(path, csv string, fields map[string]string) reply {
	u.w.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		_ = mw.WriteField(k, v)
	}
	fw, _ := mw.CreateFormFile("file", "x.csv")
	_, _ = fw.Write([]byte(csv))
	_ = mw.Close()
	req, err := http.NewRequest("POST", u.srv.URL+path, &buf)
	if err != nil {
		u.w.t.Fatal(err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-Forwarded-For", u.ip)
	req.Header.Set("Origin", u.origin)
	req.Header.Set("X-CSRF-Token", u.csrf)
	req.Header.Set("Cookie", u.cookieN+"="+u.cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		u.w.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	r := reply{status: resp.StatusCode, header: resp.Header, raw: string(raw)}
	_ = json.Unmarshal(raw, &r.body)
	return r
}
