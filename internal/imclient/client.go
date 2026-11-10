// Package imclient 是 console-server 调用 im-server 的签名客户端（PRD-admin F-KEY-03）。
//
// 写操作不重试；超时返回 ErrResultUnknown（操作可能已经生效，由审计层转成 504 / 5040）。
// im-server 返回的错误码原样透传。私钥只在这个包的结构体里，不进日志和响应。
package imclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"tianting/console/internal/apierr"
	"tianting/console/internal/clock"
)

// ErrResultUnknown 表示调用 im-server 超时，不知道操作是否生效。
var ErrResultUnknown = errors.New("im-server call timed out; result unknown")

// Config 是一个调用方。
type Config struct {
	BaseURL string
	Caller  string
	Key     ed25519.PrivateKey
	Timeout time.Duration // 默认 10 秒
	Node    string        // 运维接口必填（X-IM-Target-Node）
	Clock   clock.Clock
	HTTP    *http.Client
	// Latency 是测试模式的人为延迟（毫秒，CS-001 的 imLatencyMs）；生产环境为 nil。
	Latency *atomic.Int64
	// DropResponse 是测试模式的 imDropResponse（PRD-live 8.2 节）：写请求正常发出、im-server 处理完之后丢弃响应，
	// 按连接中断处理。只读查询不受影响：对账要靠它们。生产环境为 nil。
	DropResponse *atomic.Bool
}

// Client 是签名客户端。
type Client struct{ c Config }

// New 创建客户端。
func New(c Config) (*Client, error) {
	if len(c.Key) != ed25519.PrivateKeySize {
		return nil, errors.New("imclient: invalid Ed25519 private key")
	}
	if c.Timeout == 0 {
		c.Timeout = 10 * time.Second
	}
	if c.Clock == nil {
		c.Clock = clock.New()
	}
	if c.HTTP == nil {
		// 不跟随跳转：签名是针对原路径的，内部接口也不应该跳转。
		c.HTTP = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	return &Client{c: c}, nil
}

// Call 是一次调用的上下文：操作人和请求 ID 都在签名范围内。
type Call struct {
	Operator  string // admin:{accountId}、ops:{accountId}
	RequestID string // console 审计的 requestId；拆批时为 {requestId}.{批号}
}

// RawBody 是已经序列化好的请求体，原样发送、原样签名。
// json.Marshal 会把 < > & 转义成 \u003c，字节数变多；推送的 4KB 上限按字节算，不能让两边的长度不一致。
type RawBody []byte

// Do 发送请求，把 2xx 响应解到 out（可以为 nil）。非 2xx 返回 *apierr.Error，错误码原样透传。
func (cl *Client) Do(ctx context.Context, call Call, method, path string, query url.Values, body, out any) error {
	ctx, cancel := context.WithTimeout(ctx, cl.c.Timeout)
	defer cancel()
	req, err := cl.newRequest(ctx, call, method, path, query, body)
	if err != nil {
		return err
	}
	if err := cl.wait(ctx); err != nil {
		return err
	}
	resp, err := cl.c.HTTP.Do(req)
	if err != nil {
		return sendErr(ctx, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		// 响应读到一半断了：im-server 已经开始回应，操作很可能已经生效。
		return fmt.Errorf("%w: read response: %w", ErrResultUnknown, err)
	}
	if cl.c.DropResponse != nil && cl.c.DropResponse.Load() && method != http.MethodGet {
		return fmt.Errorf("%w: response dropped by the test fault", ErrResultUnknown)
	}
	if resp.StatusCode >= 300 {
		return errorOf(resp.StatusCode, data)
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}

// Stream 发送请求，2xx 时返回响应（调用方读完 Body 并 Close），响应体不经过内存缓冲、不落盘（CS-202 文件代理）。
// 超时只管到收到响应头为止：文件可能很大，读响应体受 ctx 控制（浏览器断开就停）。非 2xx 返回 *apierr.Error。
// 这是只读调用，不受 DropResponse 影响（和 GET 一样）。
func (cl *Client) Stream(ctx context.Context, call Call, method, path string, query url.Values, body any) (*http.Response, error) {
	ctx, cancel := context.WithCancel(ctx)
	req, err := cl.newRequest(ctx, call, method, path, query, body)
	if err != nil {
		cancel()
		return nil, err
	}
	if err := cl.wait(ctx); err != nil {
		cancel()
		return nil, err
	}
	var timedOut atomic.Bool
	timer := time.AfterFunc(cl.c.Timeout, func() { timedOut.Store(true); cancel() })
	resp, err := cl.c.HTTP.Do(req)
	if !timer.Stop() || timedOut.Load() {
		if err == nil {
			_ = resp.Body.Close()
		}
		cancel()
		return nil, ErrResultUnknown
	}
	if err != nil {
		cancel()
		return nil, sendErr(ctx, err)
	}
	if resp.StatusCode >= 300 {
		defer cancel()
		defer resp.Body.Close()
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return nil, errorOf(resp.StatusCode, data)
	}
	resp.Body = &cancelBody{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

type cancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelBody) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}

// newRequest 构造签名请求。私钥只在这里用，不进日志。
func (cl *Client) newRequest(ctx context.Context, call Call, method, path string, query url.Values, body any) (*http.Request, error) {
	var raw []byte
	switch b := body.(type) {
	case nil:
	case RawBody:
		raw = b
	default:
		var err error
		if raw, err = json.Marshal(body); err != nil {
			return nil, err
		}
	}
	rawQuery := ""
	if len(query) > 0 {
		rawQuery = query.Encode()
	}
	nonceBytes := make([]byte, 18)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, err
	}
	ts := strconv.FormatInt(cl.c.Clock.Now().UnixMilli(), 10)
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	sts := StringToSign(Request{
		Method: method, Path: path, RawQuery: rawQuery, Timestamp: ts, Nonce: nonce, Body: raw,
		Operator: call.Operator, RequestID: call.RequestID, TargetNode: cl.c.Node,
	})
	target := strings.TrimRight(cl.c.BaseURL, "/") + path
	if rawQuery != "" {
		target += "?" + rawQuery
	}
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	h := req.Header
	h.Set("Content-Type", "application/json")
	h.Set("X-IM-Caller", cl.c.Caller)
	h.Set("X-IM-Timestamp", ts)
	h.Set("X-IM-Nonce", nonce)
	h.Set("X-IM-Signature", base64.RawURLEncoding.EncodeToString(ed25519.Sign(cl.c.Key, []byte(sts))))
	if call.Operator != "" {
		h.Set("X-IM-Operator", call.Operator)
	}
	if call.RequestID != "" {
		h.Set("X-Request-Id", call.RequestID)
	}
	if cl.c.Node != "" {
		h.Set("X-IM-Target-Node", cl.c.Node)
	}
	return req, nil
}

// wait 是测试模式的人为延迟。
func (cl *Client) wait(ctx context.Context) error {
	if cl.c.Latency != nil {
		if ms := cl.c.Latency.Load(); ms > 0 {
			select {
			case <-time.After(time.Duration(ms) * time.Millisecond):
			case <-ctx.Done():
				return ErrResultUnknown
			}
		}
	}
	return nil
}

func sendErr(ctx context.Context, err error) error {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return ErrResultUnknown
	}
	// 连接中断时请求可能已经到了 im-server：一律算"结果未知"，由对账确认。
	return fmt.Errorf("%w: %w", ErrResultUnknown, err)
}

func errorOf(status int, data []byte) error {
	var e apierr.Error
	if json.Unmarshal(data, &e) == nil && e.Code != 0 {
		return &e
	}
	if status == http.StatusNotFound { // 路由没有注册（AC-ADM-15-7）
		return apierr.New(apierr.NotFound, "not found")
	}
	return apierr.New(apierr.Internal, "im-server returned HTTP %d", status)
}

// Request 是待签名的请求（字段和 tianting-server 的 adminauth 一致，由 vectors 保证）。
type Request struct {
	Method, Path, RawQuery, Timestamp, Nonce string
	Body                                     []byte
	Operator, RequestID, TargetNode          string
}

// StringToSign 是 8 行待签名串，"\n" 分隔，末尾没有换行（ADMIN.md、protocol/vectors/admin-sign.json）。
func StringToSign(r Request) string {
	p := r.Path
	if q := CanonicalQuery(r.RawQuery); q != "" {
		p += "?" + q
	}
	sum := sha256.Sum256(r.Body)
	return strings.Join([]string{strings.ToUpper(r.Method), p, r.Timestamp, r.Nonce, hex.EncodeToString(sum[:]), r.Operator, r.RequestID, r.TargetNode}, "\n")
}

// CanonicalQuery 解码后按键名（相同键按值）排序，键和值按 RFC 3986 编码。
func CanonicalQuery(raw string) string {
	if raw == "" {
		return ""
	}
	type kv struct{ k, v string }
	var pairs []kv
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		dk, err1 := url.QueryUnescape(k)
		dv, err2 := url.QueryUnescape(v)
		if err1 != nil || err2 != nil {
			dk, dv = k, v
		}
		pairs = append(pairs, kv{dk, dv})
	}
	sort.SliceStable(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	out := make([]string, len(pairs))
	for i, p := range pairs {
		out[i] = rfc3986(p.k) + "=" + rfc3986(p.v)
	}
	return strings.Join(out, "&")
}

func rfc3986(s string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&15])
	}
	return b.String()
}
