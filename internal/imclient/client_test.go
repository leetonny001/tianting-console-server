package imclient

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"tianting/console/internal/apierr"
)

type vector struct {
	Name, Alg, Seed, Method, Path, Query, Timestamp, Nonce, Body, Operator, RequestID, TargetNode, StringToSign, Signature string
}

func vectors(t *testing.T, file string) []vector {
	t.Helper()
	raw, err := os.ReadFile("../../protocol/vectors/" + file)
	if err != nil {
		t.Fatal(err)
	}
	var f struct{ Vectors []vector }
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	return f.Vectors
}

// 待签名串和 Ed25519 签名与 tianting-server 的向量完全一致。
func TestSignatureVectors(t *testing.T) {
	for _, file := range []string{"admin-sign.json", "ops-sign.json"} {
		for _, v := range vectors(t, file) {
			got := StringToSign(Request{Method: v.Method, Path: v.Path, RawQuery: v.Query, Timestamp: v.Timestamp, Nonce: v.Nonce, Body: []byte(v.Body), Operator: v.Operator, RequestID: v.RequestID, TargetNode: v.TargetNode})
			if got != v.StringToSign {
				t.Errorf("%s/%s: string to sign\n%q\nwant\n%q", file, v.Name, got, v.StringToSign)
			}
			if v.Alg == "hmac-sha256" {
				continue
			}
			seed, err := base64.StdEncoding.DecodeString(v.Seed)
			if err != nil {
				t.Fatal(err)
			}
			sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed), []byte(got)))
			if sig != v.Signature {
				t.Errorf("%s/%s: signature %s, want %s", file, v.Name, sig, v.Signature)
			}
		}
	}
}

func newClient(t *testing.T, h http.HandlerFunc, mutate func(*Config)) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	_, priv, _ := ed25519.GenerateKey(nil)
	c := Config{BaseURL: srv.URL, Caller: "console", Key: priv}
	if mutate != nil {
		mutate(&c)
	}
	cl, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	return cl
}

// 头和签名：服务端用公钥能验证；请求 ID、操作人在签名范围内。
func TestRequestIsSigned(t *testing.T) {
	var pub ed25519.PublicKey
	var checked atomic.Bool
	cl := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		sts := StringToSign(Request{Method: r.Method, Path: r.URL.Path, RawQuery: r.URL.RawQuery, Timestamp: r.Header.Get("X-IM-Timestamp"), Nonce: r.Header.Get("X-IM-Nonce"), Body: body,
			Operator: r.Header.Get("X-IM-Operator"), RequestID: r.Header.Get("X-Request-Id"), TargetNode: r.Header.Get("X-IM-Target-Node")})
		sig, _ := base64.RawURLEncoding.DecodeString(r.Header.Get("X-IM-Signature"))
		if ed25519.Verify(pub, []byte(sts), sig) && r.Header.Get("X-IM-Caller") == "console" && r.Header.Get("X-IM-Operator") == "admin:7" && r.Header.Get("X-Request-Id") == "req.1" && len(r.Header.Get("X-IM-Nonce")) >= 16 {
			checked.Store(true)
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}, func(c *Config) { pub = c.Key.Public().(ed25519.PublicKey) })
	var out struct{ OK bool }
	err := cl.Do(context.Background(), Call{Operator: "admin:7", RequestID: "req.1"}, "GET", "/admin/users", url.Values{"q": {"a b"}, "limit": {"20"}}, nil, &out)
	if err != nil || !out.OK || !checked.Load() {
		t.Errorf("err=%v out=%+v signature ok=%v", err, out, checked.Load())
	}
}

// im-server 的错误码原样透传。
func TestErrorPassThrough(t *testing.T) {
	cl := newClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"code":4043,"msg":"group not found"}`))
	}, nil)
	var e *apierr.Error
	err := cl.Do(context.Background(), Call{}, "GET", "/admin/groups/g", nil, nil, nil)
	if !errors.As(err, &e) || e.Code != 4043 {
		t.Errorf("err = %v", err)
	}
	cl = newClient(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(502) }, nil)
	if err := cl.Do(context.Background(), Call{}, "GET", "/x", nil, nil, nil); !errors.As(err, &e) || e.Code != apierr.Internal {
		t.Errorf("non-JSON error = %v", err)
	}
}

// 超时：结果未知，不重试。
func TestTimeoutIsUnknownAndNoRetry(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	cl := newClient(t, func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
		<-release
	}, func(c *Config) { c.Timeout = 50 * time.Millisecond })
	defer close(release)
	err := cl.Do(context.Background(), Call{}, "POST", "/admin/users/u/force-logout", nil, map[string]any{}, nil)
	if !errors.Is(err, ErrResultUnknown) {
		t.Errorf("err = %v", err)
	}
	if calls.Load() != 1 {
		t.Errorf("calls = %d", calls.Load())
	}
}

func TestLatencyFault(t *testing.T) {
	var ms atomic.Int64
	ms.Store(500)
	cl := newClient(t, func(http.ResponseWriter, *http.Request) {}, func(c *Config) { c.Timeout = 50 * time.Millisecond; c.Latency = &ms })
	if err := cl.Do(context.Background(), Call{}, "GET", "/x", nil, nil, nil); !errors.Is(err, ErrResultUnknown) {
		t.Errorf("err = %v", err)
	}
	ms.Store(0)
	if err := cl.Do(context.Background(), Call{}, "GET", "/x", nil, nil, nil); err != nil {
		t.Errorf("err = %v", err)
	}
}

// 错误信息不带私钥；不接受长度不对的私钥。
func TestKeyHandling(t *testing.T) {
	if _, err := New(Config{Key: []byte("short")}); err == nil || strings.Contains(err.Error(), "short") {
		t.Errorf("err = %v", err)
	}
}

// imDropResponse（PRD-live 8.2 节）：请求发出去了、服务端处理完了，调用方拿到的是"结果未知"。只读查询不受影响。
func TestDropResponseFault(t *testing.T) {
	var drop atomic.Bool
	drop.Store(true)
	var calls atomic.Int32
	cl := newClient(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}, func(c *Config) { c.DropResponse = &drop })
	err := cl.Do(context.Background(), Call{}, "POST", "/admin/push", nil, map[string]any{}, nil)
	if !errors.Is(err, ErrResultUnknown) || calls.Load() != 1 {
		t.Errorf("err = %v, calls = %d", err, calls.Load())
	}
	if err := cl.Do(context.Background(), Call{}, "GET", "/admin/audit", nil, nil, nil); err != nil {
		t.Errorf("read while dropping: %v", err)
	}
	drop.Store(false)
	if err := cl.Do(context.Background(), Call{}, "POST", "/admin/push", nil, map[string]any{}, nil); err != nil {
		t.Errorf("after clearing: %v", err)
	}
}

// 响应读到一半断了：不知道结果，不能当成失败。
func TestTruncatedResponseIsUnknown(t *testing.T) {
	cl := newClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte(`{"partial"`))
	}, func(*Config) {})
	err := cl.Do(context.Background(), Call{}, "POST", "/admin/push", nil, map[string]any{}, nil)
	if !errors.Is(err, ErrResultUnknown) {
		t.Errorf("err = %v", err)
	}
}

// RawBody 原样发送、原样签名：< 不被转义，字节数不变。
func TestRawBodyIsSentAsIs(t *testing.T) {
	const body = `{"data":{"text":"<&>"}}`
	var got string
	cl := newClient(t, func(_ http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		got = string(raw)
	}, func(*Config) {})
	if err := cl.Do(context.Background(), Call{}, "POST", "/admin/push", nil, RawBody(body), nil); err != nil {
		t.Fatal(err)
	}
	if got != body {
		t.Errorf("body = %s", got)
	}
}

// CS-202：Stream 签名和 Do 一样；2xx 原样给出响应体（大于 Do 的 16MB 上限也行）；非 2xx 透传错误码；
// 超时只算到响应头，响应体慢慢写不算超时。
func TestStream(t *testing.T) {
	const big = 17 << 20
	cl := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-IM-Signature") == "" || r.Header.Get("X-IM-Operator") != "admin:a1" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/big":
			w.Header().Set("Content-Type", "image/png")
			w.WriteHeader(200)
			chunk := make([]byte, 1<<20)
			for range big >> 20 {
				_, _ = w.Write(chunk)
				w.(http.Flusher).Flush()
				time.Sleep(5 * time.Millisecond) // 总时长超过 Timeout，但每次都有数据
			}
		case "/denied":
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"code":4039,"msg":"grant required"}`))
		case "/hang":
			time.Sleep(300 * time.Millisecond)
		}
	}, func(c *Config) { c.Timeout = 60 * time.Millisecond })
	call := Call{Operator: "admin:a1", RequestID: "r1"}
	resp, err := cl.Stream(context.Background(), call, "POST", "/big", nil, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if err != nil || n != big || resp.Header.Get("Content-Type") != "image/png" {
		t.Errorf("big: %d bytes, %v", n, err)
	}
	_, err = cl.Stream(context.Background(), call, "POST", "/denied", nil, map[string]any{})
	var e *apierr.Error
	if !errors.As(err, &e) || e.Code != 4039 {
		t.Errorf("denied = %v", err)
	}
	if _, err := cl.Stream(context.Background(), call, "POST", "/hang", nil, map[string]any{}); !errors.Is(err, ErrResultUnknown) {
		t.Errorf("hang = %v", err)
	}
}
