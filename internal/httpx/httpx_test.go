package httpx

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"tianting/console/internal/space"
)

func prefixes(list ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range list {
		if !strings.Contains(s, "/") {
			s += "/32"
		}
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func do(g Guard, remote string, h map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/login", nil)
	r.RemoteAddr = remote + ":1234"
	for k, v := range h {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	g.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })).ServeHTTP(w, r)
	return w
}

// AC-CON-01-1：直连时 X-Forwarded-For 不算数。
func TestCIDRIgnoresForwardedFromUntrustedPeer(t *testing.T) {
	var reasons []string
	g := Guard{Space: space.Space{AllowedCIDRs: prefixes("10.0.0.0/8")}, OnReject: func(r string) { reasons = append(reasons, r) }}
	w := do(g, "192.168.1.10", map[string]string{"X-Forwarded-For": "10.0.0.1"})
	if w.Code != 403 || !strings.Contains(w.Body.String(), `"code":4030`) {
		t.Errorf("%d %s", w.Code, w.Body)
	}
	if len(reasons) != 1 || reasons[0] != "cidr" {
		t.Errorf("reasons = %v", reasons)
	}
	if do(g, "10.9.9.9", nil).Code != 200 {
		t.Error("allowed address rejected")
	}
}

// AC-CON-01-2：可信代理转发时取真实来源。
func TestCIDRThroughTrustedProxy(t *testing.T) {
	g := Guard{Space: space.Space{AllowedCIDRs: prefixes("10.0.0.0/8")}, Trusted: prefixes("10.0.0.2")}
	if w := do(g, "10.0.0.2", map[string]string{"X-Forwarded-For": "192.168.1.10"}); w.Code != 403 {
		t.Errorf("outside via proxy = %d", w.Code)
	}
	if w := do(g, "10.0.0.2", map[string]string{"X-Forwarded-For": "10.1.2.3"}); w.Code != 200 {
		t.Errorf("inside via proxy = %d", w.Code)
	}
	// 客户端在左边伪造内网地址：从右往左第一个不可信的才算。
	if w := do(g, "10.0.0.2", map[string]string{"X-Forwarded-For": "10.1.1.1, 192.168.1.10"}); w.Code != 403 {
		t.Errorf("spoofed left hop = %d", w.Code)
	}
	if w := do(g, "10.0.0.2", map[string]string{"X-Forwarded-For": "10.1.1.1, garbage"}); w.Code != 403 {
		t.Errorf("garbage hop = %d", w.Code)
	}
}

func TestClientIPIPv6AndMapped(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "[::ffff:10.1.2.3]:80"
	ip, ok := ClientIP(r, nil)
	if !ok || ip.String() != "10.1.2.3" {
		t.Errorf("mapped = %v %v", ip, ok)
	}
}

// 生产环境：直连明文拒绝；可信代理必须声明 https。
func TestProductionHTTPSOnly(t *testing.T) {
	g := Guard{Space: space.Space{}, Trusted: prefixes("10.0.0.2"), Production: true}
	if w := do(g, "10.0.0.9", nil); w.Code != 403 {
		t.Errorf("plain direct = %d", w.Code)
	}
	if w := do(g, "10.0.0.2", map[string]string{"X-Forwarded-For": "10.1.1.1"}); w.Code != 403 {
		t.Errorf("proxy without proto = %d", w.Code)
	}
	if w := do(g, "10.0.0.9", map[string]string{"X-Forwarded-Proto": "https"}); w.Code != 403 {
		t.Errorf("untrusted peer claiming https = %d", w.Code)
	}
	w := do(g, "10.0.0.2", map[string]string{"X-Forwarded-For": "10.1.1.1", "X-Forwarded-Proto": "https"})
	if w.Code != 200 || w.Header().Get("Strict-Transport-Security") != "max-age=31536000" {
		t.Errorf("proxied https = %d %v", w.Code, w.Header())
	}
}

// AC-CON-10-3、05-14：页面和接口的响应头（拒绝的响应也带）。
func TestSecurityHeaders(t *testing.T) {
	g := Guard{Space: space.Space{AllowedCIDRs: prefixes("10.0.0.0/8")}}
	serve := func(path, remote string) http.Header {
		r := httptest.NewRequest("GET", path, nil)
		r.RemoteAddr = remote + ":1"
		w := httptest.NewRecorder()
		g.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(w, r)
		return w.Header()
	}
	for _, h := range []http.Header{serve("/", "10.0.0.1"), serve("/console/api/session", "10.0.0.1"), serve("/", "192.168.0.1")} {
		csp := h.Get("Content-Security-Policy")
		if !strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "unsafe-inline") {
			t.Errorf("csp = %s", csp)
		}
		if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("headers = %v", h)
		}
		if h.Get("Strict-Transport-Security") != "" {
			t.Error("HSTS outside production")
		}
	}
	if serve("/console/api/session", "10.0.0.1").Get("Cache-Control") != "no-store" {
		t.Error("API must be no-store")
	}
	if a, b := serve("/", "10.0.0.1").Get("Content-Security-Policy"), serve("/", "10.0.0.1").Get("Content-Security-Policy"); a == b {
		t.Error("nonce repeats across responses")
	}
	ops := Guard{Space: space.Space{Policy: space.Policy{FrameDeny: true, NoDataImages: true, NoStyleNonce: true}}}
	r := httptest.NewRecorder()
	ops.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(r, httptest.NewRequest("GET", "/", nil))
	if r.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("ops needs X-Frame-Options")
	}
}

// SPA 回退注入 nonce，和响应头里的一致；真实文件照常返回；目录穿越不会读到目录外。
func TestStaticInjectsNonce(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Dir(dir)
	_ = os.WriteFile(filepath.Join(parent, "outside.txt"), []byte("secret"), 0o600)
	t.Cleanup(func() { os.Remove(filepath.Join(parent, "outside.txt")) })
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte(`<style nonce="__CSP_NONCE__"></style>`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.js"), []byte("js"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := Guard{}.Wrap(Static(dir))
	get := func(p string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/", nil)
		r.URL.Path = p
		h.ServeHTTP(w, r)
		return w
	}
	w := get("/users/u1")
	nonce := regexp.MustCompile(`nonce-([A-Za-z0-9+/=]+)`).FindStringSubmatch(w.Header().Get("Content-Security-Policy"))
	if w.Code != 200 || nonce == nil || !strings.Contains(w.Body.String(), `nonce="`+nonce[1]+`"`) {
		t.Errorf("%d %s %v", w.Code, w.Body, nonce)
	}
	if got := get("/a.js"); got.Body.String() != "js" {
		t.Errorf("file = %s", got.Body)
	}
	if got := get("/../outside.txt"); strings.Contains(got.Body.String(), "secret") {
		t.Error("path traversal")
	}
}
