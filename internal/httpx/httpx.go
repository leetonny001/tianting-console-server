// Package httpx 是每个空间共用的 HTTP 中间件：来源判断、响应头、静态资源。
package httpx

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"strings"

	"tianting/console/internal/apierr"
	"tianting/console/internal/space"
)

// Guard 是一个监听地址的网络边界。
type Guard struct {
	Space      space.Space
	Trusted    []netip.Prefix
	Production bool
	OnReject   func(reason string) // 未认证的拒绝只计数、写日志，不进审计
}

func contains(list []netip.Prefix, ip netip.Addr) bool {
	for _, p := range list {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func parseIP(s string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, false
	}
	return ip.Unmap().WithZone(""), true
}

func peer(r *http.Request) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	return parseIP(host)
}

// ClientIP 返回真实来源：TCP 对端是可信代理时，从 X-Forwarded-For 自右向左取第一个不可信地址；否则就是对端地址。
// 全部地址都可信时取最左边的；格式错的段视为不可信的终点，不再往左看（左边的值可以被伪造）。
func ClientIP(r *http.Request, trusted []netip.Prefix) (netip.Addr, bool) {
	ip, ok := peer(r)
	if !ok || !contains(trusted, ip) {
		return ip, ok
	}
	parts := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		hop, ok := parseIP(parts[i])
		if !ok {
			return netip.Addr{}, false
		}
		ip = hop
		if !contains(trusted, hop) {
			return hop, true
		}
	}
	return ip, true
}

type ctxKey int

const nonceKey ctxKey = 0

// Nonce 返回这次响应的 CSP nonce。
func Nonce(ctx context.Context) string {
	s, _ := ctx.Value(nonceKey).(string)
	return s
}

// Wrap：响应头（拒绝的响应也要带）→ 来源网段 → HTTPS。
func (g Guard) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := space.NewNonce()
		h := w.Header()
		h.Set("Content-Security-Policy", g.Space.Policy.CSP(nonce))
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		if g.Space.Policy.FrameDeny {
			h.Set("X-Frame-Options", "DENY")
		}
		if g.Production {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if strings.HasPrefix(r.URL.Path, "/console/") {
			h.Set("Cache-Control", "no-store")
		}
		if reason := g.reject(r); reason != "" {
			if g.OnReject != nil {
				g.OnReject(reason)
			}
			apierr.Write(w, apierr.New(apierr.Forbidden, "request not allowed"))
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), nonceKey, nonce)))
	})
}

func (g Guard) reject(r *http.Request) string {
	ip, ok := ClientIP(r, g.Trusted)
	if len(g.Space.AllowedCIDRs) > 0 && (!ok || !contains(g.Space.AllowedCIDRs, ip)) {
		return "cidr"
	}
	if !g.Production || r.TLS != nil {
		return ""
	}
	// 生产环境只允许 HTTPS：不是自己终止 TLS，就必须是可信代理转发且声明了 https。
	p, ok := peer(r)
	if !ok || !contains(g.Trusted, p) || r.Header.Get("X-Forwarded-Proto") != "https" {
		return "proto"
	}
	return ""
}

func isFile(root http.Dir, name string) bool {
	f, err := root.Open(name)
	if err != nil {
		return false
	}
	defer f.Close()
	info, err := f.Stat()
	return err == nil && !info.IsDir()
}

// noncePlaceholder 是 index.html 里给 <style nonce> 和 <meta> 预留的占位符，返回时换成这次响应的 nonce。
const noncePlaceholder = "__CSP_NONCE__"

// Static 托管前端构建产物；不认识的路径回退到 index.html（SPA）。/console/ 下的路径不回退，由 API 路由处理。
func Static(dir string) http.Handler {
	root := http.Dir(dir) // http.Dir 负责挡住目录穿越
	files := http.FileServer(root)
	index := filepath.Join(dir, "index.html")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			apierr.Write(w, apierr.New(apierr.NotFound, "not found"))
			return
		}
		clean := path.Clean("/" + r.URL.Path)
		if clean != "/" && clean != "/index.html" {
			if isFile(root, clean) {
				files.ServeHTTP(w, r)
				return
			}
		}
		raw, err := os.ReadFile(index) // #nosec G304 -- 路径来自运维配置的构建产物目录
		if err != nil {
			apierr.Write(w, apierr.New(apierr.NotFound, "not found"))
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(bytes.ReplaceAll(raw, []byte(noncePlaceholder), []byte(Nonce(r.Context()))))
	})
}
