package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"tianting/console/internal/apierr"
	"tianting/console/internal/audit"
	"tianting/console/internal/secret"
)

// CS-117：Grafana 认证代理。只有一套登录和 TOTP：运维后台签发一次性票据，Grafana 主机上用票据换一个绑定原会话的 Cookie。

const (
	actionGrafanaEnter = "ops.grafana.enter"
	grafanaTicketTTL   = 30 * time.Second
	grafanaCookie      = "__Host-grafana_sid"
	grafanaEnterPath   = "/__tianting/enter"
	grafanaUserHeader  = "X-WEBAUTH-USER"
)

func randomToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// opsGrafanaTicket 签发票据。权限点已经在路由上检查：ops_auditor、ops_superadmin 拿不到。
func (c *rc) opsGrafanaTicket() {
	cfg := c.a.Cfg.Ops
	if cfg.GrafanaURL == "" || cfg.GrafanaHost == "" {
		c.fail(apierr.New(apierr.Unavailable, "Grafana is not configured"))
		return
	}
	if !c.minuteRate("ops.grafana.ticket", opsReadPerMinute) {
		return
	}
	ticket, err := randomToken()
	if err != nil {
		c.failErr("grafana ticket", err)
		return
	}
	if err := c.event(actionGrafanaEnter, audit.NewTarget("grafana"), nil, audit.Success, 0); err != nil {
		c.fail(apierr.New(apierr.AuditUnavailable, "audit service unavailable, try again later"))
		return
	}
	if _, err := c.a.DB.Exec(c.ctx, `INSERT INTO biz.grafana_tickets (ticket_hash, session_hash, expires_at) VALUES ($1, $2, $3)`,
		secret.SessionHash(ticket), c.sess.IDHash, c.now()+grafanaTicketTTL.Milliseconds()); err != nil {
		c.failErr("grafana ticket", err)
		return
	}
	scheme := "https://"
	if !c.a.Cfg.Production() && strings.HasPrefix(c.space.Origin, "http://") {
		scheme = "http://"
	}
	c.opsOK(map[string]any{"url": scheme + cfg.GrafanaHost + grafanaEnterPath + "?ticket=" + url.QueryEscape(ticket)}, nil)
}

func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

// isGrafanaHost 判断请求是不是发给 Grafana 主机的。
func (a *App) isGrafanaHost(r *http.Request) bool {
	h := a.Cfg.Ops.GrafanaHost
	return h != "" && (strings.EqualFold(r.Host, h) || strings.EqualFold(hostOnly(r.Host), hostOnly(h)))
}

// grafanaLogin 跳回运维后台登录页。
func (a *App) grafanaLogin(w http.ResponseWriter, r *http.Request, navigate bool) {
	s, _ := a.Cfg.Space("ops")
	if navigate && s.Origin != "" {
		http.Redirect(w, r, s.Origin+"/login", http.StatusFound)
		return
	}
	apierr.Write(w, authRequired(reasonNone))
}

// 写接口只放行查询数据的：保存面板、数据源管理在代理这一层就拦下（Grafana 的 Viewer 也会拒绝，双重保护）。
// Prometheus 只读查询接口：面板和查询构建器用的就是这些。status/config、targets、rules 不给（F-OPS-17 规则 2）。
var promQueryPaths = regexp.MustCompile(`^/api/datasources/proxy/(uid/[a-z0-9_-]+|[0-9]+)/api/v1/(query|query_range|query_exemplars|labels|label/[^/]+/values|series|metadata|status/buildinfo)$`)

// Viewer 用不到的 Grafana 接口。Grafana 自己也会拒绝大部分，这里多一层。
var grafanaBlocked = []string{"/metrics", "/api/admin", "/api/users", "/api/org/users", "/api/orgs", "/api/serviceaccounts", "/api/access-control", "/api/live"}

func grafanaAllowed(r *http.Request) bool {
	// WebSocket 只在握手时校验一次会话，登出后还能继续收数据。
	if r.Header.Get("Upgrade") != "" {
		return false
	}
	p := r.URL.Path
	// 不规范的路径一律拒绝：上游可能归一化成另一条路径，前缀判断就白做了（/api/datasources/proxy/../../admin/users）。
	if p == "" || p != path.Clean(p) && p != path.Clean(p)+"/" || strings.Contains(p, "\\") {
		return false
	}
	if esc := strings.ToLower(r.URL.EscapedPath()); strings.Contains(esc, "%2f") || strings.Contains(esc, "%5c") || strings.Contains(esc, "%2e") {
		return false
	}
	p = strings.ToLower(p) // 上游的路由可能不区分大小写
	for _, b := range grafanaBlocked {
		if p == b || strings.HasPrefix(p, b+"/") {
			return false
		}
	}
	if strings.HasPrefix(p, "/api/datasources") && !promQueryPaths.MatchString(p) {
		return false
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		return true
	case http.MethodPost:
		return p == "/api/ds/query" || promQueryPaths.MatchString(p) || p == "/api/frontend-metrics"
	}
	return false
}

// grafanaHandler 是 Grafana 主机上的全部请求。
func (a *App) grafanaHandler() http.Handler {
	target, err := url.Parse(a.Cfg.Ops.GrafanaURL)
	if err != nil || target.Host == "" {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			apierr.Write(w, apierr.New(apierr.Unavailable, "Grafana is not configured"))
		})
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = target.Host
			// Rewrite 模式下不带 X-Forwarded-*。用户头在 ServeHTTP 里设置，这里只保证客户端自带的同名头被换掉。
			pr.Out.Header.Del(grafanaUserHeader)
			pr.Out.Header.Set(grafanaUserHeader, pr.In.Header.Get(grafanaInternalUser))
			pr.Out.Header.Del(grafanaInternalUser)
			// 我们自己的 Cookie 不给 Grafana。
			cookies := pr.In.Cookies()
			pr.Out.Header.Del("Cookie")
			for _, ck := range cookies {
				if ck.Name != grafanaCookie {
					pr.Out.AddCookie(ck)
				}
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Del("Set-Cookie") // Grafana 不需要在浏览器里留会话：身份每次由代理给
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			apierr.Write(w, apierr.New(apierr.Unavailable, "Grafana is not available"))
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Guard 给运维页面设的 CSP 不适合 Grafana 自己的页面（不同源，也进不了运维后台）。
		w.Header().Del("Content-Security-Policy")
		navigate := r.Header.Get("Sec-Fetch-Mode") == "navigate"
		if r.URL.Path == grafanaEnterPath {
			a.grafanaEnter(w, r)
			return
		}
		ck, err := r.Cookie(grafanaCookie)
		if err != nil || ck.Value == "" {
			a.grafanaLogin(w, r, navigate)
			return
		}
		username, ok, err := a.grafanaSession(r.Context(), secret.SessionHash(ck.Value), navigate)
		if err != nil {
			a.Log.Error("grafana session", "err", err)
			apierr.Write(w, apierr.New(apierr.Internal, "internal error"))
			return
		}
		if !ok {
			a.grafanaLogin(w, r, navigate)
			return
		}
		if !grafanaAllowed(r) {
			apierr.Write(w, apierr.New(apierr.Forbidden, "read-only"))
			return
		}
		r.Header.Set(grafanaInternalUser, grafanaIdentity(username))
		proxy.ServeHTTP(w, r)
	})
}

// grafanaInternalUser 只在进程内传递（Rewrite 里一定删除）：客户端自带也会被 ServeHTTP 覆盖。
const grafanaInternalUser = "X-Tianting-Internal-User"

// grafanaIdentity 是传给 Grafana 的身份。auth.proxy 按登录名找用户，运维账号如果叫 admin，
// 就成了 Grafana 的服务器管理员：加前缀，运维账号怎么取名都碰不到 Grafana 的内置账号。
func grafanaIdentity(username string) string { return "ops-" + username }

// grafanaEnter 消费票据（原子删除：只能用一次），换主机专属 Cookie。
func (a *App) grafanaEnter(w http.ResponseWriter, r *http.Request) {
	ticket := r.URL.Query().Get("ticket")
	now := a.Clock.Now().UnixMilli()
	var sessionHash string
	var expires int64
	err := a.DB.QueryRow(r.Context(), `DELETE FROM biz.grafana_tickets WHERE ticket_hash = $1 RETURNING session_hash, expires_at`, secret.SessionHash(ticket)).Scan(&sessionHash, &expires)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && expires <= now) {
		a.grafanaLogin(w, r, true)
		return
	}
	if err != nil {
		a.Log.Error("grafana enter", "err", err)
		apierr.Write(w, apierr.New(apierr.Internal, "internal error"))
		return
	}
	// 拿票据的会话可能已经登出或过期：票据不能比会话活得久。
	if _, ok, err := a.grafanaUser(r.Context(), sessionHash, false); err != nil || !ok {
		if err != nil {
			a.Log.Error("grafana enter", "err", err)
		}
		a.grafanaLogin(w, r, true)
		return
	}
	cookie, err := randomToken()
	if err == nil {
		_, err = a.DB.Exec(r.Context(), `INSERT INTO biz.grafana_sessions (cookie_hash, session_hash, created_at) VALUES ($1, $2, $3)`, secret.SessionHash(cookie), sessionHash, now)
	}
	if err != nil {
		a.Log.Error("grafana enter", "err", err)
		apierr.Write(w, apierr.New(apierr.Internal, "internal error"))
		return
	}
	http.SetCookie(w, &http.Cookie{Name: grafanaCookie, Value: cookie, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/", http.StatusFound)
}

// grafanaSession 校验 Cookie 绑定的运维会话。只有页面导航续期，数据查询不续期（B-OPS-05）：
// 开着自动刷新的面板不会让会话永远不过期。
func (a *App) grafanaSession(ctx context.Context, cookieHash string, navigate bool) (string, bool, error) {
	var sessionHash string
	err := a.DB.QueryRow(ctx, `SELECT session_hash FROM biz.grafana_sessions WHERE cookie_hash = $1`, cookieHash).Scan(&sessionHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return a.grafanaUser(ctx, sessionHash, navigate)
}

// grafanaUser 校验运维会话还有效、还有查看权限，返回用户名。
func (a *App) grafanaUser(ctx context.Context, sessionHash string, navigate bool) (string, bool, error) {
	now := a.Clock.Now().UnixMilli()
	s, acct, roles, reason, err := a.checkSession(ctx, sessionHash, "ops", now)
	if err != nil || reason != "" {
		return "", false, err
	}
	if s.State != "full" {
		return "", false, nil
	}
	// 角色被改时会话已经失效；这里再确认一次，防止以后的改动绕过。
	if !opsSpace().Has(roles, "ops.overview.read") {
		return "", false, nil
	}
	if navigate {
		if _, err := a.DB.Exec(ctx, `UPDATE auth.sessions SET last_active_at = $2 WHERE id_hash = $1`, sessionHash, now); err != nil {
			return "", false, err
		}
	}
	return acct.Username, true, nil
}
