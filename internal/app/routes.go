package app

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"tianting/console/internal/apierr"
	"tianting/console/internal/audit"
	"tianting/console/internal/httpx"
	"tianting/console/internal/ids"
	"tianting/console/internal/imclient"
	"tianting/console/internal/perm"
	"tianting/console/internal/secret"
	"tianting/console/internal/space"
)

// route 是一个 /console/api/* 路由。perm 必须显式声明（权限点或 perm.LoginOnly）；公开路由必须显式写 public。
type route struct {
	method, path string
	perm         string
	public       bool // 不需要会话：登录、激活
	allowSetup   bool // setup 会话也能调用
	stepUp       bool // 需要 5 分钟内 step-up
	action       string
	h            func(*rc)
}

// rc 是一次请求的上下文。
type rc struct {
	a         *App
	w         http.ResponseWriter
	r         *http.Request
	ctx       context.Context
	space     space.Space
	ps        perm.Space
	route     route
	ip, ua    string
	requestID string
	sid       string
	sess      sessionRow
	acct      accountRow
	roles     []string
}

func (c *rc) now() int64 { return c.a.Clock.Now().UnixMilli() }

func (c *rc) json(status int, v any) {
	h := c.w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	c.w.WriteHeader(status)
	_ = json.NewEncoder(c.w).Encode(v)
}

func (c *rc) ok(v any) { c.json(http.StatusOK, v) }

func (c *rc) fail(e *apierr.Error) { apierr.Write(c.w, e) }

func (c *rc) failErr(where string, err error) {
	var e *apierr.Error
	switch {
	case errors.As(err, &e):
		c.fail(e)
	case errors.Is(err, secret.ErrBusy):
		c.fail(apierr.New(apierr.Unavailable, "too many requests, try again later"))
	case errors.Is(err, imclient.ErrResultUnknown):
		c.fail(apierr.New(apierr.ResultUnknown, "im-server did not answer in time"))
	default:
		c.a.Log.Error(where, "err", err, "requestId", c.requestID)
		c.fail(apierr.New(apierr.Internal, "internal error"))
	}
}

// readJSON 读请求体。解析失败直接回 400，不带内容（可能有密码）。
func (c *rc) readJSON(v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(c.w, c.r.Body, 1<<16)).Decode(v); err != nil {
		c.fail(apierr.New(apierr.BadRequest, "invalid JSON body"))
		return false
	}
	return true
}

func (a *App) apiRoutes(ps perm.Space) []route {
	manage := ps.ManagePerm
	rs := []route{
		{method: "POST", path: "/console/api/auth/login", public: true, h: (*rc).login},
		{method: "POST", path: "/console/api/auth/activate", public: true, h: (*rc).activate},
		{method: "GET", path: "/console/api/session", perm: perm.LoginOnly, allowSetup: true, h: (*rc).session},
		{method: "POST", path: "/console/api/auth/logout", perm: perm.LoginOnly, allowSetup: true, h: (*rc).logout},
		{method: "POST", path: "/console/api/auth/totp/setup", perm: perm.LoginOnly, allowSetup: true, h: (*rc).totpSetup},
		{method: "POST", path: "/console/api/auth/totp/confirm", perm: perm.LoginOnly, allowSetup: true, h: (*rc).totpConfirm},
		{method: "POST", path: "/console/api/auth/step-up", perm: perm.LoginOnly, h: (*rc).stepUpVerify},
		{method: "POST", path: "/console/api/me/password", perm: perm.LoginOnly, h: (*rc).changePassword},
		{method: "POST", path: "/console/api/me/recovery-codes", perm: perm.LoginOnly, stepUp: true, h: (*rc).regenerateRecovery},
		{method: "GET", path: "/console/api/notifications", perm: perm.LoginOnly, h: (*rc).listNotifications},
		{method: "GET", path: "/console/api/notifications/unread-count", perm: perm.LoginOnly, h: (*rc).unreadCount},
		{method: "POST", path: "/console/api/notifications/read", perm: perm.LoginOnly, h: (*rc).markRead},
		{method: "GET", path: "/console/api/accounts", perm: manage, action: "account.list", h: (*rc).listAccounts},
		{method: "POST", path: "/console/api/accounts", perm: manage, stepUp: true, action: "account.create", h: (*rc).createAccount},
		{method: "GET", path: "/console/api/accounts/{id}", perm: manage, action: "account.read", h: (*rc).getAccount},
		{method: "POST", path: "/console/api/accounts/{id}/roles", perm: manage, stepUp: true, action: "account.roles", h: (*rc).setRoles},
		{method: "POST", path: "/console/api/accounts/{id}/disable", perm: manage, stepUp: true, action: "account.disable", h: (*rc).disableAccount},
		{method: "POST", path: "/console/api/accounts/{id}/enable", perm: manage, stepUp: true, action: "account.enable", h: (*rc).enableAccount},
		{method: "POST", path: "/console/api/accounts/{id}/reset", perm: manage, stepUp: true, action: "account.reset", h: (*rc).resetAccount},
		{method: "POST", path: "/console/api/accounts/{id}/unlock", perm: manage, stepUp: true, action: "account.unlock", h: (*rc).unlockAccount},
	}
	rs = append(rs,
		route{method: "GET", path: auditPath, perm: ps.AuditPerm, action: actionAuditQuery, h: (*rc).auditQuery},
		route{method: "GET", path: auditRequestPath, perm: ps.AuditPerm, action: actionAuditQuery, h: (*rc).auditRequest},
		route{method: "GET", path: auditIMPath, perm: ps.AuditPerm, action: actionAuditQuery, h: (*rc).auditIM},
	)
	if ps.Emergency != "" { // 运维空间没有应急授权（PRD-ops AC-OPS-02-9）
		rs = append(rs, route{method: "POST", path: "/console/api/me/emergency-grants", perm: ps.Emergency, stepUp: true, action: "account.emergency_grant", h: (*rc).emergencyGrant})
	} else {
		rs = append(rs, route{method: "POST", path: "/console/api/me/emergency-grants", perm: "admin.emergency", action: "account.emergency_grant", h: func(*rc) {}})
	}
	return rs
}

// checkRoute：未声明权限点的路由启动失败（AC-CON-06-1）。
func checkRoute(rt route) {
	if !rt.public && rt.perm == "" {
		panic("route without permission: " + rt.method + " " + rt.path)
	}
}

func (a *App) apiMux(s space.Space) *http.ServeMux {
	ps := perm.For(s.Name)
	mux := http.NewServeMux()
	for _, rt := range a.apiRoutes(ps) {
		checkRoute(rt)
		mux.HandleFunc(rt.method+" "+rt.path, a.serve(rt, s, ps))
	}
	// 账号不能删除（F-CON-02 规则 5、AC-CON-02-11）。下面的兜底路由匹配所有方法，所以这里要显式写。
	mux.HandleFunc("DELETE /console/api/accounts/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	// 审计只读（F-CON-09 规则 5）：不依赖默认行为，显式回 405。
	for _, path := range []string{auditPath, auditRequestPath, auditIMPath} {
		for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
			mux.HandleFunc(method+" "+path, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Allow", "GET")
				w.WriteHeader(http.StatusMethodNotAllowed)
			})
		}
	}
	mux.HandleFunc("/console/api/", func(w http.ResponseWriter, r *http.Request) {
		// 还没实现的业务接口也要先过会话：未登录的请求是 401，不暴露路由是否存在。
		c := &rc{a: a, w: w, r: r, ctx: r.Context(), space: s, ps: ps}
		if !a.loadSession(c) {
			return
		}
		if c.sess.State == "setup" {
			c.fail(apierr.New(apierr.SetupRequired, "finish setting up two-step verification first"))
			return
		}
		c.fail(apierr.New(apierr.NotFound, "not found"))
	})
	return mux
}

func (a *App) serve(rt route, s space.Space, ps perm.Space) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := &rc{a: a, w: w, r: r, ctx: r.Context(), space: s, ps: ps, route: rt, ua: r.UserAgent(), requestID: ids.New(a.Clock.Now())}
		if ip, ok := httpx.ClientIP(r, a.Cfg.TrustedProxies); ok {
			c.ip = ip.String()
		}
		safe := r.Method == http.MethodGet || r.Method == http.MethodHead
		if rt.public {
			if !safe && !a.originOK(c) {
				a.rejected.WithLabelValues("csrf").Inc()
				c.fail(apierr.New(apierr.CSRFInvalid, "request origin not allowed"))
				return
			}
			rt.h(c)
			return
		}
		if !a.loadSession(c) {
			return
		}
		if c.sess.State == "setup" && !rt.allowSetup {
			c.fail(apierr.New(apierr.SetupRequired, "finish setting up two-step verification first"))
			return
		}
		if !safe && !a.csrfOK(c) {
			a.rejected.WithLabelValues("csrf").Inc()
			a.Log.Info("request rejected", "space", s.Name, "reason", "csrf")
			c.fail(apierr.New(apierr.CSRFInvalid, "invalid CSRF token or origin"))
			return
		}
		if !ps.Has(c.roles, rt.perm) {
			action := rt.action
			if action == "" {
				action = rt.method + " " + rt.path
			}
			a.recordDenied(c, action)
			c.fail(apierr.New(apierr.Forbidden, "permission denied"))
			return
		}
		if rt.stepUp && !a.stepUpFresh(c) {
			c.fail(apierr.New(apierr.StepUpRequired, "verify your one-time code first"))
			return
		}
		rt.h(c)
	}
}

func (a *App) originOK(c *rc) bool {
	return c.space.Origin == "" || c.r.Header.Get("Origin") == c.space.Origin
}

func (a *App) csrfOK(c *rc) bool {
	if !a.originOK(c) {
		return false
	}
	got := secret.SessionHash(c.r.Header.Get("X-CSRF-Token"))
	return subtle.ConstantTimeCompare([]byte(got), []byte(c.sess.CSRFHash)) == 1
}

const stepUpWindow = 5 * time.Minute

func (a *App) stepUpFresh(c *rc) bool {
	return c.sess.StepUpAt > 0 && c.now()-c.sess.StepUpAt <= stepUpWindow.Milliseconds()
}

// base 是审计记录的公共字段。
func (c *rc) base(phase, action string) audit.Record {
	return audit.Record{
		Space: c.space.Name, Phase: phase, RequestID: c.requestID, AccountID: c.acct.ID, Username: c.acct.Username, Roles: c.roles,
		Actor: c.acct.Username, IP: c.ip, UA: truncate(c.ua, 512), Action: action,
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

// event 写一条事件记录（认证事件）。
func (c *rc) event(action string, target audit.Target, params map[string]any, result string, code int) error {
	r := c.base(audit.PhaseEvent, action)
	r.Target, r.Params, r.Result, r.Code = target, params, result, code
	err := c.a.Audit.Write(context.WithoutCancel(c.ctx), r)
	if err != nil {
		c.a.Log.Error("audit event write failed", "action", action, "requestId", c.requestID, "err", err)
	}
	return err
}

// audited 是写操作的两阶段审计（F-CON-08 规则 4）：intent 写失败不执行、返回 5031；
// result 写失败时操作已经生效，照常返回真实结果，由对账任务补齐。im-server 超时 → 504 / 5040，result 记 unknown。
func (c *rc) audited(action string, target audit.Target, params map[string]any, reason string, fn func() (any, error)) {
	r := c.base(audit.PhaseIntent, action)
	r.Target, r.Params, r.Reason = target, params, reason
	if err := c.a.Audit.Write(c.ctx, r); err != nil {
		c.a.Log.Error("audit intent write failed; request rejected", "action", action, "requestId", c.requestID, "err", err)
		c.fail(apierr.New(apierr.AuditUnavailable, "audit service unavailable, the operation was not performed"))
		return
	}
	resp, err := fn()
	res := c.base(audit.PhaseResult, action)
	res.Target, res.Reason = target, reason
	var e *apierr.Error
	switch {
	case err == nil:
		res.Result = audit.Success
	case errors.Is(err, imclient.ErrResultUnknown):
		res.Result, res.Code = audit.Unknown, apierr.ResultUnknown
		err = apierr.New(apierr.ResultUnknown, "result unknown, refresh to confirm and do not resubmit")
	case errors.As(err, &e):
		res.Result, res.Code = audit.Failure, e.Code
		if e.Code == apierr.NotFound && strings.HasPrefix(action, "account.") {
			res.Result = audit.Denied // 对另一个空间的账号操作（F-CON-02 规则 7）
		}
	default:
		res.Result, res.Code = audit.Failure, apierr.Internal
	}
	if werr := c.a.Audit.Write(context.WithoutCancel(c.ctx), res); werr != nil {
		c.a.resultFailures.Inc()
		c.a.Log.Error("audit result write failed", "action", action, "requestId", c.requestID, "err", werr)
	}
	if err != nil {
		c.failErr(action, err)
		return
	}
	c.ok(resp)
}
