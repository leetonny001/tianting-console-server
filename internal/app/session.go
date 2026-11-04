package app

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"tianting/console/internal/apierr"
	"tianting/console/internal/secret"
)

const (
	idleTimeout     = 30 * time.Minute
	absoluteTimeout = 12 * time.Hour
	maxSessions     = 3
)

// 4014 的 reason（F-CON-05 规则 6）。
const (
	reasonNone      = "none"
	reasonIdle      = "idle"
	reasonAbsolute  = "absolute"
	reasonLoggedOut = "loggedOut"
	reasonRevoked   = "revoked"
	reasonReplaced  = "replaced"
)

type sessionRow struct {
	IDHash, AccountID, State, CSRFHash, Revoked string
	CreatedAt, LastActive, StepUpAt             int64
	StepUpFailures                              int
}

type accountRow struct {
	ID, Space, Username, DisplayName, Status, PasswordHash string
	PasswordHistory                                        []string
	ActivationHash                                         string
	ActivationExpires, CreatedAt, ActivatedAt              int64
}

const accountColumns = `id::text, space, username, display_name, status, password_hash, password_history, activation_hash, activation_expires, created_at, activated_at`

func scanAccount(row pgx.Row) (accountRow, error) {
	var a accountRow
	err := row.Scan(&a.ID, &a.Space, &a.Username, &a.DisplayName, &a.Status, &a.PasswordHash, &a.PasswordHistory, &a.ActivationHash, &a.ActivationExpires, &a.CreatedAt, &a.ActivatedAt)
	return a, err
}

func authRequired(reason string) *apierr.Error {
	e := apierr.New(apierr.AuthRequired, "not signed in")
	e.Reason = reason
	return e
}

// pepper：开发环境没配置 CON_HASH_PEPPER 时用固定值（生产环境启动保护要求必须配置）。
func (a *App) pepper() []byte {
	if len(a.Cfg.HashPepper) > 0 {
		return a.Cfg.HashPepper
	}
	return []byte("development-only-pepper")
}

// csrfToken 由会话 ID 派生：库里只存哈希，刷新页面后还能算出同一个令牌（不轮换，F-CON-05 规则 7）。
func (a *App) csrfToken(sid string) string {
	m := hmac.New(sha256.New, a.pepper())
	m.Write([]byte("csrf|" + sid))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// loadSession 校验 Cookie。查询带 space 条件：别的空间的 Cookie 按没有会话处理（规则 2）。失败时已经写好响应。
func (a *App) loadSession(c *rc) bool {
	reject := func(reason string) bool {
		if reason == reasonNone {
			a.rejected.WithLabelValues("noSession").Inc()
		}
		c.fail(authRequired(reason))
		return false
	}
	cookie, err := c.r.Cookie(c.space.CookieName)
	if err != nil || cookie.Value == "" {
		return reject(reasonNone)
	}
	c.sid = cookie.Value
	hash := secret.SessionHash(c.sid)
	var s sessionRow
	err = a.DB.QueryRow(c.ctx, `SELECT id_hash, account_id::text, state, csrf_token_hash, revoked_reason, created_at, last_active_at, step_up_at, step_up_failures
		FROM auth.sessions WHERE id_hash = $1 AND space = $2`, hash, c.space.Name).
		Scan(&s.IDHash, &s.AccountID, &s.State, &s.CSRFHash, &s.Revoked, &s.CreatedAt, &s.LastActive, &s.StepUpAt, &s.StepUpFailures)
	if errors.Is(err, pgx.ErrNoRows) {
		return reject(reasonNone)
	}
	if err != nil {
		c.failErr("load session", err)
		return false
	}
	now := c.now()
	switch {
	case s.Revoked != "":
		return reject(s.Revoked)
	case now-s.CreatedAt > absoluteTimeout.Milliseconds():
		return reject(reasonAbsolute)
	case now-s.LastActive > idleTimeout.Milliseconds():
		return reject(reasonIdle)
	}
	acct, err := scanAccount(a.DB.QueryRow(c.ctx, `SELECT `+accountColumns+` FROM auth.accounts WHERE id = $1::uuid`, s.AccountID))
	if err != nil {
		c.failErr("load account", err)
		return false
	}
	if acct.Status == "disabled" {
		return reject(reasonRevoked)
	}
	roles, err := a.activeRoles(c.ctx, acct.ID)
	if err != nil {
		c.failErr("load roles", err)
		return false
	}
	// 后台轮询不续期（规则 3）。
	if c.r.Header.Get("X-Console-Background") != "1" {
		if _, err := a.DB.Exec(c.ctx, `UPDATE auth.sessions SET last_active_at = $2 WHERE id_hash = $1`, hash, now); err != nil {
			c.failErr("touch session", err)
			return false
		}
	}
	c.sess, c.acct, c.roles = s, acct, roles
	return true
}

// activeRoles 返回未过期的角色（应急授权到期按 [C 钟] 判断，不需要定时任务）。
func (a *App) activeRoles(ctx context.Context, accountID string) ([]string, error) {
	rows, err := a.DB.Query(ctx, `SELECT role FROM auth.account_roles WHERE account_id = $1::uuid AND (expires_at IS NULL OR expires_at > $2) ORDER BY role`, accountID, a.Clock.Now().UnixMilli())
	if err != nil {
		return nil, err
	}
	roles, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	if roles == nil {
		roles = []string{}
	}
	return roles, nil
}

// newSession 建会话：新的随机 ID（防会话固定），超过 3 个时最早的标记 replaced。
func (a *App) newSession(ctx context.Context, tx pgx.Tx, accountID, spaceName, state string, now int64) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	sid := base64.RawURLEncoding.EncodeToString(raw)
	// 锁账号行：同一账号并发登录时，"最多 3 个"也要成立。
	if _, err := tx.Exec(ctx, `SELECT 1 FROM auth.accounts WHERE id = $1::uuid FOR UPDATE`, accountID); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `UPDATE auth.sessions SET revoked_reason = $2 WHERE id_hash IN (
		SELECT id_hash FROM auth.sessions
		WHERE account_id = $1::uuid AND revoked_reason = '' AND created_at > $3 AND last_active_at > $4
		ORDER BY created_at DESC, id_hash OFFSET $5)`,
		accountID, reasonReplaced, now-absoluteTimeout.Milliseconds(), now-idleTimeout.Milliseconds(), maxSessions-1); err != nil {
		return "", err
	}
	_, err := tx.Exec(ctx, `INSERT INTO auth.sessions (id_hash, account_id, space, state, csrf_token_hash, created_at, last_active_at) VALUES ($1, $2::uuid, $3, $4, $5, $6, $6)`,
		secret.SessionHash(sid), accountID, spaceName, state, secret.SessionHash(a.csrfToken(sid)), now)
	return sid, err
}

func (c *rc) setCookie(sid string) {
	http.SetCookie(c.w, &http.Cookie{Name: c.space.CookieName, Value: sid, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

func (c *rc) sessionPayload() map[string]any {
	return map[string]any{
		"account":   map[string]any{"id": c.acct.ID, "username": c.acct.Username, "displayName": c.acct.DisplayName, "space": c.acct.Space},
		"roles":     c.roles,
		"perms":     c.ps.Perms(c.roles),
		"state":     c.sess.State,
		"csrfToken": c.a.csrfToken(c.sid),
	}
}

func (c *rc) session() { c.ok(c.sessionPayload()) }

func (c *rc) logout() {
	if _, err := c.a.DB.Exec(c.ctx, `UPDATE auth.sessions SET revoked_reason = $2 WHERE id_hash = $1`, c.sess.IDHash, reasonLoggedOut); err != nil {
		c.failErr("logout", err)
		return
	}
	_ = c.event("auth.logout", accountTarget(c.acct), nil, "success", 0)
	http.SetCookie(c.w, &http.Cookie{Name: c.space.CookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	c.ok(struct{}{})
}

// revokeAll 让账号的全部会话失效。except 非空时保留那一个（改密码）。
func revokeAll(ctx context.Context, q pgx.Tx, accountID, except string) error {
	_, err := q.Exec(ctx, `UPDATE auth.sessions SET revoked_reason = $2 WHERE account_id = $1::uuid AND revoked_reason = '' AND id_hash <> $3`, accountID, reasonRevoked, except)
	return err
}
