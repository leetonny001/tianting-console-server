package app

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"tianting/console/internal/apierr"
	"tianting/console/internal/audit"
	"tianting/console/internal/notify"
)

type pgconnTag = pgconn.CommandTag

const (
	failLimit    = 5
	failWindow   = 15 * time.Minute
	failLock     = 15 * time.Minute
	globalLimit  = 50
	globalWindow = time.Hour
	globalLock   = time.Hour
	ipRatePerMin = 20
)

func keyNameIP(space, username, ip string) string { return "n|" + space + "|" + username + "|" + ip }
func keyName(space, username string) string       { return "g|" + space + "|" + username }

// ipAllowed 是按 IP 的限流：login + activate 每分钟 20 次。计数在库里，多实例一致。
func (c *rc) ipAllowed() bool {
	if c.a.Cfg.DisableLockout {
		return true
	}
	minute := c.now() / 60_000
	var n int
	err := c.a.DB.QueryRow(c.ctx, `INSERT INTO auth.ip_rate (ip, minute, count) VALUES ($1, $2, 1)
		ON CONFLICT (ip, minute) DO UPDATE SET count = auth.ip_rate.count + 1 RETURNING count`, c.ip, minute).Scan(&n)
	if err != nil {
		c.failErr("ip rate", err)
		return false
	}
	if n > ipRatePerMin {
		c.fail(apierr.New(apierr.RateLimited, "too many attempts, try again later"))
		return false
	}
	return true
}

// locked 判断"账号名 + IP"或账号名是否在锁定中。不管账号是否存在，响应完全相同（AC-CON-04-4）。
func (c *rc) locked(username string) (bool, error) {
	if c.a.Cfg.DisableLockout {
		return false, nil
	}
	var until int64
	err := c.a.DB.QueryRow(c.ctx, `SELECT COALESCE(MAX(locked_until), 0) FROM auth.login_failures WHERE key = ANY($1)`,
		[]string{keyNameIP(c.space.Name, username, c.ip), keyName(c.space.Name, username)}).Scan(&until)
	return until > c.now(), err
}

func lockedError() *apierr.Error {
	return apierr.New(apierr.LoginLocked, "too many failed attempts, try again later")
}

// bump 给一个键加一次失败，达到上限时上锁。返回这次是否新上锁。
func bump(ctx context.Context, q pgx.Tx, key, space, username string, now int64, limit int, window, lock time.Duration) (bool, error) {
	var count int
	err := q.QueryRow(ctx, `INSERT INTO auth.login_failures (key, space, username, count, window_start) VALUES ($1, $2, $3, 1, $4)
		ON CONFLICT (key) DO UPDATE SET
			count = CASE WHEN auth.login_failures.window_start <= $5 THEN 1 ELSE auth.login_failures.count + 1 END,
			window_start = CASE WHEN auth.login_failures.window_start <= $5 THEN $4 ELSE auth.login_failures.window_start END
		RETURNING count`, key, space, username, now, now-window.Milliseconds()).Scan(&count)
	if err != nil || count < limit {
		return false, err
	}
	_, err = q.Exec(ctx, `UPDATE auth.login_failures SET locked_until = $2, count = 0, window_start = $3 WHERE key = $1`, key, now+lock.Milliseconds(), now)
	return err == nil, err
}

// recordFailure 记一次失败（登录、激活码、step-up 共用同一账号的计数）。新上锁且账号存在时写审计、发通知。
func (c *rc) recordFailure(username string, acct *accountRow) {
	if c.a.Cfg.DisableLockout {
		return
	}
	ctx := context.WithoutCancel(c.ctx)
	now := c.now()
	var locked bool
	err := pgx.BeginFunc(ctx, c.a.DB, func(tx pgx.Tx) error {
		a, err := bump(ctx, tx, keyNameIP(c.space.Name, username, c.ip), c.space.Name, username, now, failLimit, failWindow, failLock)
		if err != nil {
			return err
		}
		b, err := bump(ctx, tx, keyName(c.space.Name, username), c.space.Name, username, now, globalLimit, globalWindow, globalLock)
		locked = a || b
		return err
	})
	if err != nil {
		c.a.Log.Error("record login failure", "err", err, "requestId", c.requestID)
		return
	}
	if locked {
		c.afterLock(username, acct)
	}
}

// afterLock：审计，账号存在时通知本人和空间超管（F-CON-04 规则 7）。
func (c *rc) afterLock(username string, acct *accountRow) {
	saved := c.acct
	if acct != nil {
		c.acct = *acct
	} else {
		c.acct = accountRow{Username: username}
	}
	_ = c.event("auth.lockout", audit.NewTarget("account", username), nil, audit.Failure, apierr.LoginLocked)
	c.acct = saved
	if acct == nil {
		return
	}
	ctx := context.WithoutCancel(c.ctx)
	n := c.a.notifier()
	payload := map[string]any{"who": acct.Username, "at": c.now()}
	if err := n.ToAccount(ctx, c.a.DB, acct.ID, c.space.Name, notify.KindLocked, payload); err != nil {
		c.a.Log.Error("notify locked", "err", err)
	}
	if err := n.ToRoles(ctx, c.a.DB, c.space.Name, []string{c.ps.SuperAdmin}, acct.ID, notify.KindLocked, payload); err != nil {
		c.a.Log.Error("notify locked", "err", err)
	}
}

// clearNameIP：成功登录清零"账号名 + IP"（全局计数不清，F-CON-04 规则 4）。
func (c *rc) clearNameIP(username string) {
	if _, err := c.a.DB.Exec(context.WithoutCancel(c.ctx), `DELETE FROM auth.login_failures WHERE key = $1`, keyNameIP(c.space.Name, username, c.ip)); err != nil {
		c.a.Log.Error("clear login failures", "err", err)
	}
}

// lockAccount：step-up 连续失败后锁定账号名，对所有 IP 生效 15 分钟（F-CON-07 规则 4）。
func (a *App) lockAccount(ctx context.Context, space, username string, now int64) error {
	_, err := a.DB.Exec(ctx, `INSERT INTO auth.login_failures (key, space, username, count, window_start, locked_until) VALUES ($1, $2, $3, 0, $4, $5)
		ON CONFLICT (key) DO UPDATE SET locked_until = GREATEST(auth.login_failures.locked_until, $5)`, keyName(space, username), space, username, now, now+failLock.Milliseconds())
	return err
}

// Unlock 清除账号名的全部失败计数和锁定。
func Unlock(ctx context.Context, q interface {
	Exec(context.Context, string, ...any) (pgconnTag, error)
}, space, username string) error {
	_, err := q.Exec(ctx, `DELETE FROM auth.login_failures WHERE space = $1 AND username = $2`, space, username)
	return err
}

// Housekeeping 清理过期数据：失败计数、IP 限流、过期会话、90 天前的通知，并写合并的拒绝记录。每分钟跑一次。
func (a *App) Housekeeping(ctx context.Context) error {
	now := a.Clock.Now().UnixMilli()
	for _, q := range []struct {
		sql string
		arg int64
	}{
		{`DELETE FROM auth.ip_rate WHERE minute < $1`, now/60_000 - 2},
		// 窗口最长 1 小时；还在锁定中的不删。
		{`DELETE FROM auth.login_failures WHERE window_start < $1 AND locked_until < ` + "$1", now - globalWindow.Milliseconds()},
		// 留到绝对过期之后：过期后的请求还要能拿到 absolute / idle / revoked 这些原因。
		{`DELETE FROM auth.sessions WHERE created_at < $1`, now - 2*absoluteTimeout.Milliseconds()},
		{`DELETE FROM auth.notifications WHERE created_at < $1`, now - 90*24*time.Hour.Milliseconds()},
	} {
		if _, err := a.DB.Exec(ctx, q.sql, q.arg); err != nil {
			return err
		}
	}
	return a.FlushDenied(ctx)
}
