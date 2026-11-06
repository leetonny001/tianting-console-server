package app

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"tianting/console/internal/apierr"
	"tianting/console/internal/audit"
	"tianting/console/internal/ids"
	"tianting/console/internal/notify"
	"tianting/console/internal/perm"
	"tianting/console/internal/secret"
)

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func conflict(format string, args ...any) *apierr.Error {
	return apierr.New(apierr.AccountConflict, format, args...)
}

func accountNotFound() *apierr.Error { return apierr.New(apierr.NotFound, "account not found") }

type accountJSON struct {
	ID          string   `json:"id"`
	Username    string   `json:"username"`
	DisplayName string   `json:"displayName"`
	Status      string   `json:"status"`
	Roles       []string `json:"roles"`
	CreatedAt   int64    `json:"createdAt"`
	ActivatedAt int64    `json:"activatedAt"`
	Locked      bool     `json:"locked"`
	// PendingRoles 是已授予、还没有第二个超管批准的角色（PRD-ops F-OPS-02 规则 6）。还没有生效，不在 Roles 里。
	PendingRoles []pendingRoleJSON `json:"pendingRoles"`
}

type pendingRoleJSON struct {
	Role        string `json:"role"`
	RequestedBy string `json:"requestedBy"`
	RequestedAt int64  `json:"requestedAt"`
	ExpiresAt   int64  `json:"expiresAt"`
	// Replaces、With：批准时去掉的现有角色、一起生效的角色。页面据此显示批准之后的角色。
	Replaces []string `json:"replaces"`
	With     []string `json:"with"`
}

func (c *rc) accountView(a accountRow) (accountJSON, error) {
	roles, err := c.a.activeRoles(c.ctx, a.ID)
	if err != nil {
		return accountJSON{}, err
	}
	var until int64
	if err := c.a.DB.QueryRow(c.ctx, `SELECT COALESCE(MAX(locked_until), 0) FROM auth.login_failures WHERE space = $1 AND username = $2`, a.Space, a.Username).Scan(&until); err != nil {
		return accountJSON{}, err
	}
	rows, err := c.a.DB.Query(c.ctx, `SELECT role, requested_by_name, requested_at, requested_at + $2::bigint, replaces_roles, with_roles FROM auth.role_grant_requests
		WHERE account_id = $1::uuid AND status = 'pending' AND requested_at > $3 ORDER BY role`, a.ID, roleGrantTTL.Milliseconds(), c.a.grantCutoff())
	if err != nil {
		return accountJSON{}, err
	}
	pending, err := pgx.CollectRows(rows, pgx.RowToStructByPos[pendingRoleJSON])
	if err != nil {
		return accountJSON{}, err
	}
	if pending == nil {
		pending = []pendingRoleJSON{}
	}
	return accountJSON{a.ID, a.Username, a.DisplayName, a.Status, roles, a.CreatedAt, a.ActivatedAt, until > c.now(), pending}, nil
}

// listAccounts：查询带 space 条件，看不到另一个空间的账号（F-CON-02 规则 7）。
func (c *rc) listAccounts() {
	c.expireGrants()
	q := c.r.URL.Query()
	limit := 20
	switch q.Get("limit") {
	case "", "20":
	case "50":
		limit = 50
	case "100":
		limit = 100
	default:
		c.fail(apierr.New(apierr.BadRequest, "limit must be 20, 50 or 100"))
		return
	}
	prefix := normalizeUsername(q.Get("username"))
	rows, err := c.a.DB.Query(c.ctx, `SELECT `+accountColumns+` FROM auth.accounts
		WHERE space = $1 AND username > $2 AND ($3 = '' OR (username >= $3 AND username < $3 || chr(1114111))) ORDER BY username LIMIT $4`,
		c.space.Name, q.Get("cursor"), prefix, limit+1)
	if err != nil {
		c.failErr("list accounts", err)
		return
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (accountRow, error) { return scanAccount(r) })
	if err != nil {
		c.failErr("list accounts", err)
		return
	}
	next := ""
	if len(list) > limit {
		list = list[:limit]
		next = list[limit-1].Username
	}
	out := make([]accountJSON, 0, len(list))
	for _, a := range list {
		v, err := c.accountView(a)
		if err != nil {
			c.failErr("account view", err)
			return
		}
		out = append(out, v)
	}
	c.ok(map[string]any{"accounts": out, "nextCursor": next})
}

// target 找本空间的账号；其他空间和不存在的一样返回 nil。
func (c *rc) target() (*accountRow, error) {
	id := c.r.PathValue("id")
	if !uuidRe.MatchString(id) {
		return nil, nil
	}
	a, err := scanAccount(c.a.DB.QueryRow(c.ctx, `SELECT `+accountColumns+` FROM auth.accounts WHERE id = $1::uuid AND space = $2`, id, c.space.Name))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &a, err
}

func (c *rc) getAccount() {
	c.expireGrants()
	a, err := c.target()
	if err != nil {
		c.failErr("get account", err)
		return
	}
	if a == nil {
		c.fail(accountNotFound())
		return
	}
	v, err := c.accountView(*a)
	if err != nil {
		c.failErr("account view", err)
		return
	}
	c.ok(v)
}

func (a *App) checkRoles(ps perm.Space, roles []string) *apierr.Error {
	if len(roles) == 0 {
		return apierr.New(apierr.BadRequest, "at least one role is required")
	}
	for _, r := range roles {
		if !ps.ValidRole(r) {
			return apierr.New(apierr.BadRequest, "unknown role %s", r)
		}
	}
	if ps.RolesConflict(roles) {
		return conflict("this role cannot be combined with other roles")
	}
	return nil
}

func (c *rc) createAccount() {
	var req struct {
		Username    string   `json:"username"`
		DisplayName string   `json:"displayName"`
		Roles       []string `json:"roles"`
	}
	if !c.readJSON(&req) {
		return
	}
	if !usernameRe.MatchString(req.Username) {
		c.fail(apierr.New(apierr.BadRequest, "username must match [a-z0-9._-]{3,32}"))
		return
	}
	if n := utf8.RuneCountInString(req.DisplayName); n < 1 || n > 64 {
		c.fail(apierr.New(apierr.BadRequest, "displayName must be 1-64 characters"))
		return
	}
	req.Roles = uniqueRoles(req.Roles)
	if e := c.a.checkRoles(c.ps, req.Roles); e != nil {
		c.fail(e)
		return
	}
	effective, pending := c.splitGrant(req.Roles, nil)
	// 激活码只在响应里出现一次，不进审计。
	c.audited("account.create", audit.NewTarget("account", req.Username), map[string]any{"roles": req.Roles, "pendingRoles": pending}, "", func() (any, error) {
		code, err := randomCode(20)
		if err != nil {
			return nil, err
		}
		now := c.now()
		id := ids.New(c.a.Clock.Now())
		err = pgx.BeginFunc(c.ctx, c.a.DB, func(tx pgx.Tx) error {
			if _, err := tx.Exec(c.ctx, `INSERT INTO auth.accounts (id, space, username, display_name, status, activation_hash, activation_expires, created_at) VALUES ($1::uuid, $2, $3, $4, 'pending', $5, $6, $7)`,
				id, c.space.Name, req.Username, req.DisplayName, secret.PepperHash(c.a.pepper(), code), now+activationTTL, now); err != nil {
				return err
			}
			if err := insertRoles(c.ctx, tx, id, effective, c.acct.Username, now); err != nil {
				return err
			}
			return c.syncPending(tx, id, pending, nil, nil)
		})
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, apierr.New(apierr.AccountExists, "username already exists in this space")
		}
		if err != nil {
			return nil, err
		}
		c.notifySensitive(req.Username, req.Roles, nil, pending)
		return map[string]any{"id": id, "username": req.Username, "activationCode": code, "pendingRoles": pending}, nil
	})
}

func uniqueRoles(roles []string) []string {
	out := slices.Clone(roles)
	slices.Sort(out)
	return slices.Compact(out)
}

func insertRoles(ctx context.Context, tx pgx.Tx, id string, roles []string, by string, now int64) error {
	for _, r := range roles {
		if _, err := tx.Exec(ctx, `INSERT INTO auth.account_roles (account_id, role, granted_by, granted_at) VALUES ($1::uuid, $2, $3, $4)`, id, r, by, now); err != nil {
			return err
		}
	}
	return nil
}

// splitGrant 把请求的角色分成马上生效的和要第二个超管批准的（PRD-ops F-OPS-02 规则 6）。已经有的角色不用再批准。
func (c *rc) splitGrant(requested, before []string) (effective, pending []string) {
	effective, pending = []string{}, []string{}
	for _, r := range requested {
		if slices.Contains(c.ps.ApprovalRoles, r) && !slices.Contains(before, r) {
			pending = append(pending, r)
		} else {
			effective = append(effective, r)
		}
	}
	return effective, pending
}

// notifySensitive：新获得敏感角色时通知审计员（F-CON-06 规则 5）。pending 是其中还没生效的。
func (c *rc) notifySensitive(who string, roles, before, pending []string) {
	for _, r := range roles {
		if slices.Contains(c.ps.Sensitive, r) && !slices.Contains(before, r) {
			payload := map[string]any{"who": who, "role": r, "by": c.acct.Username, "at": c.now()}
			if slices.Contains(pending, r) {
				payload["pending"] = true
			}
			if err := c.a.notifier().ToRoles(context.WithoutCancel(c.ctx), c.a.DB, c.space.Name, []string{c.ps.Auditor}, "", notify.KindSensitiveRole, payload); err != nil {
				c.a.Log.Error("notify sensitive role", "err", err)
			}
		}
	}
}

// spaceLock：同一空间的超管集合变化串行化，防止两个超管并发互相停用（F-CON-02 规则 8）。
// 拿到锁之后再确认操作人自己还有效：并发的另一方可能已经把他停用了。
func (c *rc) spaceLock(tx pgx.Tx) error {
	if _, err := tx.Exec(c.ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "superadmins:"+c.space.Name); err != nil {
		return err
	}
	var status, revoked string
	err := tx.QueryRow(c.ctx, `SELECT a.status, s.revoked_reason FROM auth.accounts a JOIN auth.sessions s ON s.account_id = a.id WHERE s.id_hash = $1`, c.sess.IDHash).Scan(&status, &revoked)
	if err != nil {
		return err
	}
	if status != "active" || revoked != "" {
		return authRequired(reasonRevoked)
	}
	return nil
}

// keepsSuper：去掉 target 之后空间里还有启用的超管吗。
func (c *rc) keepsSuper(tx pgx.Tx, targetID string) error {
	var n int
	err := tx.QueryRow(c.ctx, `SELECT count(*) FROM auth.accounts a JOIN auth.account_roles r ON r.account_id = a.id
		WHERE a.space = $1 AND a.status = 'active' AND r.role = $2 AND (r.expires_at IS NULL OR r.expires_at > $3) AND a.id <> $4::uuid`,
		c.space.Name, c.ps.SuperAdmin, c.now(), targetID).Scan(&n)
	if err != nil {
		return err
	}
	if n == 0 {
		return conflict("the space must keep at least one active super admin")
	}
	return nil
}

func (c *rc) isSuper(tx pgx.Tx, targetID string) (bool, error) {
	var n int
	err := tx.QueryRow(c.ctx, `SELECT count(*) FROM auth.account_roles WHERE account_id = $1::uuid AND role = $2`, targetID, c.ps.SuperAdmin).Scan(&n)
	return n > 0, err
}

// withTarget 是账号写操作的公共流程：找目标（跨空间 → 4040 denied）、自我保护、写审计。
func (c *rc) withTarget(action string, reason string, params map[string]any, fn func(a accountRow) (any, error)) {
	a, err := c.target()
	if err != nil {
		c.failErr(action, err)
		return
	}
	name := c.r.PathValue("id")
	if a != nil {
		name = a.Username
	}
	c.audited(action, audit.NewTarget("account", name), params, reason, func() (any, error) {
		if a == nil {
			return nil, accountNotFound()
		}
		return fn(*a)
	})
}

func (c *rc) setRoles() {
	var req struct {
		Roles []string `json:"roles"`
	}
	if !c.readJSON(&req) {
		return
	}
	req.Roles = uniqueRoles(req.Roles)
	if len(c.ps.ApprovalRoles) > 0 {
		if err := c.a.ExpireRoleGrants(c.ctx); err != nil { // 过期的不能挡住新的待批准
			c.failErr("account.roles", err)
			return
		}
	}
	c.withTarget("account.roles", "", map[string]any{"roles": req.Roles}, func(a accountRow) (any, error) {
		if a.ID == c.acct.ID {
			return nil, conflict("you cannot change your own roles")
		}
		if e := c.a.checkRoles(c.ps, req.Roles); e != nil {
			return nil, e
		}
		before, err := c.a.activeRoles(c.ctx, a.ID)
		if err != nil {
			return nil, err
		}
		effective, pending := c.splitGrant(req.Roles, before)
		// 待批准期间权限按未生效前的角色计算（F-OPS-02 规则 6）：这次改动要去掉现有角色时，整个改动等批准后才生效，
		// 拒绝或过期后账号的角色不变。否则互斥角色（ops_viewer → ops_superadmin）要么先丢权限，要么批准时冲突。
		var replaces, with []string
		if len(pending) > 0 {
			for _, r := range before {
				if !slices.Contains(req.Roles, r) {
					replaces = append(replaces, r)
				}
			}
			if len(replaces) > 0 {
				for _, r := range effective {
					if !slices.Contains(before, r) {
						with = append(with, r)
					}
				}
				effective = slices.Sorted(slices.Values(before))
			}
		}
		// 只是多了一个待批准的角色时，实际权限没变，会话不用失效。
		unchanged := len(pending) > 0 && slices.Equal(effective, slices.Sorted(slices.Values(before)))
		err = pgx.BeginFunc(c.ctx, c.a.DB, func(tx pgx.Tx) error {
			if err := c.spaceLock(tx); err != nil {
				return err
			}
			if !unchanged {
				if a.Status == "active" && slices.Contains(before, c.ps.SuperAdmin) && !slices.Contains(req.Roles, c.ps.SuperAdmin) {
					if err := c.keepsSuper(tx, a.ID); err != nil {
						return err
					}
				}
				if _, err := tx.Exec(c.ctx, `DELETE FROM auth.account_roles WHERE account_id = $1::uuid`, a.ID); err != nil {
					return err
				}
				if err := insertRoles(c.ctx, tx, a.ID, effective, c.acct.Username, c.now()); err != nil {
					return err
				}
			}
			if err := c.syncPending(tx, a.ID, pending, replaces, with); err != nil {
				return err
			}
			if unchanged {
				return nil
			}
			return revokeAll(c.ctx, tx, a.ID, "") // 重新登录后按新角色（F-CON-05 规则 4）
		})
		if err != nil {
			return nil, err
		}
		c.resultParams = map[string]any{"roles": effective, "pendingRoles": pending}
		c.notifySensitive(a.Username, req.Roles, before, pending)
		return map[string]any{"roles": effective, "pendingRoles": pending}, nil
	})
}

func (c *rc) disableAccount() {
	c.withTarget("account.disable", "", nil, func(a accountRow) (any, error) {
		if a.ID == c.acct.ID {
			return nil, conflict("you cannot disable yourself")
		}
		return struct{}{}, pgx.BeginFunc(c.ctx, c.a.DB, func(tx pgx.Tx) error {
			if err := c.spaceLock(tx); err != nil {
				return err
			}
			super, err := c.isSuper(tx, a.ID)
			if err != nil {
				return err
			}
			var status string
			if err := tx.QueryRow(c.ctx, `SELECT status FROM auth.accounts WHERE id = $1::uuid`, a.ID).Scan(&status); err != nil {
				return err
			}
			if super && status == "active" {
				if err := c.keepsSuper(tx, a.ID); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(c.ctx, `UPDATE auth.accounts SET status = 'disabled' WHERE id = $1::uuid`, a.ID); err != nil {
				return err
			}
			return revokeAll(c.ctx, tx, a.ID, "")
		})
	})
}

func (c *rc) enableAccount() {
	c.withTarget("account.enable", "", nil, func(a accountRow) (any, error) {
		if a.Status != "disabled" {
			return struct{}{}, nil
		}
		// 从未激活过的账号回到待激活，激活过的回到启用。
		next := "pending"
		if a.PasswordHash != "" && a.ActivatedAt > 0 {
			next = "active"
		}
		_, err := c.a.DB.Exec(c.ctx, `UPDATE auth.accounts SET status = $2 WHERE id = $1::uuid`, a.ID, next)
		return struct{}{}, err
	})
}

// resetAccount：回到待激活，旧密码、TOTP、恢复码、全部会话作废，生成新激活码。
func (c *rc) resetAccount() {
	c.withTarget("account.reset", "", nil, func(a accountRow) (any, error) {
		if a.ID == c.acct.ID {
			return nil, conflict("you cannot reset yourself")
		}
		code, err := randomCode(20)
		if err != nil {
			return nil, err
		}
		now := c.now()
		err = pgx.BeginFunc(c.ctx, c.a.DB, func(tx pgx.Tx) error {
			if err := c.spaceLock(tx); err != nil {
				return err
			}
			super, err := c.isSuper(tx, a.ID)
			if err != nil {
				return err
			}
			if super && a.Status == "active" {
				if err := c.keepsSuper(tx, a.ID); err != nil {
					return err
				}
			}
			// password_history 保留：重置之后也不能用回最近 5 次的密码。
			if _, err := tx.Exec(c.ctx, `UPDATE auth.accounts SET status = 'pending', password_hash = '', activation_hash = $2, activation_expires = $3, activated_at = 0 WHERE id = $1::uuid`,
				a.ID, secret.PepperHash(c.a.pepper(), code), now+activationTTL); err != nil {
				return err
			}
			if _, err := tx.Exec(c.ctx, `DELETE FROM auth.totp WHERE account_id = $1::uuid`, a.ID); err != nil {
				return err
			}
			if _, err := tx.Exec(c.ctx, `DELETE FROM auth.recovery_codes WHERE account_id = $1::uuid`, a.ID); err != nil {
				return err
			}
			return revokeAll(c.ctx, tx, a.ID, "")
		})
		if err != nil {
			return nil, err
		}
		if err := c.a.notifier().ToRoles(context.WithoutCancel(c.ctx), c.a.DB, c.space.Name, []string{c.ps.SuperAdmin, c.ps.Auditor}, a.ID, notify.KindReset,
			map[string]any{"who": a.Username, "by": c.acct.Username, "at": now}); err != nil {
			c.a.Log.Error("notify reset", "err", err)
		}
		return map[string]any{"activationCode": code}, nil
	})
}

func (c *rc) unlockAccount() {
	c.withTarget("account.unlock", "", nil, func(a accountRow) (any, error) {
		return struct{}{}, Unlock(c.ctx, c.a.DB, c.space.Name, a.Username)
	})
}

// validReason：去首尾空白后 4～200 个码点，不能由同一个字符重复组成（2.3 节）。
func validReason(s string) bool {
	runes := []rune(trimSpace(s))
	if len(runes) < 4 || len(runes) > 200 {
		return false
	}
	return slices.ContainsFunc(runes, func(r rune) bool { return r != runes[0] })
}

// emergencyGrant：只能给自己，不能是审计员或空间超管，15～240 分钟（F-CON-06 规则 6）。
func (c *rc) emergencyGrant() {
	var req struct {
		Role    string `json:"role"`
		Minutes int    `json:"minutes"`
		Reason  string `json:"reason"`
	}
	if !c.readJSON(&req) {
		return
	}
	if !c.ps.ValidRole(req.Role) || req.Role == c.ps.Auditor || req.Role == c.ps.SuperAdmin || req.Minutes < 15 || req.Minutes > 240 || !validReason(req.Reason) {
		c.fail(apierr.New(apierr.BadRequest, "invalid emergency grant"))
		return
	}
	c.audited("account.emergency_grant", accountTarget(c.acct), map[string]any{"role": req.Role, "minutes": req.Minutes}, trimSpace(req.Reason), func() (any, error) {
		now := c.now()
		until := now + int64(req.Minutes)*60_000
		// 已经有的永久角色不降级成临时的。
		if _, err := c.a.DB.Exec(c.ctx, `INSERT INTO auth.account_roles (account_id, role, granted_by, granted_at, expires_at) VALUES ($1::uuid, $2, $3, $4, $5)
			ON CONFLICT (account_id, role) DO UPDATE SET expires_at = $5, granted_at = $4 WHERE auth.account_roles.expires_at IS NOT NULL`,
			c.acct.ID, req.Role, c.acct.Username, now, until); err != nil {
			return nil, err
		}
		if err := c.a.notifier().ToRoles(context.WithoutCancel(c.ctx), c.a.DB, c.space.Name, []string{c.ps.Auditor, c.ps.SuperAdmin}, c.acct.ID, notify.KindEmergencyGrant,
			map[string]any{"who": c.acct.Username, "role": req.Role, "minutes": req.Minutes, "at": now}); err != nil {
			c.a.Log.Error("notify emergency grant", "err", err)
		}
		return map[string]any{"role": req.Role, "expiresAt": until}, nil
	})
}

// recordDenied：已认证的拒绝写审计；同一账号 1 分钟内超过 20 次时，其余的在该分钟结束后合并成一条（F-CON-06 规则 3）。
func (a *App) recordDenied(c *rc, action string) {
	ctx := context.WithoutCancel(c.ctx)
	minute := c.now() / 60_000
	var total int
	err := pgx.BeginFunc(ctx, a.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO auth.denied_buffer (account_id, minute, action, total) VALUES ($1::uuid, $2, $3, 1)
			ON CONFLICT (account_id, minute, action) DO UPDATE SET total = auth.denied_buffer.total + 1`, c.acct.ID, minute, action); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT sum(total) FROM auth.denied_buffer WHERE account_id = $1::uuid AND minute = $2`, c.acct.ID, minute).Scan(&total); err != nil {
			return err
		}
		if total > deniedLimit {
			_, err := tx.Exec(ctx, `UPDATE auth.denied_buffer SET merged = merged + 1 WHERE account_id = $1::uuid AND minute = $2 AND action = $3`, c.acct.ID, minute, action)
			return err
		}
		return nil
	})
	if err != nil {
		a.Log.Error("record denied", "err", err)
		return
	}
	if total <= deniedLimit {
		r := c.base(audit.PhaseEvent, action)
		r.Target, r.Result, r.Code = c.denied, audit.Denied, apierr.Forbidden
		if err := a.Audit.Write(ctx, r); err != nil {
			a.Log.Error("audit denied", "err", err)
		}
	}
	if err := a.FlushDenied(ctx); err != nil {
		a.Log.Error("flush denied", "err", err)
	}
}

const deniedLimit = 20

// FlushDenied 把已经结束的分钟合并写成一条审计。下一次拒绝或定时任务触发。
func (a *App) FlushDenied(ctx context.Context) error {
	current := a.Clock.Now().UnixMilli() / 60_000
	type row struct {
		account, username, space string
		minute                   int64
		action                   string
		merged                   int
	}
	var rows []row
	err := pgx.BeginFunc(ctx, a.DB, func(tx pgx.Tx) error {
		// 先删后写：多实例下每行只被一个实例取走。
		r, err := tx.Query(ctx, `WITH gone AS (DELETE FROM auth.denied_buffer WHERE minute < $1 RETURNING account_id, minute, action, merged)
			SELECT g.account_id::text, a.username, a.space, g.minute, g.action, g.merged FROM gone g JOIN auth.accounts a ON a.id = g.account_id WHERE g.merged > 0`, current)
		if err != nil {
			return err
		}
		defer r.Close()
		for r.Next() {
			var x row
			if err := r.Scan(&x.account, &x.username, &x.space, &x.minute, &x.action, &x.merged); err != nil {
				return err
			}
			rows = append(rows, x)
		}
		return r.Err()
	})
	if err != nil {
		return err
	}
	type key struct {
		account string
		minute  int64
	}
	merged := map[key][]row{}
	for _, x := range rows {
		k := key{x.account, x.minute}
		merged[k] = append(merged[k], x)
	}
	for k, list := range merged {
		count := 0
		actions := map[string]any{}
		for _, x := range list {
			count += x.merged
			actions[x.action] = x.merged
		}
		if err := a.Audit.Write(ctx, audit.Record{
			Space: list[0].space, Phase: audit.PhaseEvent, RequestID: ids.New(a.Clock.Now()), AccountID: k.account, Username: list[0].username, Actor: list[0].username,
			Action: "authz.denied_merged", Params: map[string]any{"count": count, "actions": actions, "minute": k.minute}, Result: audit.Denied, Code: apierr.Forbidden,
		}); err != nil {
			return err
		}
	}
	return nil
}
