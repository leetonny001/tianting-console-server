package app

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"tianting/console/internal/apierr"
	"tianting/console/internal/audit"
	"tianting/console/internal/ids"
)

// 运维空间的双人批准（PRD-ops F-OPS-02 规则 6）：授予 ApprovalRoles 里的角色先进入待批准，
// 另一名启用的超管批准才生效；任一启用的超管可以拒绝；7 天没有处理自动失效。

const (
	actionRoleApprove = "account.role_approve"
	actionRoleReject  = "ops.role.reject"
	actionRoleExpire  = "ops.role.expire"

	roleGrantTTL = 7 * 24 * time.Hour
)

// grantCutoff：requested_at 不大于它的待批准已经过期（[C 钟]）。判断都按时间，不依赖状态被改过，所以不需要定时任务才生效。
func (a *App) grantCutoff() int64 { return a.Clock.Now().Add(-roleGrantTTL).UnixMilli() }

// ExpireRoleGrants 把过期的待批准标成 expired 并写 ops.role.expire。读写时调用；定时任务也调用，只是让审计及时。
//
// 只写一次：行锁（SKIP LOCKED）让多实例不会处理同一行；审计和状态不在同一个事务（审计有自己的哈希链事务），
// 所以写之前按 request_id 查一下，上一次写完审计、没来得及改状态的不会重复写。审计写失败时状态不变，下次再试。
func (a *App) ExpireRoleGrants(ctx context.Context) error {
	ctx = context.WithoutCancel(ctx) // 请求断开时不要停在写完审计、没改状态的地方
	return pgx.BeginFunc(ctx, a.DB, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT r.id::text, a.space, a.username, r.role, r.requested_by_name, r.requested_at
			FROM auth.role_grant_requests r JOIN auth.accounts a ON a.id = r.account_id
			WHERE r.status = 'pending' AND r.requested_at <= $1 ORDER BY r.requested_at FOR UPDATE OF r SKIP LOCKED LIMIT 100`, a.grantCutoff())
		if err != nil {
			return err
		}
		type expired struct {
			id, space, username, role, requestedBy string
			requestedAt                            int64
		}
		list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (expired, error) {
			var e expired
			err := r.Scan(&e.id, &e.space, &e.username, &e.role, &e.requestedBy, &e.requestedAt)
			return e, err
		})
		if err != nil {
			return err
		}
		now := a.Clock.Now().UnixMilli()
		for _, e := range list {
			var written bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM audit.records WHERE request_id = $1 AND action = $2)`, e.id, actionRoleExpire).Scan(&written); err != nil {
				return err
			}
			if !written {
				if err := a.Audit.Write(ctx, audit.Record{Space: e.space, Phase: audit.PhaseEvent, RequestID: e.id, Actor: "system", Action: actionRoleExpire,
					Target: audit.NewTarget("account", e.username), Params: map[string]any{"role": e.role, "requestedBy": e.requestedBy, "requestedAt": e.requestedAt}, Result: audit.Success}); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(ctx, `UPDATE auth.role_grant_requests SET status = 'expired', decided_at = $2 WHERE id = $1::uuid`, e.id, now); err != nil {
				return err
			}
		}
		return nil
	})
}

// expireGrants 是请求路径上的调用：失败只记日志，列表和批准都按时间判断过期，结果不受影响。
func (c *rc) expireGrants() {
	if len(c.ps.ApprovalRoles) == 0 {
		return
	}
	if err := c.a.ExpireRoleGrants(c.ctx); err != nil {
		c.a.Log.Error("expire role grants", "err", err, "requestId", c.requestID)
	}
}

// syncPending 让账号的待批准角色等于 pending：不再要的作废，已有的保留原发起人和原时间（重复提交不能延长 7 天）。
func (c *rc) syncPending(tx pgx.Tx, accountID string, pending, replaces, with []string) error {
	if len(c.ps.ApprovalRoles) == 0 {
		return nil
	}
	now := c.now()
	if _, err := tx.Exec(c.ctx, `UPDATE auth.role_grant_requests SET status = 'cancelled', decided_by = $3::uuid, decided_by_name = $4, decided_at = $5
		WHERE account_id = $1::uuid AND status = 'pending' AND NOT role = ANY($2)`, accountID, pending, c.acct.ID, c.acct.Username, now); err != nil {
		return err
	}
	for _, r := range pending {
		if _, err := tx.Exec(c.ctx, `INSERT INTO auth.role_grant_requests (id, account_id, role, requested_by, requested_by_name, requested_at, status, replaces_roles, with_roles)
			VALUES ($1::uuid, $2::uuid, $3, $4::uuid, $5, $6, 'pending', $7, $8)
			ON CONFLICT (account_id, role) WHERE status = 'pending' DO UPDATE SET replaces_roles = EXCLUDED.replaces_roles, with_roles = EXCLUDED.with_roles`,
			ids.New(c.a.Clock.Now()), accountID, r, c.acct.ID, c.acct.Username, now, nonNilStrings(replaces), nonNilStrings(with)); err != nil {
			return err
		}
	}
	return nil
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// approveRole：第二个超管批准待批准的角色（AC-OPS-02-8、02-10）。发起人自己批准 403 / 4030，留一条 denied。
// 批准时重新检查账号状态和互斥角色，不满足 409 / 4093；过期、已拒绝、已撤回也是 409 / 4093。
func (c *rc) approveRole() {
	var req struct {
		Role string `json:"role"`
	}
	if !c.readJSON(&req) {
		return
	}
	if !slices.Contains(c.ps.ApprovalRoles, req.Role) {
		c.fail(apierr.New(apierr.BadRequest, "this role does not need approval"))
		return
	}
	c.expireGrants()
	a, err := c.target()
	if err != nil {
		c.failErr(actionRoleApprove, err)
		return
	}
	if a != nil {
		var requestedBy string
		err := c.a.DB.QueryRow(c.ctx, `SELECT requested_by::text FROM auth.role_grant_requests WHERE account_id = $1::uuid AND role = $2 AND status = 'pending' AND requested_at > $3`,
			a.ID, req.Role, c.a.grantCutoff()).Scan(&requestedBy)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			c.failErr(actionRoleApprove, err)
			return
		}
		if requestedBy == c.acct.ID || a.ID == c.acct.ID {
			c.denied = audit.NewTarget("account", a.Username)
			c.a.recordDenied(c, actionRoleApprove)
			c.fail(&apierr.Error{Code: apierr.Forbidden, Msg: "another super admin must approve this grant", Reason: "ownGrant"})
			return
		}
	}
	c.withTarget(actionRoleApprove, "", map[string]any{"role": req.Role}, func(a accountRow) (any, error) {
		var requestedByName string
		err := pgx.BeginFunc(c.ctx, c.a.DB, func(tx pgx.Tx) error {
			if err := c.spaceLock(tx); err != nil {
				return err
			}
			var requestID, status string
			var replaces, with []string
			err := tx.QueryRow(c.ctx, `SELECT r.id::text, r.requested_by_name, a.status, r.replaces_roles, r.with_roles FROM auth.role_grant_requests r JOIN auth.accounts a ON a.id = r.account_id
				WHERE r.account_id = $1::uuid AND r.role = $2 AND r.status = 'pending' AND r.requested_at > $3 FOR UPDATE OF r`, a.ID, req.Role, c.a.grantCutoff()).Scan(&requestID, &requestedByName, &status, &replaces, &with)
			if errors.Is(err, pgx.ErrNoRows) {
				return conflict("no pending grant for this role")
			}
			if err != nil {
				return err
			}
			if status == "disabled" {
				return conflict("the account is disabled")
			}
			rows, err := tx.Query(c.ctx, `SELECT role FROM auth.account_roles WHERE account_id = $1::uuid`, a.ID)
			if err != nil {
				return err
			}
			current, err := pgx.CollectRows(rows, pgx.RowTo[string])
			if err != nil {
				return err
			}
			if slices.Contains(current, req.Role) {
				return conflict("the account already has this role")
			}
			next := slices.DeleteFunc(current, func(r string) bool { return slices.Contains(replaces, r) })
			add := []string{req.Role}
			for _, r := range with {
				if !slices.Contains(next, r) {
					add = append(add, r)
				}
			}
			if c.ps.RolesConflict(append(next, add...)) {
				return conflict("this role cannot be combined with other roles")
			}
			if _, err := tx.Exec(c.ctx, `DELETE FROM auth.account_roles WHERE account_id = $1::uuid AND role = ANY($2)`, a.ID, replaces); err != nil {
				return err
			}
			if err := insertRoles(c.ctx, tx, a.ID, add, c.acct.Username, c.now()); err != nil {
				return err
			}
			if _, err := tx.Exec(c.ctx, `UPDATE auth.role_grant_requests SET status = 'approved', decided_by = $2::uuid, decided_by_name = $3, decided_at = $4 WHERE id = $1::uuid`,
				requestID, c.acct.ID, c.acct.Username, c.now()); err != nil {
				return err
			}
			return revokeAll(c.ctx, tx, a.ID, "") // 角色变化：重新登录后按新角色（F-CON-05 规则 4）
		})
		if err != nil {
			return nil, err
		}
		c.resultParams = map[string]any{"role": req.Role, "requestedBy": requestedByName}
		c.notifySensitive(a.Username, []string{req.Role}, nil, nil)
		return map[string]any{"role": req.Role}, nil
	})
}

// rejectRole：任一启用的超管拒绝，发起人拒绝等于撤回（AC-OPS-02-11）。理由必填，角色不变，会话不受影响。
// 重新验证由路由检查，所以 4038 先于理由的 4000。
func (c *rc) rejectRole() {
	var req struct {
		Role   string `json:"role"`
		Reason string `json:"reason"`
	}
	if !c.readJSON(&req) {
		return
	}
	if !slices.Contains(c.ps.ApprovalRoles, req.Role) {
		c.fail(apierr.New(apierr.BadRequest, "this role does not need approval"))
		return
	}
	reason, e := CheckReason(req.Reason)
	if e != nil {
		c.fail(e)
		return
	}
	c.expireGrants()
	c.withTarget(actionRoleReject, reason, map[string]any{"role": req.Role}, func(a accountRow) (any, error) {
		var requestedByName string
		err := pgx.BeginFunc(c.ctx, c.a.DB, func(tx pgx.Tx) error {
			if err := c.spaceLock(tx); err != nil {
				return err
			}
			var requestID string
			err := tx.QueryRow(c.ctx, `SELECT id::text, requested_by_name FROM auth.role_grant_requests
				WHERE account_id = $1::uuid AND role = $2 AND status = 'pending' AND requested_at > $3 FOR UPDATE`, a.ID, req.Role, c.a.grantCutoff()).Scan(&requestID, &requestedByName)
			if errors.Is(err, pgx.ErrNoRows) {
				return conflict("no pending grant for this role")
			}
			if err != nil {
				return err
			}
			_, err = tx.Exec(c.ctx, `UPDATE auth.role_grant_requests SET status = 'rejected', decided_by = $2::uuid, decided_by_name = $3, decided_at = $4 WHERE id = $1::uuid`,
				requestID, c.acct.ID, c.acct.Username, c.now())
			return err
		})
		if err != nil {
			return nil, err
		}
		c.resultParams = map[string]any{"role": req.Role, "requestedBy": requestedByName}
		return map[string]any{"role": req.Role}, nil
	})
}
