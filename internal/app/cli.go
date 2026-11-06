package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"

	"github.com/jackc/pgx/v5"

	"tianting/console/internal/audit"
	"tianting/console/internal/ids"
	"tianting/console/internal/notify"
	"tianting/console/internal/perm"
	"tianting/console/internal/secret"
)

// CLIActor 是命令行操作的操作人：cli:{操作系统用户}@{主机名}。
func CLIActor() string {
	name := "unknown"
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	host, _ := os.Hostname()
	return "cli:" + name + "@" + host
}

// Bootstrap 创建空间的超管（F-CON-02 规则 2）。同名账号还没激活时重发激活码。
//
// 管理空间：已有启用的超管时拒绝。运维空间：启用的超管（含待激活）少于 2 个时可以执行，否则没有第二个人能批准
// （PRD-ops F-OPS-02 规则 6），写审计并通知全部超管和审计员。达到 2 个后拒绝，只能走双人批准；唯一的例外是一个超管都还没激活时，
// 给已有的待激活超管重发激活码：不增加超管，否则两个激活码都过期后这个空间就再也进不去了。
func (a *App) Bootstrap(ctx context.Context, spaceName, username string) (string, error) {
	ps := perm.For(spaceName)
	if ps.Name != spaceName {
		return "", fmt.Errorf("unknown space %q", spaceName)
	}
	if !usernameRe.MatchString(username) {
		return "", errors.New("username must match [a-z0-9._-]{3,32}")
	}
	code, err := randomCode(20)
	if err != nil {
		return "", err
	}
	now := a.Clock.Now().UnixMilli()
	actor := CLIActor()
	err = pgx.BeginFunc(ctx, a.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "superadmins:"+spaceName); err != nil {
			return err
		}
		var active int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM auth.accounts a JOIN auth.account_roles r ON r.account_id = a.id WHERE a.space = $1 AND a.status = 'active' AND r.role = $2`, spaceName, ps.SuperAdmin).Scan(&active); err != nil {
			return err
		}
		var id, status string
		err := tx.QueryRow(ctx, `SELECT id::text, status FROM auth.accounts WHERE space = $1 AND username = $2`, spaceName, username).Scan(&id, &status)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if ps.BootstrapLimit == 0 {
			if active > 0 {
				return fmt.Errorf("space %s already has an active super admin", spaceName)
			}
		} else if err := a.bootstrapAllowed(ctx, tx, ps, active, id, status); err != nil {
			return err
		}
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			id = ids.New(a.Clock.Now())
			if _, err := tx.Exec(ctx, `INSERT INTO auth.accounts (id, space, username, display_name, status, activation_hash, activation_expires, created_at) VALUES ($1::uuid, $2, $3, $3, 'pending', $4, $5, $6)`,
				id, spaceName, username, secret.PepperHash(a.pepper(), code), now+activationTTL, now); err != nil {
				return err
			}
		case err != nil:
			return err
		case status != "pending":
			return fmt.Errorf("account %s exists and is %s", username, status)
		default:
			if _, err := tx.Exec(ctx, `UPDATE auth.accounts SET activation_hash = $2, activation_expires = $3, password_hash = '' WHERE id = $1::uuid`, id, secret.PepperHash(a.pepper(), code), now+activationTTL); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `DELETE FROM auth.account_roles WHERE account_id = $1::uuid`, id); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `DELETE FROM auth.totp WHERE account_id = $1::uuid`, id); err != nil {
				return err
			}
			// 命令行直接给了超管，这个账号之前的待批准作废（已过期的留给过期处理写审计）。
			if _, err := tx.Exec(ctx, `UPDATE auth.role_grant_requests SET status = 'cancelled', decided_by_name = $2, decided_at = $3
				WHERE account_id = $1::uuid AND status = 'pending' AND requested_at > $4`, id, actor, now, a.grantCutoff()); err != nil {
				return err
			}
		}
		return insertRoles(ctx, tx, id, []string{ps.SuperAdmin}, actor, now)
	})
	if err != nil {
		return "", err
	}
	if err := a.Audit.Write(ctx, audit.Record{Space: spaceName, Phase: audit.PhaseEvent, RequestID: ids.New(a.Clock.Now()), Actor: actor, Action: "account.bootstrap",
		Target: audit.NewTarget("account", username), Result: audit.Success}); err != nil {
		return "", err
	}
	if ps.BootstrapLimit > 0 {
		// 通知失败不影响结果：账号已经建好，激活码只有这一次机会显示。审计里有这次操作。
		if err := a.notifier().ToRoles(ctx, a.DB, spaceName, []string{ps.SuperAdmin, ps.Auditor}, "", notify.KindBootstrap,
			map[string]any{"who": username, "by": actor, "at": now}); err != nil {
			a.Log.Error("notify bootstrap", "err", err)
		}
	}
	return code, nil
}

// bootstrapAllowed 是运维空间的上限判断。调用方持有超管集合的锁。id、status 是同名账号，没有时为空。
func (a *App) bootstrapAllowed(ctx context.Context, tx pgx.Tx, ps perm.Space, active int, id, status string) error {
	var total int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM auth.accounts a JOIN auth.account_roles r ON r.account_id = a.id
		WHERE a.space = $1 AND a.status IN ('active', 'pending') AND r.role = $2`, ps.Name, ps.SuperAdmin).Scan(&total); err != nil {
		return err
	}
	if total < ps.BootstrapLimit {
		return nil
	}
	if active == 0 && status == "pending" {
		var isSuper bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM auth.account_roles WHERE account_id = $1::uuid AND role = $2)`, id, ps.SuperAdmin).Scan(&isSuper); err != nil {
			return err
		}
		if isSuper {
			return nil
		}
	}
	return fmt.Errorf("space %s already has %d super admins (pending activation included); further grants need two-person approval", ps.Name, total)
}

// CLIUnlock 是命令行解锁（应急），写审计。
func (a *App) CLIUnlock(ctx context.Context, spaceName, username string) error {
	if err := Unlock(ctx, a.DB, spaceName, normalizeUsername(username)); err != nil {
		return err
	}
	return a.Audit.Write(ctx, audit.Record{Space: spaceName, Phase: audit.PhaseEvent, RequestID: ids.New(a.Clock.Now()), Actor: CLIActor(), Action: "account.unlock",
		Target: audit.NewTarget("account", username), Result: audit.Success})
}
