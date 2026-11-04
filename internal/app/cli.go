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

// Bootstrap 创建空间的第一个超管：已有启用的超管时拒绝（F-CON-02 规则 2）。同名账号还没激活时重发激活码。
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
		if active > 0 {
			return fmt.Errorf("space %s already has an active super admin", spaceName)
		}
		var id, status string
		err := tx.QueryRow(ctx, `SELECT id::text, status FROM auth.accounts WHERE space = $1 AND username = $2`, spaceName, username).Scan(&id, &status)
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
	return code, nil
}

// CLIUnlock 是命令行解锁（应急），写审计。
func (a *App) CLIUnlock(ctx context.Context, spaceName, username string) error {
	if err := Unlock(ctx, a.DB, spaceName, normalizeUsername(username)); err != nil {
		return err
	}
	return a.Audit.Write(ctx, audit.Record{Space: spaceName, Phase: audit.PhaseEvent, RequestID: ids.New(a.Clock.Now()), Actor: CLIActor(), Action: "account.unlock",
		Target: audit.NewTarget("account", username), Result: audit.Success})
}
