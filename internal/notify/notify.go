// Package notify 是站内安全通知（PRD-admin F-CON-12）。内容只说"谁、什么事、何时"，不含任何凭证。
package notify

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"tianting/console/internal/ids"
)

// 通知种类。
const (
	KindBootstrap       = "account.bootstrap"
	KindActivated       = "account.activated"
	KindReset           = "account.reset"
	KindLocked          = "account.locked"
	KindRecoveryUsed    = "auth.recovery_code_used"
	KindRecoveryLow     = "auth.recovery_codes_low"
	KindSensitiveRole   = "account.sensitive_role"
	KindEmergencyGrant  = "account.emergency_grant"
	KindAuditVerifyFail = "audit.verify_failed"
	KindAnchorFail      = "audit.anchor_failed"
	KindQueryAnomaly    = "ops.troubleshoot_anomaly"
)

// DB 是发通知需要的数据库接口：连接池和事务都满足。
type DB interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

// Notifier 发通知。只发给启用的账号。
type Notifier struct {
	Now func() time.Time
}

func (n Notifier) insert(ctx context.Context, q DB, accountIDs []string, space, kind string, payload map[string]any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	now := n.Now()
	for _, id := range accountIDs {
		if _, err := q.Exec(ctx, `INSERT INTO auth.notifications (id, account_id, space, kind, payload, created_at) VALUES ($1::uuid, $2::uuid, $3, $4, $5::jsonb, $6)`,
			ids.New(now), id, space, kind, string(raw), now.UnixMilli()); err != nil {
			return err
		}
	}
	return nil
}

// ToAccount 发给一个账号。
func (n Notifier) ToAccount(ctx context.Context, q DB, accountID, space, kind string, payload map[string]any) error {
	return n.insert(ctx, q, []string{accountID}, space, kind, payload)
}

// ToRoles 发给空间里有这些角色的全部启用账号，except 是要排除的账号 ID。
func (n Notifier) ToRoles(ctx context.Context, q DB, space string, roles []string, except, kind string, payload map[string]any) error {
	rows, err := q.Query(ctx, `SELECT DISTINCT a.id::text FROM auth.accounts a JOIN auth.account_roles r ON r.account_id = a.id
		WHERE a.space = $1 AND a.status = 'active' AND r.role = ANY($2) AND a.id::text <> $3 AND (r.expires_at IS NULL OR r.expires_at > $4)`,
		space, roles, except, n.Now().UnixMilli())
	if err != nil {
		return err
	}
	list, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	return n.insert(ctx, q, list, space, kind, payload)
}
