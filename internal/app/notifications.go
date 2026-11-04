package app

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"tianting/console/internal/apierr"
)

func trimSpace(s string) string { return strings.TrimSpace(s) }

type notificationJSON struct {
	ID        string          `json:"id"`
	Kind      string          `json:"kind"`
	Payload   json.RawMessage `json:"payload"`
	CreatedAt int64           `json:"createdAt"`
	Read      bool            `json:"read"`
}

// listNotifications：只看自己的，新的在前。保留 90 天，超过的不返回（清理任务随 CS-015）。
func (c *rc) listNotifications() {
	before := int64(1) << 62
	if v := c.r.URL.Query().Get("cursor"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			c.fail(apierr.New(apierr.BadRequest, "invalid cursor"))
			return
		}
		before = n
	}
	const limit = 20
	rows, err := c.a.DB.Query(c.ctx, `SELECT id::text, kind, payload::text, created_at, read_at IS NOT NULL FROM auth.notifications
		WHERE account_id = $1::uuid AND created_at < $2 AND created_at > $3 ORDER BY created_at DESC LIMIT $4`, c.acct.ID, before, c.now()-90*86_400_000, limit+1)
	if err != nil {
		c.failErr("list notifications", err)
		return
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (notificationJSON, error) {
		var n notificationJSON
		var payload string
		err := r.Scan(&n.ID, &n.Kind, &payload, &n.CreatedAt, &n.Read)
		n.Payload = json.RawMessage(payload)
		return n, err
	})
	if err != nil {
		c.failErr("list notifications", err)
		return
	}
	next := ""
	if len(list) > limit {
		list = list[:limit]
		next = strconv.FormatInt(list[limit-1].CreatedAt, 10)
	}
	if list == nil {
		list = []notificationJSON{}
	}
	c.ok(map[string]any{"notifications": list, "nextCursor": next})
}

func (c *rc) unreadCount() {
	var n int
	if err := c.a.DB.QueryRow(c.ctx, `SELECT count(*) FROM auth.notifications WHERE account_id = $1::uuid AND read_at IS NULL`, c.acct.ID).Scan(&n); err != nil {
		c.failErr("unread count", err)
		return
	}
	c.ok(map[string]any{"unread": n})
}

func (c *rc) markRead() {
	if _, err := c.a.DB.Exec(c.ctx, `UPDATE auth.notifications SET read_at = $2 WHERE account_id = $1::uuid AND read_at IS NULL`, c.acct.ID, c.now()); err != nil {
		c.failErr("mark read", err)
		return
	}
	c.ok(struct{}{})
}
