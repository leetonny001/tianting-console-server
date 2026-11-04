package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"

	"tianting/console/internal/audit"
	"tianting/console/internal/ids"
	"tianting/console/internal/imclient"
)

const (
	reconcileEvery  = 10 * time.Minute
	reconcileAfter  = 5 * time.Minute     // intent 超过这么久没有结论才对账（F-CON-09 规则 4）
	reconcileWindow = 31 * 24 * time.Hour // 更早的不再扫：im-server 审计查询一次最多 31 天
	reconcileBatch  = 500
)

// imAuditEntry 是 im-server GET /admin/audit 的一条（protocol/ADMIN.md）。
type imAuditEntry struct {
	ID        int64  `json:"id"`
	TS        int64  `json:"ts"`
	RequestID string `json:"requestId"`
	Route     string `json:"route"`
	Phase     string `json:"phase"`
	Code      int    `json:"code"`
}

// imAuditRaw 查 im-server 审计，原样返回条目给页面。callID 是这次查询自己的 requestId。
func (a *App) imAuditRaw(ctx context.Context, operator, callID, requestID string, from, to int64) (json.RawMessage, error) {
	var page struct {
		Entries json.RawMessage `json:"entries"`
	}
	q := url.Values{"from": {strconv.FormatInt(from, 10)}, "to": {strconv.FormatInt(to, 10)}, "requestId": {requestID}, "limit": {"200"}}
	err := a.IM.Do(ctx, imclient.Call{Operator: operator, RequestID: callID}, "GET", "/admin/audit", q, nil, &page)
	return page.Entries, err
}

// imAudit 按 requestId 查 im-server 审计。
//
// 这次查询自己用一个新的 requestId：/admin/audit 在 im-server 侧也要写审计，
// 如果沿用被查的 requestId，下一轮对账就会把这次查询当成"im-server 执行过"。
func (a *App) imAudit(ctx context.Context, operator, requestID string, from, to int64) ([]imAuditEntry, error) {
	if a.IM == nil {
		return nil, errors.New("im-server is not configured")
	}
	var page struct {
		Entries []imAuditEntry `json:"entries"`
	}
	q := url.Values{"from": {strconv.FormatInt(from, 10)}, "to": {strconv.FormatInt(to, 10)}, "requestId": {requestID}, "limit": {"200"}}
	err := a.IM.Do(ctx, imclient.Call{Operator: operator, RequestID: ids.New(a.Clock.Now())}, "GET", "/admin/audit", q, nil, &page)
	return page.Entries, err
}

// localOnlyAction：只改 console 自己数据库的动作，im-server 不知道它们，没法靠 im-server 判断结果。
func localOnlyAction(action string) bool {
	for _, p := range []string{"account.", "auth.", "audit."} {
		if strings.HasPrefix(action, p) {
			return true
		}
	}
	return false
}

// Reconcile 补写缺失的结论（F-CON-09 规则 4）：intent 超过 5 分钟没有 result，或者 result 是 unknown。
// 多实例只跑一个。im-server 查询失败时跳过这条，下一轮再试：查不到不等于没有执行。
func (a *App) Reconcile(ctx context.Context) error {
	conn, err := a.DB.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	const lockKey = "audit.reconcile"
	var locked bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtext($1))`, lockKey).Scan(&locked); err != nil {
		return err
	}
	if !locked {
		return nil
	}
	defer func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock(hashtext($1))`, lockKey)
	}()

	now := a.Clock.Now()
	rows, err := conn.Query(ctx, `SELECT `+audit.StoredColumns+` FROM audit.records i
		WHERE i.phase = 'intent' AND i.ts >= $1 AND i.ts < $2
		AND NOT EXISTS (SELECT 1 FROM audit.records r WHERE r.request_id = i.request_id AND r.phase = 'result'
			AND (r.result <> 'unknown' OR r.params LIKE '%"reconciled"%'))
		ORDER BY i.seq LIMIT $3`, now.Add(-reconcileWindow).UnixMilli(), now.Add(-reconcileAfter).UnixMilli(), reconcileBatch)
	if err != nil {
		return err
	}
	pending, err := collectStored(rows)
	if err != nil {
		return err
	}
	var firstErr error
	for _, in := range pending {
		result, code, marker, err := a.reconcileOne(ctx, in, now)
		if err != nil {
			a.Log.Warn("audit reconcile skipped", "requestId", in.RequestID, "err", err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		rec := audit.Record{
			Space: in.Space, Phase: audit.PhaseResult, RequestID: in.RequestID, AccountID: in.AccountID, Username: in.Username, Actor: in.Actor, IP: in.IP, UA: in.UA,
			Action: in.Action, Reason: in.Reason, Ticket: in.Ticket, Result: result, Code: code, Params: map[string]any{"reconciled": marker},
		}
		rec.Roles = parseJSONStrings(in.Roles)
		rec.Target = parseTarget(in.Target)
		if err := a.Audit.Write(ctx, rec); err != nil {
			return err
		}
	}
	return firstErr
}

// reconcileOne 判断一条 intent 的结论。marker 写进 params.reconciled。
func (a *App) reconcileOne(ctx context.Context, in audit.Stored, now time.Time) (result string, code int, marker any, err error) {
	if localOnlyAction(in.Action) {
		// 操作在 console 自己的事务里，im-server 查不到。不能写 notExecuted：它很可能已经生效了。
		return audit.Unknown, 0, "localOnly", nil
	}
	from := in.TS - time.Minute.Milliseconds()
	to := min(now.Add(time.Minute).UnixMilli(), from+reconcileWindow.Milliseconds())
	// 拆批的操作：im-server 那边每批一个 requestId（{requestId}.{批号}），批数在 intent 的 params.batches。
	var p struct {
		Batches int `json:"batches"`
	}
	_ = json.Unmarshal([]byte(in.Params), &p)
	ids := []string{in.RequestID}
	if p.Batches > 0 {
		ids = ids[:0]
		for i := 1; i <= p.Batches; i++ {
			ids = append(ids, batchRequestID(in.RequestID, i))
		}
	}
	seen, succeeded := 0, 0
	for _, id := range ids {
		entries, err := a.imAudit(ctx, "system:reconcile", id, from, to)
		if err != nil {
			return "", 0, nil, err
		}
		if len(entries) > 0 {
			seen++
		}
		for _, e := range entries {
			if e.Phase != "result" {
				continue
			}
			if e.Code != 0 {
				return audit.Failure, e.Code, true, nil
			}
			succeeded++
		}
	}
	switch {
	case seen == 0:
		return audit.Failure, 0, "notExecuted", nil // console 在调用前就失败了
	case succeeded == len(ids):
		return audit.Success, 0, true, nil
	case succeeded > 0:
		return audit.Unknown, 0, "partial", nil // 拆批中途停了，没有失败记录：只能确定做了一部分
	}
	return audit.Unknown, 0, "imIntentOnly", nil // im-server 写了 intent 就崩溃：只能确定它开始过
}
