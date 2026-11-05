package app

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"tianting/console/internal/apierr"
	"tianting/console/internal/audit"
	"tianting/console/internal/ids"
	"tianting/console/internal/imclient"
)

// PRD-live 4.7 节：系统通知的 5040 对账与重放。
//
//	im-server 审计          结论         重放
//	result 2xx              success      不重放
//	result 4xx、5xx         failed       不重放，运营修正后新发
//	只有 intent，没有 result  unknown      用同一 pushId 重放
//	没有 intent              notExecuted  用同一 pushId 重放
//
// 重放只有一次，不重走双人复核，不受 5 分钟间隔约束，也不写"最近一次全员发送时间"（sent_at 不变）。
// 距首次发送超过 pushReplayWindow 不再重放，记录标 unknown，由运营判断。

const (
	// pushReplayWindow：通知有时效，晚到比不到更容易误导（未校准）。
	pushReplayWindow = time.Hour
	replayOperator   = "system:reconcile"
)

// pushConclude 把对账结论写进发送记录。要在审计 result 之前调用：进程在两步之间崩溃时，下一轮会再算一次，这里是幂等的。
func (a *App) pushConclude(ctx context.Context, in audit.Stored, result string, code int) error {
	var err error
	switch in.Action {
	case actionPushUser, actionPushApprove:
		status := pushReplayDue
		switch {
		case result == audit.Success:
			status = pushSuccess
		case result == audit.Failure && code != 0:
			status = pushFailed
		}
		_, err = a.DB.Exec(ctx, `UPDATE biz.push_records SET status = $2, error_code = $3 WHERE request_id = $1 AND status IN ('sending', 'unknown', 'replay_due') AND replay_request_id IS NULL`, in.RequestID, status, code)
	case actionPushReplay:
		// 重放本身的结果未知：能查到结论就更新，查不到就停在 unknown。不会有第二次重放。
		status := pushUnknown
		switch {
		case result == audit.Success:
			status = pushSuccess
		case result == audit.Failure && code != 0:
			status = pushFailed
		}
		_, err = a.DB.Exec(ctx, `UPDATE biz.push_records SET status = $2, error_code = $3 WHERE replay_request_id = $1 AND status IN ('unknown', 'replay_due')`, in.RequestID, status, code)
	}
	return err
}

type replayRow struct {
	id, kind, typ, data, targets, pushID, requestID string
	sentAt                                          int64
}

// replayPushes 执行到期的重放。调用方持有对账的 advisory lock。
func (a *App) replayPushes(ctx context.Context, now time.Time) error {
	if a.IM == nil {
		return nil
	}
	rows, err := a.DB.Query(ctx, `SELECT id::text, kind, type, data, targets, im_push_id, request_id, sent_at FROM biz.push_records
		WHERE status = 'replay_due' AND replay_request_id IS NULL ORDER BY sent_at LIMIT $1`, reconcileBatch)
	if err != nil {
		return err
	}
	due, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (replayRow, error) {
		var x replayRow
		err := r.Scan(&x.id, &x.kind, &x.typ, &x.data, &x.targets, &x.pushID, &x.requestID, &x.sentAt)
		return x, err
	})
	if err != nil {
		return err
	}
	var firstErr error
	for _, r := range due {
		if err := a.replayOne(ctx, r, now); err != nil {
			a.Log.Warn("push replay skipped", "recordId", r.id, "requestId", r.requestID, "err", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func (a *App) replayOne(ctx context.Context, r replayRow, now time.Time) error {
	base := audit.Record{Space: "admin", Actor: replayOperator, Username: replayOperator, Target: audit.NewTarget("push", r.pushID)}
	data := []byte(r.data)
	if now.UnixMilli()-r.sentAt > pushReplayWindow.Milliseconds() {
		if _, err := a.DB.Exec(ctx, `UPDATE biz.push_records SET status = $2, replay_expired = true WHERE id = $1::uuid AND status = 'replay_due'`, r.id, pushUnknown); err != nil {
			return err
		}
		ev := base
		ev.Phase, ev.RequestID, ev.Action, ev.Result = audit.PhaseEvent, ids.New(now), "push.replay.expired", audit.Unknown
		ev.Params = map[string]any{"pushId": r.pushID, "requestId": r.requestID}
		return a.Audit.Write(ctx, ev)
	}
	var targets []string
	if err := json.Unmarshal([]byte(r.targets), &targets); err != nil {
		return err
	}
	replayID := ids.New(now)
	// 先领走这一次重放，再写 intent、再调用：之后任何一步崩溃都不会有第二次。
	tag, err := a.DB.Exec(ctx, `UPDATE biz.push_records SET replay_request_id = $2, replay_at = $3 WHERE id = $1::uuid AND status = 'replay_due' AND replay_request_id IS NULL`, r.id, replayID, now.UnixMilli())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return nil
	}
	params := pushAuditParams(r.kind, r.pushID, r.typ, data, len(targets))
	params["requestId"] = r.requestID
	intent := base
	intent.Phase, intent.RequestID, intent.Action, intent.Params = audit.PhaseIntent, replayID, actionPushReplay, params
	if err := a.Audit.Write(ctx, intent); err != nil {
		// intent 写不进去不能执行。放回去，下一轮再试。
		if _, uerr := a.DB.Exec(ctx, `UPDATE biz.push_records SET replay_request_id = NULL, replay_at = NULL WHERE id = $1::uuid`, r.id); uerr != nil {
			a.Log.Error("release push replay failed", "recordId", r.id, "err", uerr)
		}
		return err
	}
	body, err := imPushBody(r.kind, targets, r.typ, r.pushID, data)
	if err != nil {
		return err
	}
	var out imPushReply
	callErr := a.IM.Do(ctx, imclient.Call{Operator: replayOperator, RequestID: replayID}, "POST", "/admin/push", nil, body, &out)
	res := base
	res.Phase, res.RequestID, res.Action = audit.PhaseResult, replayID, actionPushReplay
	res.Params = map[string]any{"pushId": r.pushID, "requestId": r.requestID}
	var e *apierr.Error
	var uerr error
	switch {
	case callErr == nil:
		res.Result = audit.Success
		res.Params["created"] = out.Created
		_, uerr = a.DB.Exec(ctx, `UPDATE biz.push_records SET status = $2, replay_created = $3, accepted = COALESCE(accepted, $4) WHERE id = $1::uuid`, r.id, pushSuccess, out.Created, out.Accepted)
	case errors.Is(callErr, imclient.ErrResultUnknown):
		res.Result, res.Code = audit.Unknown, apierr.ResultUnknown
		_, uerr = a.DB.Exec(ctx, `UPDATE biz.push_records SET status = $2 WHERE id = $1::uuid`, r.id, pushUnknown)
	case errors.As(callErr, &e):
		res.Result, res.Code = audit.Failure, e.Code
		_, uerr = a.DB.Exec(ctx, `UPDATE biz.push_records SET status = $2, error_code = $3 WHERE id = $1::uuid`, r.id, pushFailed, e.Code)
	default:
		res.Result, res.Code = audit.Unknown, apierr.ResultUnknown
		_, uerr = a.DB.Exec(ctx, `UPDATE biz.push_records SET status = $2 WHERE id = $1::uuid`, r.id, pushUnknown)
	}
	if werr := a.Audit.Write(ctx, res); werr != nil {
		a.resultFailures.Inc()
		a.Log.Error("audit result write failed", "action", actionPushReplay, "requestId", replayID, "err", werr)
	}
	return uerr
}

// pushRetention：审计在线 1 年，再加密归档 CON_AUDIT_ARCHIVE_YEARS 年。
func (a *App) pushRetention() time.Duration {
	return time.Duration(1+a.Cfg.Archive.Years) * 366 * 24 * time.Hour
}
