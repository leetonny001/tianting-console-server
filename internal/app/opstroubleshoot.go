package app

import (
	"context"
	"encoding/json"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"tianting/console/internal/apierr"
	"tianting/console/internal/audit"
	"tianting/console/internal/imclient"
	"tianting/console/internal/notify"
	"tianting/console/internal/opsnode"
	"tianting/console/internal/prom"
)

// CS-114：连接排查。

const (
	actionTroubleshoot      = "ops.troubleshoot.query"
	troubleshootDaily       = 50
	troubleshootPerMinute   = 30
	troubleshootDisconnects = 50
	anomalyThreshold        = 20
	anomalyWindow           = time.Hour
)

// opsConn 是一条连接。独立类型：节点将来多返回什么也不会透传。
type opsConn struct {
	ConnID      string `json:"connId"`
	Platform    string `json:"platform"`
	ConnectedAt int64  `json:"connectedAt"`
	Node        string `json:"node"`
	IP          string `json:"ip"`
	QueueLen    int    `json:"queueLen"`
}

// opsDisconnect 是一条断开记录。没有 userId：已经按它查了，不用再回传。
type opsDisconnect struct {
	ConnID     string `json:"connId"`
	Phase      string `json:"phase"`
	Platform   string `json:"platform"`
	Code       int    `json:"code"`
	Reason     string `json:"reason"`
	By         string `json:"by"`
	TS         int64  `json:"ts"`
	DurationMs int64  `json:"durationMs"`
	IP         string `json:"ip"`
	Node       string `json:"node"`
}

func troubleshootDeniedTarget(c *rc) audit.Target {
	var req struct {
		UserID string `json:"userId"`
	}
	raw, err := io.ReadAll(io.LimitReader(c.r.Body, 1<<16))
	if err != nil || json.Unmarshal(raw, &req) != nil || !validID(req.UserID) {
		return audit.Target{}
	}
	return audit.NewTarget("user", req.UserID)
}

// disconnectSummary 是页面的汇总和两类提示（F-OPS-09 规则 4）。
func disconnectSummary(list []opsDisconnect) map[string]any {
	codes := map[int]int{}
	server, authHandshake := 0, 0
	for _, d := range list {
		codes[d.Code]++
		if d.By == "server" {
			server++
		}
		if d.Phase == "handshake" && (d.Code == 4011 || d.Code == 4012) {
			authHandshake++
		}
	}
	type codeN struct {
		Code  int `json:"code"`
		Count int `json:"count"`
	}
	out := make([]codeN, 0, len(codes))
	for c, n := range codes {
		out = append(out, codeN{c, n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Code < out[j].Code
	})
	return map[string]any{
		"codes": out, "serverClosedMajority": server*2 > len(list), "handshakeAuthMajority": authHandshake*2 > len(list),
	}
}

func (c *rc) opsTroubleshoot() {
	var req struct {
		UserID string `json:"userId"`
		Ticket string `json:"ticket"`
		Reason string `json:"reason"`
	}
	if !c.readJSON(&req) {
		return
	}
	if !validID(req.UserID) {
		c.fail(apierr.New(apierr.InvalidID, "invalid userId"))
		return
	}
	if req.Ticket == "" {
		c.fail(&apierr.Error{Code: apierr.BadRequest, Msg: "ticket is required", Reason: "ticketInvalid"})
		return
	}
	reason, ok := c.reasonTicket(req.Reason, req.Ticket)
	if !ok || !c.requireFleet() {
		return
	}
	if !c.minuteRate("ops.troubleshoot", troubleshootPerMinute) || !c.dailyQuota("ops.troubleshoot", req.UserID, troubleshootDaily) {
		return
	}
	c.ticket = req.Ticket
	// 先写审计再调用节点；写失败时 audited 不会调用 fn（AC-OPS-14-4）。
	c.audited(actionTroubleshoot, audit.NewTarget("user", req.UserID), nil, reason, func() (any, error) {
		c.watchQueryVolume(req.UserID)
		r, err := c.runTroubleshoot(req.UserID)
		if err != nil {
			return nil, err
		}
		c.resultParams = map[string]any{"count": r.count, "partial": len(r.missing) > 0, "nodes": r.queried}
		return opsEnvelope{Data: r.data, Partial: len(r.missing) > 0, MissingNodes: r.missing, DataTime: c.now()}, nil
	})
}

// watchQueryVolume：同一账号 1 小时内查了 20 个不同的 userId，通知全部审计员（AC-OPS-08-14）。窗口是滑动的，
// 通知之后 1 小时内不再发。内容只有账号名和数量，不含 userId。失败不影响这次排查：下一次查询会再判断。
func (c *rc) watchQueryVolume(userID string) {
	ctx := context.WithoutCancel(c.ctx)
	now := c.now()
	window := anomalyWindow.Milliseconds()
	err := pgx.BeginFunc(ctx, c.a.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "ops.query.watch:"+c.acct.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM biz.ops_query_recent WHERE account_id = $1::uuid AND last_at <= $2`, c.acct.ID, now-window); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO biz.ops_query_recent (account_id, user_id, last_at) VALUES ($1::uuid, $2, $3)
			ON CONFLICT (account_id, user_id) DO UPDATE SET last_at = $3`, c.acct.ID, userID, now); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM biz.ops_query_recent WHERE account_id = $1::uuid`, c.acct.ID).Scan(&n); err != nil {
			return err
		}
		if n < anomalyThreshold {
			return nil
		}
		tag, err := tx.Exec(ctx, `INSERT INTO biz.ops_query_anomalies (account_id, notified_at) VALUES ($1::uuid, $2)
			ON CONFLICT (account_id) DO UPDATE SET notified_at = $2 WHERE biz.ops_query_anomalies.notified_at <= $3`, c.acct.ID, now, now-window)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		return c.a.notifier().ToRoles(ctx, tx, c.space.Name, []string{c.ps.Auditor}, "", notify.KindQueryAnomaly,
			map[string]any{"who": c.acct.Username, "count": n, "at": now})
	})
	if err != nil {
		c.a.Log.Error("watch query volume", "err", err, "requestId", c.requestID)
	}
}

type troubleshootResult struct {
	data    map[string]any
	missing []string
	queried []string
	count   int // 所有节点返回的条数之和：和节点访问日志对账用（deploy/ops/reconcile）
}

func (c *rc) runTroubleshoot(userID string) (*troubleshootResult, error) {
	var (
		mu         sync.Mutex
		conns      = []opsConn{}
		records    = []opsDisconnect{}
		bufferFrom = map[string]int64{}
		count      int
	)
	// 同一个请求 ID 发给每个节点，审计和节点访问日志靠它对账。不带 userId。
	call := imclient.Call{Operator: c.operator(), RequestID: c.requestID}
	ctx := context.WithoutCancel(c.ctx)
	failed := c.a.Nodes.Each(ctx, func(ctx context.Context, n *opsnode.Node) error {
		var cr struct {
			Connections []opsConn `json:"connections"`
		}
		if err := n.Call(ctx, call, "POST", "/internal/v1/connections:query", map[string]any{"userId": userID}, &cr); err != nil {
			return err
		}
		var dr struct {
			Records    []opsDisconnect `json:"records"`
			BufferFrom int64           `json:"bufferFrom"`
		}
		if err := n.Call(ctx, call, "POST", "/internal/v1/disconnects:query", map[string]any{"userId": userID, "limit": troubleshootDisconnects}, &dr); err != nil {
			return err
		}
		mu.Lock()
		defer mu.Unlock()
		for i := range cr.Connections {
			cr.Connections[i].Node = n.Entry.NodeID
		}
		for i := range dr.Records {
			dr.Records[i].Node = n.Entry.NodeID
		}
		conns = append(conns, cr.Connections...)
		records = append(records, dr.Records...)
		bufferFrom[n.Entry.NodeID] = dr.BufferFrom
		count += len(cr.Connections) + len(dr.Records)
		return nil
	})
	var missing, queried []string
	for _, n := range c.a.Nodes.Nodes {
		queried = append(queried, n.Entry.NodeID)
		if failed[n.Entry.NodeID] != nil {
			missing = append(missing, n.Entry.NodeID)
		}
	}
	sort.Strings(missing)
	if missing == nil {
		missing = []string{}
	}
	sort.Slice(conns, func(i, j int) bool { return conns[i].ConnectedAt < conns[j].ConnectedAt })
	sort.SliceStable(records, func(i, j int) bool { return records[i].TS > records[j].TS })
	if len(records) > troubleshootDisconnects {
		records = records[:troubleshootDisconnects]
	}
	// 只有全部节点都响应、而且都没有连接，才能说"当前不在线"（F-OPS-08 规则 4）。
	verdict := "online"
	switch {
	case len(conns) > 0 && len(missing) > 0:
		verdict = "onlinePartial"
	case len(conns) > 0:
	case len(missing) > 0:
		verdict = "unknown"
	default:
		verdict = "offline"
	}
	unattributed := any(cardDown("Prometheus"))
	if s, err := c.a.Prom.Query(ctx, prom.QueryUnattributed); err == nil {
		m := map[string]float64{"4401": 0, "4010": 0, "4009": 0}
		for _, x := range s {
			m[x.Labels["code"]] = x.Value
		}
		unattributed = map[string]any{"counts": m}
	}
	return &troubleshootResult{
		data: map[string]any{
			"verdict": verdict, "connections": conns, "disconnects": records, "summary": disconnectSummary(records), "unattributed": unattributed,
			"bufferFrom": bufferFrom, "queriedNodes": queried, "respondedNodes": len(queried) - len(missing),
		},
		missing: missing, queried: queried, count: count,
	}, nil
}
