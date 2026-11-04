package app

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"tianting/console/internal/ids"
	"tianting/console/internal/imclient"
	"tianting/console/internal/opsnode"
)

// CS-112：节点探测。结果存 Postgres，多实例看到的一致；总览和节点列表只读这里，不在用户请求时扇出（F-OPS-04 规则 4）。

const (
	probeEvery       = 5 * time.Second
	unreachableAfter = 15 * time.Second
	versionWarnAfter = 30 * time.Minute
)

// 节点状态。
const (
	nodeReady       = "ready"
	nodeDraining    = "draining"
	nodeNotReady    = "notReady"
	nodeUnreachable = "unreachable"
	nodeIdentity    = "identityFailed"
)

// nodeSnapshot 是 /internal/v1/node 的响应。
type nodeSnapshot struct {
	NodeID               string         `json:"nodeId"`
	Version              string         `json:"version"`
	StartedAt            int64          `json:"startedAt"`
	Ready                bool           `json:"ready"`
	Draining             bool           `json:"draining"`
	Connections          map[string]int `json:"connections"`
	TotalConns           int            `json:"totalConns"`
	LiveBytes            uint64         `json:"liveBytes"`
	HeapBytes            uint64         `json:"heapBytes"`
	StackBytes           uint64         `json:"stackBytes"`
	GoMemLimit           uint64         `json:"goMemLimit"`
	Goroutines           uint64         `json:"goroutines"`
	DisconnectBufferFrom int64          `json:"disconnectBufferFrom"`
}

// NodeView 是节点列表的一行。
type NodeView struct {
	nodeSnapshot
	NodeID     string `json:"nodeId"`
	Addr       string `json:"addr"`
	Status     string `json:"status"`
	LastSeenAt int64  `json:"lastSeenAt"`
}

// ProbeNodes 探测全部节点。多实例下 5 秒内只有一个实例真的探测。
func (a *App) ProbeNodes(ctx context.Context) error {
	if a.Nodes == nil {
		return nil
	}
	now := a.Clock.Now().UnixMilli()
	// 留 1 秒余量：定时器抖动时不至于跳过一轮。at > now 是时钟回拨（测试模式）。
	var claimed bool
	err := a.DB.QueryRow(ctx, `UPDATE biz.ops_probe SET at = $1 WHERE id = 1 AND (at <= $2 OR at > $1) RETURNING true`, now, now-(probeEvery-time.Second).Milliseconds()).Scan(&claimed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	type outcome struct {
		raw     []byte
		version string
	}
	results := make(map[string]outcome, len(a.Nodes.Nodes))
	var probeMu sync.Mutex
	failed := a.Nodes.Each(ctx, func(ctx context.Context, n *opsnode.Node) error {
		var snap json.RawMessage
		if err := n.Call(ctx, imclient.Call{Operator: "ops:probe", RequestID: ids.New(a.Clock.Now())}, "GET", "/internal/v1/node", nil, &snap); err != nil {
			return err
		}
		var parsed nodeSnapshot
		if err := json.Unmarshal(snap, &parsed); err != nil {
			return err
		}
		probeMu.Lock()
		results[n.Entry.NodeID] = outcome{snap, parsed.Version}
		probeMu.Unlock()
		return nil
	})
	versions := map[string]bool{}
	for _, n := range a.Nodes.Nodes {
		id := n.Entry.NodeID
		if err := failed[id]; err != nil {
			failure := nodeUnreachable
			if errors.Is(err, opsnode.ErrIdentity) {
				failure = nodeIdentity
			}
			if _, err := a.DB.Exec(ctx, `INSERT INTO biz.ops_node_status (node_id, last_probe_at, failure) VALUES ($1, $2, $3)
				ON CONFLICT (node_id) DO UPDATE SET last_probe_at = $2, failure = $3`, id, now, failure); err != nil {
				return err
			}
			continue
		}
		r := results[id]
		versions[r.version] = true
		if _, err := a.DB.Exec(ctx, `INSERT INTO biz.ops_node_status (node_id, snapshot, last_seen_at, last_probe_at, failure) VALUES ($1, $2, $3, $3, '')
			ON CONFLICT (node_id) DO UPDATE SET snapshot = $2, last_seen_at = $3, last_probe_at = $3, failure = ''`, id, string(r.raw), now); err != nil {
			return err
		}
	}
	// 版本不一致从什么时候开始。恢复一致就清零。
	since := int64(0)
	if len(versions) > 1 {
		since = now
	}
	_, err = a.DB.Exec(ctx, `UPDATE biz.ops_probe SET version_mismatch_since = CASE WHEN $1::bigint = 0 THEN 0 WHEN version_mismatch_since = 0 THEN $1 ELSE version_mismatch_since END WHERE id = 1`, since)
	return err
}

// nodeStatus 判定状态：身份校验失败最优先（不再信任这个节点）；其次是是否可达；最后才看节点自己报的状态。
func nodeStatus(failure string, lastSeen, now int64, snap nodeSnapshot) string {
	switch {
	case failure == nodeIdentity:
		return nodeIdentity
	case lastSeen == 0 || now-lastSeen > unreachableAfter.Milliseconds():
		return nodeUnreachable
	case snap.Draining:
		return nodeDraining
	case !snap.Ready:
		return nodeNotReady
	}
	return nodeReady
}

// loadNodes 读探测结果。静态节点从凭证表来：不可达时也一直在列表里。
func (a *App) loadNodes(ctx context.Context) ([]NodeView, int64, error) {
	now := a.Clock.Now().UnixMilli()
	rows, err := a.DB.Query(ctx, `SELECT node_id, snapshot, last_seen_at, failure FROM biz.ops_node_status`)
	if err != nil {
		return nil, 0, err
	}
	type row struct {
		snap     string
		lastSeen int64
		failure  string
	}
	stored := map[string]row{}
	defer rows.Close()
	for rows.Next() {
		var id string
		var r row
		if err := rows.Scan(&id, &r.snap, &r.lastSeen, &r.failure); err != nil {
			return nil, 0, err
		}
		stored[id] = r
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	var mismatch int64
	if err := a.DB.QueryRow(ctx, `SELECT version_mismatch_since FROM biz.ops_probe WHERE id = 1`).Scan(&mismatch); err != nil {
		return nil, 0, err
	}
	out := make([]NodeView, 0, len(stored))
	if a.Nodes != nil {
		for _, n := range a.Nodes.Nodes {
			r := stored[n.Entry.NodeID]
			var snap nodeSnapshot
			if r.snap != "" {
				_ = json.Unmarshal([]byte(r.snap), &snap)
			}
			out = append(out, NodeView{nodeSnapshot: snap, NodeID: n.Entry.NodeID, Addr: n.Entry.Addr, Status: nodeStatus(r.failure, r.lastSeen, now, snap), LastSeenAt: r.lastSeen})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out, mismatch, nil
}

// missingNodes 是不可达或身份校验失败的节点。
func missingNodes(list []NodeView) []string {
	var out []string
	for _, n := range list {
		if n.Status == nodeUnreachable || n.Status == nodeIdentity {
			out = append(out, n.NodeID)
		}
	}
	return out
}

func (c *rc) opsNodes() {
	list, mismatch, err := c.a.loadNodes(c.ctx)
	if err != nil {
		c.failErr("ops nodes", err)
		return
	}
	c.opsOK(map[string]any{"nodes": list, "versions": versionInfo(list, mismatch, c.now())}, missingNodes(list))
}

type versionsView struct {
	List          []string `json:"list"`
	Mismatch      bool     `json:"mismatch"`
	MismatchSince int64    `json:"mismatchSince,omitempty"`
	Over30Min     bool     `json:"over30Min"`
}

func versionInfo(list []NodeView, since, now int64) versionsView {
	seen := map[string]bool{}
	v := versionsView{List: []string{}}
	for _, n := range list {
		if n.Version != "" && !seen[n.Version] {
			seen[n.Version] = true
			v.List = append(v.List, n.Version)
		}
	}
	sort.Strings(v.List)
	v.Mismatch = len(v.List) > 1
	if v.Mismatch && since > 0 {
		v.MismatchSince = since
		v.Over30Min = now-since >= versionWarnAfter.Milliseconds()
	}
	return v
}
