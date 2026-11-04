package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"sync"

	"tianting/console/internal/apierr"
	"tianting/console/internal/audit"
	"tianting/console/internal/imclient"
	"tianting/console/internal/opsnode"
	"tianting/console/internal/prom"
)

// CS-115：配置检查。im-server 的摘要原样透传（检查项不在这里手抄），这里只算风险提示和节点间差异。

const (
	actionConfigView = "ops.config.view"
	liveBytesPerConn = 32 * 1024
)

// ConfigInput 是风险提示要用的字段（/internal/v1/config 的一部分）。
type ConfigInput struct {
	Env struct {
		Env          string `json:"env"`
		NodeIDSet    bool   `json:"nodeIdConfigured"`
		GOMEMLIMIT   int64  `json:"gomemlimit"`
		PlannedConns int    `json:"plannedConns"`
	} `json:"env"`
	Network struct {
		PprofAddr      string   `json:"pprofAddr"`
		AllowedOrigins []string `json:"allowedOrigins"`
		TrustedProxies []string `json:"trustedProxies"`
	} `json:"network"`
	Switches struct {
		TestMode bool `json:"testMode"`
	} `json:"switches"`
}

// Risk 是一条风险提示。
type Risk struct {
	Item  string `json:"item"`
	Level string `json:"level"` // high、info
	Text  string `json:"text"`
}

// ConfigRisks 是风险提示（F-OPS-10 规则 2，纯函数）。peak 是 Prometheus 近 7 天峰值连接数，0 表示拿不到。
func ConfigRisks(c ConfigInput, peak int) []Risk {
	out := []Risk{}
	add := func(item, level, text string) { out = append(out, Risk{item, level, text}) }
	prod := c.Env.Env == "production"
	if slices.Contains(c.Network.AllowedOrigins, "*") {
		add("allowedOrigins", "high", "Origin 白名单含 *：任何网站都能发起连接")
	}
	if prod && len(c.Network.TrustedProxies) == 0 {
		add("trustedProxies", "info", "如果部署在负载均衡之后，客户端 IP 和限流会失效")
	}
	if c.Env.GOMEMLIMIT <= 0 {
		add("gomemlimit", "info", "GOMEMLIMIT 未设置，请参考内存分析报告")
	} else {
		planned, source := c.Env.PlannedConns, "IM_PLANNED_CONNS"
		if planned <= 0 {
			planned, source = peak, "近 7 天峰值"
		}
		if planned > 0 && float64(c.Env.GOMEMLIMIT) < float64(planned)*liveBytesPerConn*1.5 {
			add("gomemlimit", "high", fmt.Sprintf("GOMEMLIMIT 低于规划连接数 %d（来源：%s）× 32 KB × 1.5，有 GC 风暴风险", planned, source))
		}
	}
	if !prod && !c.Env.NodeIDSet {
		add("nodeId", "info", "IM_NODE_ID 未配置：集群部署和生产环境必须配置")
	}
	if !prod && c.Network.PprofAddr != "" && c.Network.PprofAddr != "off" && !isLoopbackAddr(c.Network.PprofAddr) {
		add("pprofAddr", "high", "pprof 不是回环地址")
	}
	if !prod && c.Switches.TestMode {
		add("testMode", "info", "非生产环境开启了测试模式")
	}
	return out
}

func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

// 差异视图不比较这些：每个节点本来就不一样（规则 3）。
var diffIgnored = map[string]bool{
	"env.version": true, "env.nodeId": true, "network.addr": true, "network.metricsAddr": true, "network.adminAddr": true,
	"network.opsAddr": true, "network.pprofAddr": true, "database.location": true,
}

// ConfigDiff 是节点间取值不同的配置项。生产检查项不比较：它是逐项结论，不是配置值。
func ConfigDiff(nodes map[string]map[string]any) []map[string]any {
	flat := map[string]map[string]string{}
	for id, cfg := range nodes {
		for group, v := range cfg {
			m, ok := v.(map[string]any)
			if !ok {
				continue
			}
			for k, val := range m {
				key := group + "." + k
				if diffIgnored[key] {
					continue
				}
				if flat[key] == nil {
					flat[key] = map[string]string{}
				}
				raw, _ := json.Marshal(val)
				flat[key][id] = string(raw)
			}
		}
	}
	keys := make([]string, 0, len(flat))
	for k := range flat {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := []map[string]any{}
	for _, k := range keys {
		distinct := map[string]bool{}
		for _, v := range flat[k] {
			distinct[v] = true
		}
		if len(distinct) > 1 || len(flat[k]) != len(nodes) {
			out = append(out, map[string]any{"item": k, "values": flat[k]})
		}
	}
	return out
}

// fanoutRaw 对全部节点 GET 一个接口，原样收集 JSON。
func (c *rc) fanoutRaw(path string) (map[string]json.RawMessage, []string) {
	var mu sync.Mutex
	got := map[string]json.RawMessage{}
	call := imclient.Call{Operator: c.operator(), RequestID: c.requestID}
	failed := c.a.Nodes.Each(context.WithoutCancel(c.ctx), func(ctx context.Context, n *opsnode.Node) error {
		var raw json.RawMessage
		if err := n.Call(ctx, call, "GET", path, nil, &raw); err != nil {
			return err
		}
		mu.Lock()
		got[n.Entry.NodeID] = raw
		mu.Unlock()
		return nil
	})
	var missing []string
	for id := range failed {
		missing = append(missing, id)
	}
	return got, missing
}

func (c *rc) opsConfig() {
	if !c.requireFleet() {
		return
	}
	// 写失败不返回数据（AC-OPS-14-4）。查看配置是一次性事件，不分两阶段。
	if err := c.event(actionConfigView, audit.NewTarget("node", "*"), nil, audit.Success, 0); err != nil {
		c.fail(apierr.New(apierr.AuditUnavailable, "audit service unavailable, try again later"))
		return
	}
	got, missing := c.fanoutRaw("/internal/v1/config")
	peaks := map[string]int{}
	if s, err := c.a.Prom.Query(c.ctx, prom.QueryPeakConns); err == nil {
		for _, x := range s {
			peaks[x.Labels["node_id"]] = int(x.Value)
		}
	}
	type nodeConfig struct {
		NodeID string          `json:"nodeId"`
		Config json.RawMessage `json:"config"`
		Risks  []Risk          `json:"risks"`
	}
	nodes := make([]nodeConfig, 0, len(got))
	parsed := map[string]map[string]any{}
	for id, raw := range got {
		var in ConfigInput
		if err := json.Unmarshal(raw, &in); err != nil {
			missing = append(missing, id)
			continue
		}
		var all map[string]any
		_ = json.Unmarshal(raw, &all)
		parsed[id] = all
		nodes = append(nodes, nodeConfig{id, raw, ConfigRisks(in, peaks[id])})
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].NodeID < nodes[j].NodeID })
	c.opsOK(map[string]any{"nodes": nodes, "diff": ConfigDiff(parsed)}, missing)
}

func (c *rc) opsDB() {
	if !c.requireFleet() {
		return
	}
	got, missing := c.fanoutRaw("/internal/v1/db")
	type nodeDB struct {
		NodeID string          `json:"nodeId"`
		DB     json.RawMessage `json:"db"`
	}
	nodes := make([]nodeDB, 0, len(got))
	for id, raw := range got {
		nodes = append(nodes, nodeDB{id, raw})
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].NodeID < nodes[j].NodeID })
	c.opsOK(map[string]any{"nodes": nodes}, missing)
}
