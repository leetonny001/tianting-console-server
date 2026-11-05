package app

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"tianting/console/internal/prom"
)

// CS-110：接口清单和注册的路由一致；改了任何一边启动就失败。
func TestOpsRoutesMatchYAML(t *testing.T) {
	if p := checkOpsRoutes(opsRoutes()); len(p) != 0 {
		t.Fatal(p)
	}
	missing := opsRoutes()[1:]
	if p := checkOpsRoutes(missing); len(p) != 1 || !strings.Contains(p[0], "not registered") {
		t.Errorf("missing route: %v", p)
	}
	extra := append(opsRoutes(), route{method: "POST", path: opsPrefix + "/restart", perm: "ops.overview.read"})
	if p := checkOpsRoutes(extra); len(p) != 1 || !strings.Contains(p[0], "not in api/ops-routes.yaml") {
		t.Errorf("extra route: %v", p)
	}
	changed := opsRoutes()
	changed[0].perm = "ops.config.read"
	if p := checkOpsRoutes(changed); len(p) != 2 {
		t.Errorf("changed perm: %v", p)
	}
}

// AC-OPS-05-4、CS-110 内容 3：节点相关接口只读；没有备份、恢复路径。写接口只有告警静默，都要重新验证（F-OPS-18）。
func TestOpsRoutesReadOnly(t *testing.T) {
	for _, r := range opsRoutes() {
		if strings.HasPrefix(r.path, opsPrefix+"/silences") {
			if !r.stepUp || r.perm != "ops.silence.write" {
				t.Errorf("silence route: %+v", r)
			}
			continue
		}
		if r.method != "GET" && r.path != opsPrefix+"/troubleshoot/query" && r.path != opsPrefix+"/grafana/ticket" {
			t.Errorf("write route: %s %s", r.method, r.path)
		}
		for _, bad := range []string{"backup/", "restore", "restart", "drain", "kick"} {
			if strings.Contains(r.path, bad) {
				t.Errorf("forbidden path: %s", r.path)
			}
		}
	}
}

func riskInput(env string, limit int64, planned int) ConfigInput {
	var c ConfigInput
	c.Env.Env, c.Env.GOMEMLIMIT, c.Env.PlannedConns, c.Env.NodeIDSet = env, limit, planned, true
	return c
}

func riskItem(r []Risk, item string) *Risk {
	for i := range r {
		if r[i].Item == item {
			return &r[i]
		}
	}
	return nil
}

// AC-OPS-10-3、10-2。
func TestConfigRisks(t *testing.T) {
	const mib = 1 << 20
	if r := riskItem(ConfigRisks(riskInput("production", 300*mib, 10000), 0), "gomemlimit"); r == nil || r.Level != "high" {
		t.Errorf("300MiB = %+v", r)
	}
	if r := riskItem(ConfigRisks(riskInput("production", 800*mib, 10000), 0), "gomemlimit"); r != nil {
		t.Errorf("800MiB = %+v", r)
	}
	r := riskItem(ConfigRisks(riskInput("production", 300*mib, 0), 10000), "gomemlimit")
	if r == nil || r.Level != "high" || !strings.Contains(r.Text, "近 7 天峰值") {
		t.Errorf("peak = %+v", r)
	}
	if r := riskItem(ConfigRisks(riskInput("production", 300*mib, 0), 0), "gomemlimit"); r != nil {
		t.Errorf("no plan and no peak = %+v", r)
	}
	if r := riskItem(ConfigRisks(riskInput("production", 0, 0), 0), "gomemlimit"); r == nil || r.Level != "info" {
		t.Errorf("unset = %+v", r)
	}
	c := riskInput("development", 800*mib, 0)
	c.Env.NodeIDSet = false
	c.Network.AllowedOrigins = []string{"https://a", "*"}
	c.Network.PprofAddr = "0.0.0.0:6060"
	c.Switches.TestMode = true
	list := ConfigRisks(c, 0)
	for item, level := range map[string]string{"allowedOrigins": "high", "nodeId": "info", "pprofAddr": "high", "testMode": "info"} {
		if r := riskItem(list, item); r == nil || r.Level != level {
			t.Errorf("%s = %+v", item, r)
		}
	}
	// production 下这些由启动保护管，不重复提示；没有可信代理才提示。
	p := riskInput("production", 800*mib, 0)
	p.Network.PprofAddr = "127.0.0.1:6060"
	list = ConfigRisks(p, 0)
	if len(list) != 1 || list[0].Item != "trustedProxies" {
		t.Errorf("production = %+v", list)
	}
}

// AC-OPS-10-6：不同的项高亮；版本、节点 ID、地址类不算。
func TestConfigDiff(t *testing.T) {
	parse := func(s string) map[string]any {
		var m map[string]any
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	nodes := map[string]map[string]any{
		"n1": parse(`{"env":{"version":"1","nodeId":"n1","env":"production"},"network":{"addr":"a"},"limits":{"maxConnsPerUser":10},"productionChecks":[{"id":"x"}]}`),
		"n2": parse(`{"env":{"version":"2","nodeId":"n2","env":"production"},"network":{"addr":"b"},"limits":{"maxConnsPerUser":20},"productionChecks":[{"id":"y"}]}`),
	}
	d := ConfigDiff(nodes)
	if len(d) != 1 || d[0]["item"] != "limits.maxConnsPerUser" {
		t.Fatalf("diff = %v", d)
	}
	vals := d[0]["values"].(map[string]string)
	if vals["n1"] != "10" || vals["n2"] != "20" {
		t.Errorf("values = %v", vals)
	}
}

func TestNodeStatus(t *testing.T) {
	now := int64(1_000_000)
	fresh := now - 1000
	stale := now - 16_000
	for _, tc := range []struct {
		failure string
		seen    int64
		snap    nodeSnapshot
		want    string
	}{
		{"", fresh, nodeSnapshot{Ready: true}, nodeReady},
		{"", fresh, nodeSnapshot{Ready: false}, nodeNotReady},
		{"", fresh, nodeSnapshot{Ready: false, Draining: true}, nodeDraining}, // 下线中优先于未就绪
		{"", stale, nodeSnapshot{Ready: true}, nodeUnreachable},
		{"", 0, nodeSnapshot{}, nodeUnreachable},
		{nodeUnreachable, fresh, nodeSnapshot{Ready: true}, nodeReady}, // 一次失败不算：15 秒内还算可达
		{nodeIdentity, fresh, nodeSnapshot{Ready: true}, nodeIdentity},
	} {
		if got := nodeStatus(tc.failure, tc.seen, now, tc.snap); got != tc.want {
			t.Errorf("%+v = %s", tc, got)
		}
	}
}

func TestErrorCard(t *testing.T) {
	m := errorCard([]prom.Sample{
		{Labels: map[string]string{"code": "0"}, Value: 80},
		{Labels: map[string]string{"code": "4290"}, Value: 15},
		{Labels: map[string]string{"code": "4033"}, Value: 3},
		{Labels: map[string]string{"code": "4030"}, Value: 1},
		{Labels: map[string]string{"code": "5000"}, Value: 1},
	})
	if m["share4xx"].(float64) != 0.19 || m["share5xx"].(float64) != 0.01 {
		t.Errorf("%v", m)
	}
	top := m["top"].([]codeCount)
	if len(top) != 3 || top[0].Code != "4290" || top[1].Code != "4033" {
		t.Errorf("top = %v", top)
	}
	if empty := errorCard(nil); empty["share4xx"].(float64) != 0 {
		t.Errorf("empty = %v", empty)
	}
}

func TestSinceMidnight(t *testing.T) {
	at := time.Date(2026, 11, 4, 16, 30, 0, 0, time.UTC) // 上海 11-05 00:30
	if d := sinceShanghaiMidnight(at); d != 30*time.Minute {
		t.Error(d)
	}
}

// AC-OPS-12-6：只有文件名；失败原因里带路径的不显示。
func TestBackupSanitize(t *testing.T) {
	r := backupRecord{File: "/var/backups/im/2026.db.age", Error: "cannot open /var/backups/x"}
	r.sanitize()
	if r.File != "2026.db.age" || strings.Contains(r.Error, "/var") {
		t.Errorf("%+v", r)
	}
	ok := backupRecord{File: "a.db", Error: "加密失败"}
	ok.sanitize()
	if ok.Error != "加密失败" {
		t.Errorf("%+v", ok)
	}
}

func TestDisconnectSummary(t *testing.T) {
	s := disconnectSummary([]opsDisconnect{{Code: 4012, By: "server", Phase: "handshake"}, {Code: 4012, By: "server", Phase: "handshake"}, {Code: 1000, By: "client", Phase: "session"}})
	if s["serverClosedMajority"] != true || s["handshakeAuthMajority"] != true {
		t.Errorf("%v", s)
	}
	if s := disconnectSummary(nil); s["serverClosedMajority"] != false {
		t.Errorf("empty = %v", s)
	}
}

func TestCSVCell(t *testing.T) {
	for in, want := range map[string]string{
		"": "", "abc": "abc", "a=b": "a=b", "10.0.0.1": "10.0.0.1", `{"ids":["u"]}`: `{"ids":["u"]}`, "   ": "   ",
		"=1": "'=1", "+1": "'+1", "-1": "'-1", "@a": "'@a", "\t1": "'\t1", "\r1": "'\r1", "\n1": "'\n1",
		" =1": "' =1", "\u3000+1": "'\u3000+1", "＝1": "'＝1", "＋1": "'＋1", "－1": "'－1", "＠1": "'＠1",
	} {
		if got := csvCell(in); got != want {
			t.Errorf("csvCell(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCheckSilenceMatchers(t *testing.T) {
	yes, no := true, false
	good := [][]silenceMatcher{
		{{Name: "alertname", Value: "节点不可达"}},
		{{Name: "alertname", Value: "5xxx错误率高"}, {Name: "node_id", Value: "n1"}},
		{{Name: "alertname", Value: "疑似GC风暴", IsRegex: &no, IsEqual: &yes}},
	}
	for _, in := range good {
		out, e := checkSilenceMatchers(in)
		if e != nil {
			t.Errorf("%+v: %v", in, e)
			continue
		}
		for _, m := range out {
			if m.IsRegex || !m.IsEqual {
				t.Errorf("not an equality matcher: %+v", m)
			}
		}
	}
	bad := [][]silenceMatcher{
		nil, {},
		{{Name: "alertname", Value: ".*"}}, {{Name: "alertname", Value: "a|b"}}, {{Name: "alertname", Value: "a+"}}, {{Name: "alertname", Value: "[a]"}},
		{{Name: "alertname", Value: ""}}, {{Name: "alertname", Value: " a"}}, {{Name: "alertname", Value: "a "}},
		{{Name: "alertname", Value: "a", IsRegex: &yes}}, {{Name: "alertname", Value: "a", IsEqual: &no}},
		{{Name: "node_id", Value: "n1 n2"}}, {{Name: "severity", Value: "critical"}},
		{{Name: "alertname", Value: "a"}, {Name: "alertname", Value: "b"}},
		{{Name: "alertname", Value: strings.Repeat("a", 129)}},
	}
	for _, in := range bad {
		if _, e := checkSilenceMatchers(in); e == nil {
			t.Errorf("%+v accepted", in)
		}
	}
}
