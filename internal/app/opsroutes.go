package app

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"

	"gopkg.in/yaml.v3"

	"tianting/console/api"
	"tianting/console/internal/apierr"
	"tianting/console/internal/objstore"
	"tianting/console/internal/opsnode"
	"tianting/console/internal/perm"
	"tianting/console/internal/prom"
)

// CS-110：运维模块骨架。

const opsPrefix = "/console/api/ops/v1"

func opsRoutes() []route {
	const (
		view    = "ops.overview.read"
		conf    = "ops.config.read"
		silence = "ops.silence.write"
	)
	return []route{
		{method: "GET", path: opsPrefix + "/overview", perm: view, h: (*rc).opsOverview},
		{method: "GET", path: opsPrefix + "/nodes", perm: view, h: (*rc).opsNodes},
		{method: "GET", path: opsPrefix + "/alerts", perm: view, h: (*rc).opsAlerts},
		{method: "POST", path: opsPrefix + "/troubleshoot/query", perm: "ops.troubleshoot", sensitive: true, action: actionTroubleshoot, deniedTarget: troubleshootDeniedTarget, h: (*rc).opsTroubleshoot},
		{method: "GET", path: opsPrefix + "/config", perm: conf, action: actionConfigView, h: (*rc).opsConfig},
		{method: "GET", path: opsPrefix + "/db", perm: conf, h: (*rc).opsDB},
		{method: "GET", path: opsPrefix + "/backups", perm: conf, h: (*rc).opsBackups},
		{method: "POST", path: opsPrefix + "/grafana/ticket", perm: view, action: actionGrafanaEnter, h: (*rc).opsGrafanaTicket},
		{method: "POST", path: opsPrefix + "/silences", perm: silence, stepUp: true, action: actionSilenceCreate, h: (*rc).opsSilenceCreate},
		{method: "POST", path: opsPrefix + "/silences/{id}:expire", pattern: opsPrefix + "/silences/{id}", perm: silence, stepUp: true, action: actionSilenceExpire, h: (*rc).opsSilenceExpire},
	}
}

// OpsRouteSpec 是接口清单的一行。
type OpsRouteSpec struct {
	Method string `yaml:"method"`
	Path   string `yaml:"path"`
	Perm   string `yaml:"perm"`
	Audit  string `yaml:"audit"`
	StepUp bool   `yaml:"stepUp"`
	Batch  int    `yaml:"batch"`
}

// OpsRouteSpecs 解析接口清单。
func OpsRouteSpecs() ([]OpsRouteSpec, error) {
	var out []OpsRouteSpec
	err := yaml.Unmarshal(api.OpsRoutes, &out)
	return out, err
}

// checkOpsRoutes：接口清单和实际注册的路由必须一致，否则启动失败（CS-110）。第二批的条目注册后才算。
func checkOpsRoutes(rs []route) []string {
	specs, err := OpsRouteSpecs()
	if err != nil {
		return []string{"api/ops-routes.yaml is not valid YAML"}
	}
	key := func(method, path, perm string, stepUp bool, action string) string {
		return fmt.Sprintf("%s %s perm=%s stepUp=%v audit=%s", method, path, perm, stepUp, action)
	}
	var want, got []string
	for _, s := range specs {
		want = append(want, key(s.Method, opsPrefix+s.Path, s.Perm, s.StepUp, s.Audit))
	}
	for _, r := range rs {
		got = append(got, key(r.method, r.path, r.perm, r.stepUp, r.action))
	}
	sort.Strings(want)
	sort.Strings(got)
	var out []string
	for _, w := range want {
		if !slices.Contains(got, w) {
			out = append(out, "api/ops-routes.yaml lists a route that is not registered: "+w)
		}
	}
	for _, g := range got {
		if !slices.Contains(want, g) {
			out = append(out, "route is not in api/ops-routes.yaml: "+g)
		}
	}
	return out
}

// opsEnvelope 是运维接口的统一响应（PRD-ops 3.2 节"部分结果"）。
type opsEnvelope struct {
	Data         any      `json:"data"`
	Partial      bool     `json:"partial"`
	MissingNodes []string `json:"missingNodes"`
	DataTime     int64    `json:"dataTime"`
}

func (c *rc) opsOK(data any, missing []string) {
	if missing == nil {
		missing = []string{}
	}
	sort.Strings(missing)
	c.ok(opsEnvelope{Data: data, Partial: len(missing) > 0, MissingNodes: missing, DataTime: c.now()})
}

// requireFleet：没有配置节点时接口仍然 200，节点列表为空；只有真的要调用节点的才用它。
func (c *rc) requireFleet() bool {
	if c.a.Nodes == nil {
		c.fail(apierr.New(apierr.Unavailable, "no nodes are configured"))
		return false
	}
	return true
}

// registerMethodGuards：其他方法显式回 405，不依赖默认行为（AC-OPS-10-7）。
func registerMethodGuards(mux *http.ServeMux, rs []route) {
	allowed := map[string][]string{}
	for _, r := range rs {
		allowed[r.muxPath()] = append(allowed[r.muxPath()], r.method)
	}
	for path, methods := range allowed {
		for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
			if slices.Contains(methods, m) {
				continue
			}
			allow := methods[0]
			mux.HandleFunc(m+" "+path, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Allow", allow)
				w.WriteHeader(http.StatusMethodNotAllowed)
			})
		}
	}
}

// setupOps 创建运维模块的客户端。
func (a *App) setupOps() error {
	o := a.Cfg.Ops
	if len(o.Nodes) > 0 {
		f, err := opsnode.New(o.Nodes, o.CAFile, a.Clock)
		if err != nil {
			return err
		}
		a.Nodes = f
	}
	a.Prom = prom.New(o.PrometheusURL)
	if o.AlertmanagerURL != "" {
		a.Alertmanager = &prom.Alertmanager{Base: o.AlertmanagerURL}
	}
	if o.BackupBucket != "" {
		a.Backups = objstore.New(objstore.Config{Endpoint: o.BackupEndpoint, Region: o.BackupRegion, Bucket: o.BackupBucket, Prefix: o.BackupPrefix, AccessKey: o.BackupAccessKey, SecretKey: o.BackupSecretKey})
	}
	return nil
}

var errBackupNotConfigured = errors.New("backup store is not configured")

func opsSpace() perm.Space { return perm.Ops }

// bootstrapStatus：这个空间还没有账号时，登录页提示先用命令行创建运维超管（F-OPS-01）。不透露有多少账号。
func (c *rc) bootstrapStatus() {
	var has bool
	if err := c.a.DB.QueryRow(c.ctx, `SELECT EXISTS (SELECT 1 FROM auth.accounts WHERE space = $1)`, c.space.Name).Scan(&has); err != nil {
		c.failErr("bootstrap status", err)
		return
	}
	c.ok(map[string]any{"hasAccounts": has})
}
