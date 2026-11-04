package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tianting/console/internal/clock"
	"tianting/console/internal/imclient"
	"tianting/console/internal/objstore"
	"tianting/console/internal/objstore/objstoretest"
	"tianting/console/internal/opsnode"
)

var (
	imBinOnce sync.Once
	imBin     string
	imBinErr  error
)

func buildIM(t *testing.T) string {
	t.Helper()
	src := os.Getenv("TIANTING_SERVER_DIR")
	if src == "" {
		src = "../../im-mvp/server"
	}
	if _, err := os.Stat(filepath.Join(src, "go.mod")); err != nil {
		t.Skip("tianting-server is not available")
	}
	imBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "ops-im")
		if err != nil {
			imBinErr = err
			return
		}
		imBin = filepath.Join(dir, "im-server")
		b := exec.Command("go", "build", "-o", imBin, "./cmd/im-server")
		b.Dir = src
		if out, err := b.CombinedOutput(); err != nil {
			imBinErr = fmt.Errorf("%v: %s", err, out)
		}
	})
	if imBinErr != nil {
		t.Fatal(imBinErr)
	}
	return imBin
}

// imNode 是一个真实的 im-server 进程，运维端口开着。
type imNode struct {
	id             string
	ws, admin, ops string
	seed           string // base64：运维私钥
	cmd            *exec.Cmd
	logs           *syncBuf
	sys            *imclient.Client
}

func startNode(t *testing.T, id string, env ...string) *imNode {
	t.Helper()
	bin := buildIM(t)
	dir := t.TempDir()
	opsPub, opsPriv, _ := ed25519.GenerateKey(rand.Reader)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	callers, _ := json.Marshal([]map[string]any{{"id": "console", "alg": "ed25519", "publicKey": base64.StdEncoding.EncodeToString(pub), "scopes": allConsoleScopes}})
	file := filepath.Join(dir, "callers.json")
	if err := os.WriteFile(file, callers, 0o600); err != nil {
		t.Fatal(err)
	}
	n := &imNode{id: id, ws: freeAddr(t), admin: freeAddr(t), ops: freeAddr(t), seed: base64.StdEncoding.EncodeToString(opsPriv.Seed()), logs: &syncBuf{}}
	cmd := exec.Command(bin)
	cmd.Stdout, cmd.Stderr = n.logs, n.logs
	cmd.Env = append(os.Environ(), "IM_ADDR="+n.ws, "IM_ADMIN_ADDR="+n.admin, "IM_OPS_ADDR="+n.ops, "IM_METRICS_ADDR=off", "IM_PPROF_ADDR=off", "IM_NODE_ID="+id,
		"IM_OPS_PUBKEYS=k1:"+base64.StdEncoding.EncodeToString(opsPub), "IM_DB="+filepath.Join(dir, "im.db"), "IM_ADMIN_CALLERS="+file)
	cmd.Env = append(cmd.Env, env...)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	n.cmd = cmd
	t.Cleanup(func() {
		_ = cmd.Process.Signal(sigCont)
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		if c, err := net.DialTimeout("tcp", n.ops, 100*time.Millisecond); err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not start:\n%s", id, n.logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	sys, err := imclient.New(imclient.Config{BaseURL: "http://" + n.admin, Caller: "console", Key: priv})
	if err != nil {
		t.Fatal(err)
	}
	n.sys = sys
	return n
}

func (n *imNode) dial(t *testing.T, w *world, uid, platform string) *wsClient {
	t.Helper()
	b := &bizWorld{world: w, sys: n.sys, ws: n.ws}
	return b.dial(uid, platform)
}

func (n *imNode) import_(t *testing.T, ids ...string) {
	t.Helper()
	list := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		list = append(list, map[string]any{"userId": id})
	}
	if err := n.sys.Do(context.Background(), imclient.Call{Operator: "test", RequestID: "imp-" + uid()}, "POST", "/admin/users/import", nil, map[string]any{"users": list}, nil); err != nil {
		t.Fatal(err)
	}
}

func uid() string { return strings.ReplaceAll(fmt.Sprint(time.Now().UnixNano()), "-", "") }

// fakeProm 是可以开关的 Prometheus：按查询语句里的关键字回结果。
type fakeProm struct {
	srv     *httptest.Server
	down    atomic.Bool
	results sync.Map // 关键字 → JSON 字符串
	queries atomic.Int64
}

func newFakeProm(t *testing.T) *fakeProm {
	f := &fakeProm{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.queries.Add(1)
		if f.down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		q := r.URL.Query().Get("query")
		result := "[]"
		f.results.Range(func(k, v any) bool {
			if strings.Contains(q, k.(string)) {
				result = v.(string)
				return false
			}
			return true
		})
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":%s}}`, result)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func promVec(code string, v float64) string {
	return fmt.Sprintf(`{"metric":{"code":%q},"value":[1,"%v"]}`, code, v)
}

// opsWorld 是运维空间 + 两个真实节点 + 假的 Prometheus、Alertmanager、备份桶、Grafana。
type opsWorld struct {
	*world
	n1, n2   *imNode
	prom     *fakeProm
	alerts   atomic.Value // string：JSON；空表示不可用
	backups  *objstoretest.Server
	grafana  *httptest.Server
	grafReqs chan *http.Request
	super    *user
	engineer *user
	viewer   *user
	auditor  *user
}

func nodeTable(t *testing.T, nodes ...*imNode) string {
	t.Helper()
	dir := t.TempDir()
	rows := []map[string]string{}
	for _, n := range nodes {
		key := filepath.Join(dir, n.id+".key")
		if err := os.WriteFile(key, []byte(n.seed), 0o600); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, map[string]string{"nodeId": n.id, "addr": n.ops, "kid": "k1", "keyFile": key})
	}
	raw, _ := json.Marshal(rows)
	file := filepath.Join(dir, "nodes.json")
	if err := os.WriteFile(file, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

const grafanaHost = "grafana.ops.test"

func newOpsWorld(t *testing.T, nodes ...*imNode) *opsWorld {
	t.Helper()
	o := &opsWorld{prom: newFakeProm(t), backups: objstoretest.New(t, "ops-backup"), grafReqs: make(chan *http.Request, 16)}
	o.backups.PageSize = 40
	if len(nodes) > 0 {
		o.n1 = nodes[0]
	}
	if len(nodes) > 1 {
		o.n2 = nodes[1]
	}
	o.grafana = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case o.grafReqs <- r.Clone(context.Background()):
		default:
		}
		w.Header().Set("Set-Cookie", "grafana_session=abc")
		w.Header().Set("Content-Security-Policy", "grafana-own")
		fmt.Fprint(w, "grafana:"+r.URL.Path)
	}))
	t.Cleanup(o.grafana.Close)
	alerts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		v, _ := o.alerts.Load().(string)
		if v == "" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		fmt.Fprint(w, v)
	}))
	t.Cleanup(alerts.Close)
	o.alerts.Store(`[]`)
	env := map[string]string{
		"CON_OPS_PROMETHEUS_URL": o.prom.srv.URL, "CON_OPS_ALERTMANAGER_URL": alerts.URL, "CON_OPS_GRAFANA_URL": o.grafana.URL, "CON_OPS_GRAFANA_HOST": grafanaHost,
		"CON_OPS_BACKUP_STORE": "s3://ops-backup", "CON_OPS_BACKUP_ENDPOINT": o.backups.URL(), "CON_OPS_BACKUP_ACCESS_KEY": o.backups.Reader.AccessKey, "CON_OPS_BACKUP_SECRET_KEY": o.backups.Reader.SecretKey,
	}
	if len(nodes) > 0 {
		env["CON_OPS_NODES"] = nodeTable(t, nodes...)
	}
	o.world = newWorld(t, env)
	// [C 钟] 冻结在 2027 年；节点校验签名时间戳，签名用真实时钟。
	if len(nodes) > 0 {
		f, err := opsnode.New(o.a.Cfg.Ops.Nodes, "", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		o.a.Nodes = f
	}
	o.super = o.opsSuper("osuper")
	o.engineer = o.super.create("oeng1", "ops_engineer")
	o.viewer = o.super.create("oview1", "ops_viewer")
	o.auditor = o.super.create("oaud1", "ops_auditor")
	return o
}

// probe 推进时钟再探测一轮。
func (o *opsWorld) probe() {
	o.t.Helper()
	o.advance(5 * time.Second)
	if err := o.a.ProbeNodes(context.Background()); err != nil {
		o.t.Fatal(err)
	}
}

func (o *opsWorld) putManifest(source string, finished int64, body map[string]any) {
	o.t.Helper()
	store := objstore.New(objstore.Config{Endpoint: o.backups.URL(), Bucket: "ops-backup", AccessKey: o.backups.Writer.AccessKey, SecretKey: []byte(o.backups.Writer.SecretKey)})
	raw, _ := json.Marshal(body)
	key := fmt.Sprintf("manifests/%s/%013d.json", source, finished)
	if err := store.Put(context.Background(), key, strings.NewReader(string(raw)), time.Now().Add(time.Hour)); err != nil {
		o.t.Fatal(err)
	}
}
