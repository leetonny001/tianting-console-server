// Package app 组装 console-server：每个空间一个 http.Handler，共用数据库和时钟。
package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"tianting/console/assets"
	"tianting/console/internal/anchor"
	"tianting/console/internal/apierr"
	"tianting/console/internal/audit"
	"tianting/console/internal/clock"
	"tianting/console/internal/config"
	"tianting/console/internal/httpx"
	"tianting/console/internal/imclient"
	"tianting/console/internal/objstore"
	"tianting/console/internal/opsnode"
	"tianting/console/internal/prom"
	"tianting/console/internal/secret"
	"tianting/console/internal/space"
)

// App 是组装好的服务。进程无状态：会话、计数、授权都在库里（PRD-admin F-CON-01 规则 7）。
type App struct {
	Cfg   config.Config
	DB    *pgxpool.Pool
	Clock *clock.Settable
	Log   *slog.Logger

	registry *prometheus.Registry
	rejected *prometheus.CounterVec
	dbOK     atomic.Int64 // 上次确认数据库可用的时间（Unix 毫秒），1 秒内不重复 ping

	// 测试模式的故障注入（CS-001 内容 8）。
	auditFault     atomic.Value // string
	IMLatencyMs    atomic.Int64
	IMDropResponse atomic.Bool

	Audit *audit.Writer
	IM    *imclient.Client // 没有配置 im-server 时为 nil
	// MsgRead 用单独的 console-msgread 凭证读正文（PRD-admin 15 节 Q-1 的默认方案）；没有配置 CON_IM_MSGREAD_KEY 时为 nil，正文接口 503。
	MsgRead *imclient.Client

	// 运维模块（PRD-ops）。都可能为 nil：没有配置时对应卡片显示"数据不可用"。
	Nodes        *opsnode.Fleet
	Prom         *prom.Client
	Alertmanager *prom.Alertmanager
	Backups      *objstore.Store
	backupCache  backupCacheEntry
	Anchor       anchor.Sink // 没有配置锚定时为 nil（只有开发环境）

	anchorWake     chan struct{}
	resultFailures prometheus.Counter
	anchorFailures prometheus.Counter
	anchorLag      prometheus.Gauge

	hasher *secret.Hasher
	weak   map[string]bool

	dummyOnce sync.Once
	dummyHash string
}

// New 创建服务。连接是惰性的：开发环境数据库暂时不可用时也能启动，接口返回 503。
func New(cfg config.Config, log *slog.Logger) (*App, error) {
	a := &App{Cfg: cfg, Clock: clock.New(), Log: log, registry: prometheus.NewRegistry()}
	a.rejected = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "console_rejected_total", Help: "Requests rejected before authentication, by reason.",
	}, []string{"reason"})
	a.resultFailures = prometheus.NewCounter(prometheus.CounterOpts{Name: "console_audit_result_failures_total", Help: "Operations whose audit result could not be written."})
	a.anchorFailures = prometheus.NewCounter(prometheus.CounterOpts{Name: "console_audit_anchor_failures_total", Help: "Failed writes to the external audit anchor."})
	a.anchorLag = prometheus.NewGauge(prometheus.GaugeOpts{Name: "console_audit_anchor_lag_seconds", Help: "Seconds since the latest audit anchor."})
	a.registry.MustRegister(a.rejected, a.resultFailures, a.anchorFailures, a.anchorLag)
	a.anchorWake = make(chan struct{}, 1)
	a.hasher = secret.NewHasher(cfg.Argon)
	a.weak = assets.WeakPasswords()
	if cfg.DatabaseURL != "" {
		pool, err := pgxpool.New(context.Background(), string(cfg.DatabaseURL))
		if err != nil {
			// 不带 err 的细节：解析失败的错误可能包含连接串。
			return nil, errors.New("CON_DATABASE_URL is not a valid connection string")
		}
		a.DB = pool
	}
	if err := a.setupOps(); err != nil {
		return nil, err
	}
	a.Audit = &audit.Writer{DB: a.DB, Now: a.Clock.Now, Fault: func(phase string) bool {
		f, _ := a.auditFault.Load().(string)
		return f == "fail" || (f == "failResult" && phase == audit.PhaseResult)
	}, OnCommit: func(seq int64) {
		if seq%anchorEvery == 0 {
			select {
			case a.anchorWake <- struct{}{}:
			default:
			}
		}
	}}
	var err error
	if a.Anchor, err = openAnchorSink(cfg); err != nil {
		return nil, err
	}
	if cfg.IMAdminURL != "" && len(cfg.IMSigningKey) == ed25519.PrivateKeySize {
		im := imclient.Config{BaseURL: cfg.IMAdminURL, Caller: cfg.IMCaller, Key: ed25519.PrivateKey(cfg.IMSigningKey), Timeout: cfg.IMTimeout, Clock: a.Clock}
		if cfg.TestMode {
			im.Latency = &a.IMLatencyMs
			im.DropResponse = &a.IMDropResponse
		}
		if a.IM, err = imclient.New(im); err != nil {
			return nil, err
		}
		if len(cfg.IMMsgReadKey) == ed25519.PrivateKeySize {
			im.Caller, im.Key = msgReadCaller, ed25519.PrivateKey(cfg.IMMsgReadKey)
			if a.MsgRead, err = imclient.New(im); err != nil {
				return nil, err
			}
		}
	}
	return a, nil
}

// Close 关闭连接池。
func (a *App) Close() {
	if a.DB != nil {
		a.DB.Close()
	}
}

// MetricsHandler 是 /metrics。
func (a *App) MetricsHandler() http.Handler {
	return promhttp.HandlerFor(a.registry, promhttp.HandlerOpts{})
}

func (a *App) ping(ctx context.Context) error {
	if a.DB == nil {
		return errors.New("database is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return a.DB.Ping(ctx)
}

// dbGate：Postgres 不可用时所有 /console/api/* 返回 503 / 5030（CS-002 内容 5）。
func (a *App) dbGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now().UnixMilli()
		if now-a.dbOK.Load() > 1000 {
			if err := a.ping(r.Context()); err != nil {
				apierr.Write(w, apierr.New(apierr.Unavailable, "service unavailable, try again later"))
				return
			}
			a.dbOK.Store(now)
		}
		next.ServeHTTP(w, r)
	})
}

// Handler 返回一个空间的 http.Handler。
func (a *App) Handler(s space.Space) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := a.ping(r.Context()); err != nil {
			apierr.Write(w, apierr.New(apierr.Unavailable, "not ready"))
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	api := a.apiMux(s)
	mux.Handle("/console/api/", a.dbGate(api))
	if a.Cfg.TestMode {
		a.registerTestRoutes(mux)
	}
	mux.HandleFunc("/console/", func(w http.ResponseWriter, _ *http.Request) {
		apierr.Write(w, apierr.New(apierr.NotFound, "not found"))
	})
	if s.WebDir != "" {
		mux.Handle("/", httpx.Static(s.WebDir))
	}
	var root http.Handler = mux
	if s.Name == "ops" && a.Cfg.Ops.GrafanaHost != "" {
		// Grafana 主机：同一进程按 Host 分流，网段限制同样生效（Guard 在外层）。
		grafana := a.grafanaHandler()
		root = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if a.isGrafanaHost(r) {
				grafana.ServeHTTP(w, r)
				return
			}
			mux.ServeHTTP(w, r)
		})
	}
	return httpx.Guard{
		Space: s, Trusted: a.Cfg.TrustedProxies, Production: a.Cfg.Production(),
		OnReject: func(reason string) {
			a.rejected.WithLabelValues(reason).Inc()
			a.Log.Info("request rejected", "space", s.Name, "reason", reason)
		},
	}.Wrap(root)
}

func (a *App) registerTestRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /console/test/clock", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			NowMs *int64 `json:"nowMs"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		if req.NowMs == nil {
			a.Clock.Unfreeze()
		} else {
			a.Clock.Freeze(time.UnixMilli(*req.NowMs))
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("POST /console/test/probe", func(w http.ResponseWriter, r *http.Request) {
		if err := a.ProbeNodes(r.Context()); err != nil {
			apierr.Write(w, apierr.New(apierr.Internal, "probe failed"))
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("POST /console/test/faults", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			AuditWrite  string `json:"auditWrite"` // "fail"、"failResult"、"ok"
			IMLatencyMs int64  `json:"imLatencyMs"`
			// IMDropResponse：im-server 处理完，console 收不到响应（PRD-live 8.2 节，AC-PUSH-06-6）。
			IMDropResponse bool `json:"imDropResponse"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		a.auditFault.Store(req.AuditWrite)
		a.IMLatencyMs.Store(req.IMLatencyMs)
		a.IMDropResponse.Store(req.IMDropResponse)
		w.WriteHeader(http.StatusOK)
	})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(v); err != nil {
		apierr.Write(w, apierr.New(apierr.BadRequest, "invalid JSON body"))
		return false
	}
	return true
}

// StartupCheck 是一项启动保护。运维空间（PRD-ops B-OPS-15）追加节点凭证、Grafana 代理等检查时实现这个接口。
type StartupCheck interface {
	Check(ctx context.Context, a *App) []string
}

// StartupCheckFunc 把函数变成 StartupCheck。
type StartupCheckFunc func(ctx context.Context, a *App) []string

func (f StartupCheckFunc) Check(ctx context.Context, a *App) []string { return f(ctx, a) }

// StartupProblems 跑完全部检查，一次返回全部问题（规则 9）。
func (a *App) StartupProblems(ctx context.Context, extra ...StartupCheck) []string {
	checks := append([]StartupCheck{StartupCheckFunc(keysInUse)}, extra...)
	if _, ok := a.Cfg.Space("ops"); ok {
		checks = append(checks, StartupCheckFunc(func(context.Context, *App) []string { return checkOpsRoutes(opsRoutes()) }))
	}
	if a.Cfg.Production() {
		checks = append(checks, StartupCheckFunc(databaseRole))
	}
	var out []string
	for _, c := range checks {
		out = append(out, c.Check(ctx, a)...)
	}
	return out
}

// keysInUse：库里有记录用的 kid，配置里必须有（AC-CON-11-2）。开发环境数据库不可用时跳过，接口会返回 503。
func keysInUse(ctx context.Context, a *App) []string {
	if a.DB == nil || a.ping(ctx) != nil {
		return nil
	}
	missing, err := secret.MissingKIDs(ctx, a.DB, a.Cfg.DataKeys)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "42P01" { // 还没有执行迁移
			return nil
		}
		return []string{fmt.Sprintf("check data keys: %v", err)}
	}
	if len(missing) > 0 {
		return []string{secret.MissingKIDProblem(missing)}
	}
	return nil
}

// databaseRole：运行账号必须是 console_app，且确实改不了审计（规则 9）。
func databaseRole(ctx context.Context, a *App) []string {
	if a.DB == nil {
		return []string{"CON_DATABASE_URL is required in production"}
	}
	if err := a.ping(ctx); err != nil {
		return []string{"database is not reachable"}
	}
	var out []string
	var user string
	if err := a.DB.QueryRow(ctx, `SELECT current_user`).Scan(&user); err != nil {
		return []string{"check database user failed"}
	}
	if user != "console_app" {
		out = append(out, fmt.Sprintf("database user must be console_app, got %s", user))
	}
	// 在一个会回滚的事务里尝试 UPDATE：探针表一行都不会真的被改。
	err := pgx.BeginFunc(ctx, a.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE audit.probe SET note = note`); err != nil {
			return err
		}
		return errProbeWritable
	})
	var pgErr *pgconn.PgError
	switch {
	case errors.Is(err, errProbeWritable):
		out = append(out, "database user can UPDATE audit.probe: the audit tables must be append-only for the runtime role")
	case errors.As(err, &pgErr) && pgErr.Code == "42501": // insufficient_privilege：符合预期
	case err != nil:
		out = append(out, "audit permission probe failed: run `console-server migrate up` first")
	}
	return out
}

var errProbeWritable = errors.New("probe writable")

// JoinProblems 把问题写成一条错误。
func JoinProblems(problems []string) error {
	return errors.New("invalid configuration:\n  - " + strings.Join(problems, "\n  - "))
}
