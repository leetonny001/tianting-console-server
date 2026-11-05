package e2e

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"tianting/console/internal/app"
	"tianting/console/internal/config"
	"tianting/console/internal/totp"
)

const (
	adminOrigin = "https://admin.test"
	opsOrigin   = "https://ops.test"
	goodPass    = "Correct-Horse-9-Battery"
)

// world 是一个进程内的 console-server：冻结的 [C 钟]、两个空间、独立的库。来源 IP 用 X-Forwarded-For 模拟（127.0.0.1 是可信代理）。
type world struct {
	t     *testing.T
	a     *app.App
	admin *httptest.Server
	ops   *httptest.Server
	now   time.Time
	owner string
	db    *pgxpool.Pool
	logs  *syncBuf
	// onClock 在 [C 钟] 推进后调用：对账测试要让 [IM 钟] 一起走。
	onClock func(time.Time)
}

func newWorld(t *testing.T, extra map[string]string) *world {
	t.Helper()
	owner, appURL := newDB(t)
	env := map[string]string{
		"CON_DATABASE_URL": appURL, "CON_DATA_KEYS": "k1:" + b64(testDataKey), "CON_HASH_PEPPER": b64(testPepper), "CON_TEST_MODE": "1",
		"CON_ADMIN_ORIGIN": adminOrigin, "CON_OPS_ORIGIN": opsOrigin, "CON_TRUSTED_PROXIES": "127.0.0.1",
		"CON_ARGON_MEMORY_KIB": "1024", "CON_ARGON_TIME": "1",
	}
	for k, v := range extra {
		env[k] = v
	}
	cfg, problems := config.Load(func(k string) string { return env[k] })
	if len(problems) > 0 {
		t.Fatal(problems)
	}
	logs := &syncBuf{}
	a, err := app.New(cfg, slog.New(slog.NewTextHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	w := &world{t: t, a: a, now: time.UnixMilli(1_800_000_000_000), owner: owner, db: a.DB, logs: logs}
	a.Clock.Freeze(w.now)
	adminSpace, _ := cfg.Space("admin")
	opsSpace, _ := cfg.Space("ops")
	w.admin = httptest.NewServer(a.Handler(adminSpace))
	w.ops = httptest.NewServer(a.Handler(opsSpace))
	t.Cleanup(w.admin.Close)
	t.Cleanup(w.ops.Close)
	return w
}

func (w *world) advance(d time.Duration) {
	w.now = w.now.Add(d)
	w.a.Clock.Freeze(w.now)
	if w.onClock != nil {
		w.onClock(w.now)
	}
}

// tick 换到下一个 TOTP 步长（同一步长的码不能用两次）。
func (w *world) tick() { w.advance(30 * time.Second) }

// reply 是一次响应。
type reply struct {
	status int
	header http.Header
	raw    string
	body   map[string]any
}

func (r reply) code() int {
	if v, ok := r.body["code"].(float64); ok {
		return int(v)
	}
	return 0
}

func (r reply) reason() string { s, _ := r.body["reason"].(string); return s }

func (r reply) str(k string) string { s, _ := r.body[k].(string); return s }

// user 是一个客户端：Cookie、CSRF 令牌、来源 IP。
type user struct {
	w        *world
	srv      *httptest.Server
	origin   string
	cookie   string
	cookieN  string
	csrf     string
	ip       string
	name     string
	id       string
	password string
	seed     []byte
	recovery []string
}

func (w *world) client(name string) *user {
	return &user{w: w, srv: w.admin, origin: adminOrigin, cookieN: "__Host-adm_sid", ip: "10.0.0.1", name: name, password: goodPass}
}

func (w *world) opsClient(name string) *user {
	return &user{w: w, srv: w.ops, origin: opsOrigin, cookieN: "__Host-ops_sid", ip: "10.0.0.1", name: name, password: goodPass}
}

func (u *user) do(method, path string, body any, mutate ...func(*http.Request)) reply {
	u.w.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, isRaw := body.([]byte) // 已经序列化好的（和浏览器的 JSON.stringify 一样不转义 < > &）
		if !isRaw {
			raw, _ = json.Marshal(body)
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, u.srv.URL+path, rd)
	if err != nil {
		u.w.t.Fatal(err)
	}
	req.Header.Set("X-Forwarded-For", u.ip)
	if method != "GET" && method != "HEAD" {
		req.Header.Set("Origin", u.origin)
		if u.csrf != "" {
			req.Header.Set("X-CSRF-Token", u.csrf)
		}
	}
	if u.cookie != "" {
		req.Header.Set("Cookie", u.cookieN+"="+u.cookie)
	}
	for _, m := range mutate {
		m(req)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		u.w.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	r := reply{status: resp.StatusCode, header: resp.Header, raw: string(raw)}
	_ = json.Unmarshal(raw, &r.body)
	for _, c := range resp.Cookies() {
		if c.Name == u.cookieN && c.Value != "" {
			u.cookie = c.Value
		}
	}
	if v, ok := r.body["csrfToken"].(string); ok {
		u.csrf = v
	}
	if a, ok := r.body["account"].(map[string]any); ok {
		u.id, _ = a["id"].(string)
	}
	return r
}

func expect(t *testing.T, label string, r reply, status, code int) {
	t.Helper()
	if r.status != status || (code != 0 && r.code() != code) {
		t.Errorf("%s: %d %s, want %d / %d", label, r.status, r.raw, status, code)
	}
}

func (u *user) otp() string { return totp.Code(u.seed, totp.Step(u.w.now)) }

// activate 用激活码激活并绑定 TOTP。
func (u *user) activate(code string) {
	t := u.w.t
	t.Helper()
	r := u.do("POST", "/console/api/auth/activate", map[string]any{"username": u.name, "code": code, "newPassword": u.password})
	expect(t, "activate", r, 200, 0)
	r = u.do("POST", "/console/api/auth/totp/setup", map[string]any{})
	expect(t, "totp setup", r, 200, 0)
	parsed, err := url.Parse(r.str("otpauthUri"))
	if err != nil {
		t.Fatal(err)
	}
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(parsed.Query().Get("secret"))
	if err != nil {
		t.Fatal(err)
	}
	u.seed = seed
	r = u.do("POST", "/console/api/auth/totp/confirm", map[string]any{"otp": u.otp()})
	expect(t, "totp confirm", r, 200, 0)
	u.recovery = nil
	for _, c := range r.body["recoveryCodes"].([]any) {
		u.recovery = append(u.recovery, c.(string))
	}
	u.w.tick()
}

// super 引导一个超管并登录。
func (w *world) super(name string) *user {
	w.t.Helper()
	u := w.client(name)
	code, err := w.a.Bootstrap(context.Background(), "admin", name)
	if err != nil {
		w.t.Fatal(err)
	}
	u.activate(code)
	return u
}

func (w *world) opsSuper(name string) *user {
	w.t.Helper()
	u := w.opsClient(name)
	code, err := w.a.Bootstrap(context.Background(), "ops", name)
	if err != nil {
		w.t.Fatal(err)
	}
	u.activate(code)
	return u
}

func (u *user) stepUp() {
	u.w.t.Helper()
	u.w.tick()
	expect(u.w.t, "step-up", u.do("POST", "/console/api/auth/step-up", map[string]any{"otp": u.otp()}), 200, 0)
}

// create 由超管新建账号并激活，返回已登录的客户端。
func (u *user) create(name string, roles ...string) *user {
	t := u.w.t
	t.Helper()
	u.stepUp()
	r := u.do("POST", "/console/api/accounts", map[string]any{"username": name, "displayName": name, "roles": roles})
	expect(t, "create "+name, r, 200, 0)
	var c *user
	if u.srv == u.w.admin {
		c = u.w.client(name)
	} else {
		c = u.w.opsClient(name)
	}
	c.activate(r.str("activationCode"))
	return c
}

func (u *user) login() reply {
	u.w.t.Helper()
	return u.do("POST", "/console/api/auth/login", map[string]any{"username": u.name, "password": u.password, "otp": u.otp()})
}

// auditRows 用超级账号读审计。
func (w *world) auditRows(where string, args ...any) []map[string]any {
	w.t.Helper()
	ctx := context.Background()
	c, err := pgx.Connect(ctx, w.owner)
	if err != nil {
		w.t.Fatal(err)
	}
	defer c.Close(ctx)
	rows, err := c.Query(ctx, `SELECT seq, phase, request_id, username, actor, ip, action, target, params, reason, ticket, result, code FROM audit.records WHERE `+where+` ORDER BY seq`, args...)
	if err != nil {
		w.t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowToMap)
	if err != nil {
		w.t.Fatal(err)
	}
	return out
}

func (w *world) notifications(u *user) []string {
	w.t.Helper()
	var out []string
	rows, err := w.db.Query(context.Background(), `SELECT n.kind || ':' || n.payload::text FROM auth.notifications n WHERE n.account_id = $1::uuid ORDER BY n.created_at, n.id`, u.id)
	if err != nil {
		w.t.Fatal(err)
	}
	out, err = pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		w.t.Fatal(err)
	}
	return out
}

func hasNotice(list []string, kind, who string) bool {
	for _, n := range list {
		if strings.HasPrefix(n, kind+":") && strings.Contains(n, who) {
			return true
		}
	}
	return false
}

func background(r *http.Request) { r.Header.Set("X-Console-Background", "1") }

var _ = base64.StdEncoding

func totpDecode(s string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}

// newAppSameDB 是第二个实例：连同一个库，共享 [C 钟] 的取值（测试里手动同步）。
func newAppSameDB(w *world) (*httptest.Server, error) {
	cfg := w.a.Cfg
	second, err := app.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		return nil, err
	}
	second.Clock = w.a.Clock
	second.Audit.Now = w.a.Clock.Now
	w.t.Cleanup(second.Close)
	s, _ := cfg.Space("admin")
	srv := httptest.NewServer(second.Handler(s))
	w.t.Cleanup(srv.Close)
	return srv, nil
}

func metricValue(t *testing.T, w *world, series string) float64 {
	t.Helper()
	rec := httptest.NewRecorder()
	w.a.MetricsHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	for _, l := range strings.Split(rec.Body.String(), "\n") {
		if v, ok := strings.CutPrefix(l, series+" "); ok {
			var f float64
			_ = json.Unmarshal([]byte(v), &f)
			return f
		}
	}
	return 0
}
