// Package e2e 是进程级测试：真实二进制 + 真实 Postgres（可选：真实 im-server）。
package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"tianting/console/internal/apierr"
	"tianting/console/internal/dbx"
	"tianting/console/internal/imclient"
	"tianting/console/internal/secret"
)

func adminURL() string {
	if v := os.Getenv("CON_TEST_ADMIN_URL"); v != "" {
		return v
	}
	return "postgres://127.0.0.1:5432/postgres?sslmode=disable"
}

// withUser 把连接串改成另一个数据库 / 用户。
func withDB(raw, db, user string) string {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	u.Path = "/" + db
	if user != "" {
		if pw, ok := u.User.Password(); ok {
			u.User = url.UserPassword(user, pw)
		} else {
			u.User = url.User(user)
		}
	}
	return u.String()
}

// newDB 建一个独立的库并执行迁移，返回 owner 和 console_app 的连接串。Postgres 不可用时跳过（CI 设 CON_TEST_REQUIRE_DB=1 时失败）。
func newDB(t *testing.T) (owner, appURL string) {
	t.Helper()
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, adminURL())
	if err != nil {
		if os.Getenv("CON_TEST_REQUIRE_DB") != "" {
			t.Fatalf("postgres: %v", err)
		}
		t.Skipf("postgres is not available: %v", err)
	}
	defer admin.Close(ctx)
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "t_" + hex.EncodeToString(b)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), adminURL())
		if err != nil {
			return
		}
		defer c.Close(context.Background())
		_, _ = c.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	})
	owner = withDB(adminURL(), name, "")
	if _, err := dbx.Up(ctx, owner); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// 角色是集群级的。测试环境给运行账号开 LOGIN（生产环境由运维设置密码）。
	if _, err := admin.Exec(ctx, "ALTER ROLE console_app LOGIN"); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "ALTER ROLE console_archiver LOGIN"); err != nil {
		t.Fatal(err)
	}
	return owner, withDB(adminURL(), name, "console_app")
}

var (
	binOnce sync.Once
	binPath string
	binErr  error
)

func buildBin(t *testing.T) string {
	t.Helper()
	binOnce.Do(func() {
		dir, err := os.MkdirTemp("", "console-e2e")
		if err != nil {
			binErr = err
			return
		}
		binPath = filepath.Join(dir, "console-server")
		out, err := exec.Command("go", "build", "-o", binPath, "../cmd/console-server").CombinedOutput()
		if err != nil {
			binErr = fmt.Errorf("%v: %s", err, out)
		}
	})
	if binErr != nil {
		t.Fatal(binErr)
	}
	return binPath
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func run(t *testing.T, env []string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, buildBin(t), args...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

type proc struct {
	admin, ops string
	cmd        *exec.Cmd
}

// start 启动服务并等它就绪（管理或运维地址能连上）。
func start(t *testing.T, env ...string) *proc {
	t.Helper()
	p := &proc{admin: freeAddr(t), ops: freeAddr(t)}
	cmd := exec.Command(buildBin(t))
	var out syncBuf
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.Env = append(os.Environ(), "CON_ADMIN_ADDR="+p.admin, "CON_OPS_ADDR="+p.ops, "CON_METRICS_ADDR=off")
	cmd.Env = append(cmd.Env, env...)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p.cmd = cmd
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, a := range []string{p.admin, p.ops} {
			if c, err := net.DialTimeout("tcp", a, 100*time.Millisecond); err == nil {
				c.Close()
				return p
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server did not start:\n%s", out.String())
	return nil
}

type syncBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func get(t *testing.T, url string, h map[string]string) (int, http.Header, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	for k, v := range h {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b)
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

var (
	testDataKey = strings.Repeat("d", 32)
	testPepper  = strings.Repeat("p", 32)
	testSeed    = strings.Repeat("s", 32)
)

func prodEnv(appURL string) []string {
	return []string{
		"CON_ENV=production", "CON_SPACES=admin", "CON_ADMIN_ALLOWED_CIDRS=127.0.0.0/8", "CON_ADMIN_ORIGIN=https://admin.example.internal",
		"CON_DATABASE_URL=" + appURL, "CON_DATA_KEYS=k1:" + b64(testDataKey), "CON_HASH_PEPPER=" + b64(testPepper),
		"CON_IM_SIGNING_KEY=" + b64(testSeed), "CON_AUDIT_ANCHOR=s3://anchor", "CON_AUDIT_ANCHOR_ENDPOINT=https://s3.example.internal", "CON_AUDIT_ANCHOR_ACCESS_KEY=w", "CON_AUDIT_ANCHOR_SECRET_KEY=" + strings.Repeat("w", 32),
	}
}

// AC-CON-01-6：只开一个空间时另一个地址连不上；两个空间的响应头不同。
func TestSpaces(t *testing.T) {
	_, appURL := newDB(t)
	p := start(t, "CON_SPACES=admin", "CON_DATABASE_URL="+appURL)
	if code, _, _ := get(t, "http://"+p.admin+"/healthz", nil); code != 200 {
		t.Errorf("admin = %d", code)
	}
	if c, err := net.DialTimeout("tcp", p.ops, 200*time.Millisecond); err == nil {
		c.Close()
		t.Error("ops space should not listen")
	}
	both := start(t, "CON_DATABASE_URL="+appURL)
	_, ah, _ := get(t, "http://"+both.admin+"/healthz", nil)
	_, oh, _ := get(t, "http://"+both.ops+"/healthz", nil)
	if !strings.Contains(ah.Get("Content-Security-Policy"), "data:") || strings.Contains(oh.Get("Content-Security-Policy"), "data:") || oh.Get("X-Frame-Options") != "DENY" {
		t.Errorf("admin %v\nops %v", ah, oh)
	}
	// AC-CON-05-14、01-3（没有会话时 401 / 4014；带另一个空间的 Cookie 同样）。
	for _, addr := range []string{both.admin, both.ops} {
		code, h, body := get(t, "http://"+addr+"/console/api/session", map[string]string{"Cookie": "__Host-adm_sid=whatever"})
		if code != 401 || !strings.Contains(body, `"code":4014`) || h.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: %d %s %v", addr, code, body, h)
		}
	}
	// 测试路由只在测试模式下存在。
	req, _ := http.NewRequest("POST", "http://"+both.admin+"/console/test/clock", strings.NewReader(`{"nowMs":1}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("test route = %d", resp.StatusCode)
	}
	test := start(t, "CON_DATABASE_URL="+appURL, "CON_TEST_MODE=1")
	req, _ = http.NewRequest("POST", "http://"+test.admin+"/console/test/clock", strings.NewReader(`{"nowMs":1}`))
	if resp, err = http.DefaultClient.Do(req); err != nil || resp.StatusCode != 200 {
		t.Errorf("test mode clock: %v %v", resp, err)
	} else {
		resp.Body.Close()
	}
}

// AC-CON-01-4：五种错误配置都非 0 退出并指出原因；多个错误一次列全。
func TestProductionStartupGuards(t *testing.T) {
	owner, appURL := newDB(t)
	ownerConn, err := pgx.Connect(context.Background(), owner)
	if err != nil {
		t.Fatal(err)
	}
	defer ownerConn.Close(context.Background())
	with := func(extra ...string) []string { return append(prodEnv(appURL), extra...) }
	cases := []struct {
		name string
		env  []string
		want string
	}{
		{"test mode", with("CON_TEST_MODE=1"), "CON_TEST_MODE"},
		{"no cidrs", with("CON_ADMIN_ALLOWED_CIDRS="), "CON_ADMIN_ALLOWED_CIDRS"},
		{"0.0.0.0/0", with("CON_ADMIN_ALLOWED_CIDRS=0.0.0.0/0"), "0.0.0.0/0"},
		{"no anchor", with("CON_AUDIT_ANCHOR="), "CON_AUDIT_ANCHOR"},
		{"anchor without credentials", with("CON_AUDIT_ANCHOR_SECRET_KEY="), "CON_AUDIT_ANCHOR_SECRET_KEY"},
		{"anchor over http", with("CON_AUDIT_ANCHOR_ENDPOINT=http://s3.example.internal"), "must be https"},
		{"anchor bad scheme", with("CON_AUDIT_ANCHOR=ftp://x"), "CON_AUDIT_ANCHOR"},
		{"archive in anchor bucket", with("CON_AUDIT_ARCHIVE=s3://anchor/old", "CON_AUDIT_ARCHIVE_ENDPOINT=https://s3.example.internal"), "same bucket"},
		{"bad archive key", with("CON_ARCHIVE_RECIPIENT=not-a-key"), "CON_ARCHIVE_RECIPIENT"},
		{"superuser role", append(prodEnv(owner), "CON_ADMIN_ADDR="+freeAddr(t)), "must be console_app"},
		{"16 byte data key", with("CON_DATA_KEYS=k1:" + b64(strings.Repeat("d", 16))), "k1"},
		{"data key equals signing key", with("CON_DATA_KEYS=k1:" + b64(testSeed)), "must be different"},
	}
	for _, tc := range cases {
		out, err := run(t, tc.env)
		if err == nil || !strings.Contains(out, tc.want) {
			t.Errorf("%s: err=%v\n%s", tc.name, err, out)
		}
		for _, secretValue := range []string{testDataKey, testSeed, testPepper} {
			if strings.Contains(out, secretValue) {
				t.Errorf("%s: output leaks a secret", tc.name)
			}
		}
	}
	// 运行账号被误授了审计表的 UPDATE。
	if _, err := ownerConn.Exec(context.Background(), `GRANT UPDATE ON audit.probe TO console_app`); err != nil {
		t.Fatal(err)
	}
	if out, err := run(t, with()); err == nil || !strings.Contains(out, "audit.probe") {
		t.Errorf("writable probe: err=%v\n%s", err, out)
	}
	var note string
	if err := ownerConn.QueryRow(context.Background(), `SELECT note FROM audit.probe WHERE id = 1`).Scan(&note); err != nil || note != "startup permission probe" {
		t.Errorf("probe row changed: %q %v", note, err)
	}
	if _, err := ownerConn.Exec(context.Background(), `REVOKE UPDATE ON audit.probe FROM console_app`); err != nil {
		t.Fatal(err)
	}
	// 静态问题和要连库的问题一次列全。
	out, err := run(t, append(prodEnv(owner), "CON_TEST_MODE=1", "CON_AUDIT_ANCHOR="))
	if err == nil || !strings.Contains(out, "CON_TEST_MODE") || !strings.Contains(out, "CON_AUDIT_ANCHOR") || !strings.Contains(out, "must be console_app") {
		t.Errorf("all problems at once: err=%v\n%s", err, out)
	}
	// 配置正确：能启动；生产环境明文直连被拒，可信代理声明 https 才通过。
	p := start(t, with("CON_TRUSTED_PROXIES=127.0.0.1")...)
	code, h, _ := get(t, "http://"+p.admin+"/healthz", map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-For": "127.0.0.2"})
	if code != 200 || h.Get("Strict-Transport-Security") != "max-age=31536000" {
		t.Errorf("proxied = %d %v", code, h)
	}
	if code, _, _ := get(t, "http://"+p.admin+"/healthz", nil); code != 403 {
		t.Errorf("plain = %d", code)
	}
}

// CS-002 内容 5：数据库不可用时接口 503 / 5030，/readyz 503，进程还活着。
func TestDatabaseDown(t *testing.T) {
	p := start(t, "CON_DATABASE_URL=postgres://nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	code, _, body := get(t, "http://"+p.admin+"/console/api/session", nil)
	if code != 503 || !strings.Contains(body, `"code":5030`) {
		t.Errorf("api = %d %s", code, body)
	}
	if code, _, _ := get(t, "http://"+p.admin+"/readyz", nil); code != 503 {
		t.Errorf("readyz = %d", code)
	}
	if code, _, _ := get(t, "http://"+p.admin+"/healthz", nil); code != 200 {
		t.Errorf("healthz = %d", code)
	}
	if strings.Contains(body, "nobody") {
		t.Errorf("connection string in response: %s", body)
	}
}

// CS-002 内容 1：迁移幂等、校验和；运行账号的权限。
func TestMigrationsAndRoles(t *testing.T) {
	owner, appURL := newDB(t)
	env := []string{"CON_OWNER_DATABASE_URL=" + owner}
	if out, err := run(t, env, "migrate", "up"); err != nil || !strings.Contains(out, "applied 0 migration") {
		t.Errorf("second up: %v\n%s", err, out)
	}
	if out, err := run(t, env, "migrate", "status"); err != nil || !strings.Contains(out, "0001_schemas_roles  applied") || strings.Contains(out, "pending") {
		t.Errorf("status: %v\n%s", err, out)
	}
	if out, err := run(t, nil, "migrate", "status"); err == nil || !strings.Contains(out, "console_owner") {
		t.Errorf("no owner url: %v\n%s", err, out)
	}

	ctx := context.Background()
	app, err := pgx.Connect(ctx, appURL)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close(ctx)
	mustDeny := func(sql string) {
		t.Helper()
		_, err := app.Exec(ctx, sql)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("%s: err = %v, want permission denied", sql, err)
		}
	}
	mustDeny(`UPDATE audit.probe SET note = 'x'`)
	mustDeny(`DELETE FROM audit.probe`)
	mustDeny(`TRUNCATE audit.probe`)
	mustDeny(`CREATE TABLE audit.x (id int)`)
	mustDeny(`CREATE TABLE auth.x (id int)`)
	mustDeny(`CREATE TABLE public.x (id int)`)
	mustDeny(`DROP TABLE auth.totp`)
	// AC-CON-08-3
	mustDeny(`UPDATE audit.records SET reason = 'x'`)
	mustDeny(`DELETE FROM audit.records`)
	mustDeny(`TRUNCATE audit.records`)
	mustDeny(`INSERT INTO audit.chain_head (id, seq, hash) VALUES (2, 0, '')`)
	mustDeny(`DELETE FROM audit.chain_head`)
	if _, err := app.Exec(ctx, `INSERT INTO audit.probe (id, note) VALUES (2, 'n')`); err != nil {
		t.Errorf("insert into audit: %v", err)
	}
	if _, err := app.Exec(ctx, `INSERT INTO auth.accounts (id, space, username, display_name, status, created_at) VALUES ('00000000-0000-7000-8000-000000000001', 'admin', 'probe', 'x', 'active', 1)`); err != nil {
		t.Errorf("auth write: %v", err)
	}
	if _, err := app.Exec(ctx, `UPDATE auth.accounts SET display_name = 'y'`); err != nil {
		t.Errorf("auth update: %v", err)
	}

	// 已执行的迁移被改过：up 和 status 都报错。
	oc, err := pgx.Connect(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	defer oc.Close(ctx)
	if _, err := oc.Exec(ctx, `UPDATE public.schema_migrations SET checksum = 'x' WHERE version = 1`); err != nil {
		t.Fatal(err)
	}
	if out, err := run(t, env, "migrate", "status"); err == nil || !strings.Contains(out, "checksum mismatch") {
		t.Errorf("tampered status: %v\n%s", err, out)
	}
	if out, err := run(t, env, "migrate", "up"); err == nil || !strings.Contains(out, "modified after being applied") {
		t.Errorf("tampered up: %v\n%s", err, out)
	}
}

// AC-CON-11-1、11-2：库里只有密文；缺 kid 拒绝启动并指出；轮换后可以删旧 kid。
func TestDataKeyRotation(t *testing.T) {
	ownerURL, appURL := newDB(t)
	ctx := context.Background()
	k1 := "k1:" + b64(testDataKey)
	k2 := "k2:" + b64(strings.Repeat("e", 32))
	old, err := secret.ParseKeyring(k1, "k1")
	if err != nil {
		t.Fatal(err)
	}
	const seed = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	pool, err := pgxpool.New(ctx, appURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	_ = ownerURL
	for n := 1; n <= 150; n++ { // 超过一批（100）
		id := fmt.Sprintf("00000000-0000-7000-8000-%012d", n)
		if _, err := pool.Exec(ctx, `INSERT INTO auth.accounts (id, space, username, display_name, status, created_at) VALUES ($1::uuid, 'admin', $2, 'x', 'active', 1)`, id, fmt.Sprintf("user%d", n)); err != nil {
			t.Fatal(err)
		}
		kid, nonce, ct, err := old.Encrypt(id, []byte(seed))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO auth.totp (account_id, kid, nonce, ciphertext) VALUES ($1::uuid, $2, $3, $4)`, id, kid, nonce, ct); err != nil {
			t.Fatal(err)
		}
	}
	var hits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM auth.totp WHERE position($1::bytea in ciphertext) > 0 OR position($1::bytea in nonce) > 0`, []byte(seed)).Scan(&hits); err != nil || hits != 0 {
		t.Errorf("seed in plaintext: %d %v", hits, err)
	}

	// 未轮换就删 k1：拒绝启动，指出 k1。
	out, err := run(t, []string{"CON_DATABASE_URL=" + appURL, "CON_DATA_KEYS=" + k2, "CON_DATA_ACTIVE_KID=k2", "CON_ADMIN_ADDR=" + freeAddr(t), "CON_OPS_ADDR=" + freeAddr(t), "CON_METRICS_ADDR=off"})
	if err == nil || !strings.Contains(out, "k1") || !strings.Contains(out, "keys rotate") {
		t.Errorf("missing kid: err=%v\n%s", err, out)
	}
	// 轮换。
	out, err = run(t, []string{"CON_DATABASE_URL=" + appURL, "CON_DATA_KEYS=" + k1 + "," + k2, "CON_DATA_ACTIVE_KID=k2"}, "keys", "rotate")
	if err != nil || !strings.Contains(out, "re-encrypted 150") {
		t.Fatalf("rotate: %v\n%s", err, out)
	}
	if out, err := run(t, []string{"CON_DATABASE_URL=" + appURL, "CON_DATA_KEYS=" + k1 + "," + k2, "CON_DATA_ACTIVE_KID=k2"}, "keys", "rotate"); err != nil || !strings.Contains(out, "re-encrypted 0") {
		t.Errorf("second rotate: %v\n%s", err, out)
	}
	// 删掉 k1 后能启动，全部记录能用 k2 解开。
	start(t, "CON_DATABASE_URL="+appURL, "CON_DATA_KEYS="+k2, "CON_DATA_ACTIVE_KID=k2")
	only, _ := secret.ParseKeyring(k2, "k2")
	rows, err := pool.Query(ctx, `SELECT account_id::text, kid, nonce, ciphertext FROM auth.totp`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var id, kid string
		var nonce, ct []byte
		if err := rows.Scan(&id, &kid, &nonce, &ct); err != nil {
			t.Fatal(err)
		}
		plain, err := only.Decrypt(id, kid, nonce, ct)
		if err != nil || string(plain) != seed {
			t.Errorf("account %s: %v", id, err)
		}
		n++
	}
	if n != 150 {
		t.Errorf("rows = %d", n)
	}
}

// CS-004：对真实 im-server 的签名调用。需要同级目录有 tianting-server（CI 上是私有仓库，没有部署密钥时跳过）。
// startRealIM 编译并启动真实的 im-server，返回管理地址和调用方私钥。没有 tianting-server 源码时跳过。
func startRealIM(t *testing.T) (string, ed25519.PrivateKey) {
	admin, _, priv := startRealIMWS(t)
	return admin, priv
}

var allConsoleScopes = []string{"user.read", "user.write", "user.kick", "user.sessions", "token.issue", "group.read", "group.write", "group.dissolve", "msg.meta", "audit.read", "social.settings", "social.friends"}

// startRealIMWS 同时返回客户端（WebSocket）地址。
func startRealIMWS(t *testing.T) (adminAddress, wsAddress string, key ed25519.PrivateKey) {
	return startRealIMScopes(t, allConsoleScopes)
}

func startRealIMScopes(t *testing.T, scopes []string) (adminAddress, wsAddress string, key ed25519.PrivateKey) {
	t.Helper()
	src := os.Getenv("TIANTING_SERVER_DIR")
	if src == "" {
		src = "../../im-mvp/server"
	}
	if _, err := os.Stat(filepath.Join(src, "go.mod")); err != nil {
		t.Skip("tianting-server is not available")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "im-server")
	build := exec.Command("go", "build", "-o", bin, "./cmd/im-server")
	build.Dir = src
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	callers, _ := json.Marshal([]map[string]any{{
		"id": "console", "alg": "ed25519", "publicKey": base64.StdEncoding.EncodeToString(pub),
		"scopes": scopes,
	}})
	callersFile := filepath.Join(dir, "callers.json")
	if err := os.WriteFile(callersFile, callers, 0o600); err != nil {
		t.Fatal(err)
	}
	addr, adminAddr := freeAddr(t), freeAddr(t)
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(), "IM_ADDR="+addr, "IM_ADMIN_ADDR="+adminAddr, "IM_METRICS_ADDR=off", "IM_PPROF_ADDR=off", "IM_OPS_ADDR=off",
		"IM_DB="+filepath.Join(dir, "im.db"), "IM_ADMIN_CALLERS="+callersFile)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		if c, err := net.DialTimeout("tcp", adminAddr, 100*time.Millisecond); err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("im-server did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return adminAddr, addr, priv
}

func TestSignedCallToRealIMServer(t *testing.T) {
	adminAddr, _, priv := startRealIMScopes(t, []string{"user.read", "user.write", "audit.read"})
	cl, err := imclient.New(imclient.Config{BaseURL: "http://" + adminAddr, Caller: "console", Key: priv})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	call := imclient.Call{Operator: "admin:7", RequestID: "req-cs004"}
	if err := cl.Do(ctx, call, "POST", "/admin/users/import", nil, map[string]any{"users": []any{map[string]any{"userId": "u100", "nickname": "小明"}}}, nil); err != nil {
		t.Fatalf("import: %v", err)
	}
	var page struct {
		Users []struct {
			UserID   string `json:"userId"`
			Nickname string `json:"nickname"`
		} `json:"users"`
	}
	// 查询串带中文：规范化后的签名两边一致。
	if err := cl.Do(ctx, call, "GET", "/admin/users", url.Values{"q": {"小明"}, "limit": {"20"}}, nil, &page); err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(page.Users) != 1 || page.Users[0].UserID != "u100" {
		t.Errorf("page = %+v", page)
	}
	// 错误码原样透传。
	var e *apierr.Error
	if err := cl.Do(ctx, call, "GET", "/admin/users/nobody", nil, nil, nil); !errors.As(err, &e) || e.Code != 4042 {
		t.Errorf("err = %v", err)
	}
	// scope 不足：透传 4030。
	if err := cl.Do(ctx, call, "POST", "/admin/users/sessions/query", nil, map[string]any{"userId": "u100"}, nil); !errors.As(err, &e) || e.Code != 4030 {
		t.Errorf("scope err = %v", err)
	}
	// 操作人和请求 ID 进了 im-server 的审计。
	var audit struct {
		Entries []struct {
			Caller, Operator, RequestID string
		} `json:"entries"`
	}
	now := time.Now().UnixMilli()
	q := url.Values{"from": {fmt.Sprint(now - 60_000)}, "to": {fmt.Sprint(now + 60_000)}, "requestId": {"req-cs004"}}
	if err := cl.Do(ctx, imclient.Call{Operator: "admin:7", RequestID: "req-audit"}, "GET", "/admin/audit", q, nil, &audit); err != nil {
		t.Fatalf("audit: %v", err)
	}
	if len(audit.Entries) == 0 || audit.Entries[0].Caller != "console" || audit.Entries[0].Operator != "admin:7" {
		t.Errorf("audit = %+v", audit)
	}
	// 错误的私钥：401 / 4017。
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	bad, _ := imclient.New(imclient.Config{BaseURL: "http://" + adminAddr, Caller: "console", Key: other})
	if err := bad.Do(ctx, call, "GET", "/admin/users/u100", nil, nil, nil); !errors.As(err, &e) || e.Code != 4017 {
		t.Errorf("bad key err = %v", err)
	}
}
