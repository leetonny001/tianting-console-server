package e2e

import (
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"tianting/console/internal/totp"
)

const pathSession = "/console/api/session"

// AC-CON-02-1：引导：退出码、激活码、审计；已有启用超管时拒绝；ops 空间独立。
func TestCON02Bootstrap(t *testing.T) {
	_, appURL := newDB(t)
	env := []string{"CON_DATABASE_URL=" + appURL, "CON_DATA_KEYS=k1:" + b64(testDataKey)}
	out, err := run(t, env, "account", "bootstrap", "--space", "admin", "--username", "frank")
	if err != nil || !regexp.MustCompile(`[A-Z2-7]{20}`).MatchString(out) {
		t.Fatalf("bootstrap: %v\n%s", err, out)
	}
	code := regexp.MustCompile(`[A-Z2-7]{20}`).FindString(out)

	// 跑一个真实进程激活，确认 CLI 和服务用同一个 pepper。
	p := start(t, env...)
	resp := postJSON(t, "http://"+p.admin+"/console/api/auth/activate", fmt.Sprintf(`{"username":"frank","code":%q,"newPassword":%q}`, code, goodPass))
	if resp != 200 {
		t.Errorf("activate = %d", resp)
	}

	// 还没绑定 TOTP，账号不算启用：可以重发。
	if out, err := run(t, env, "account", "bootstrap", "--space", "admin", "--username", "frank"); err != nil {
		t.Errorf("rerun while pending: %v\n%s", err, out)
	}
	// 启用后拒绝（直接改状态模拟绑定完成，完整流程见 TestCON02Lifecycle）。
	ctx := context.Background()
	c, err := pgx.Connect(ctx, appURL)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	if _, err := c.Exec(ctx, `UPDATE auth.accounts SET status = 'active' WHERE username = 'frank'`); err != nil {
		t.Fatal(err)
	}
	if out, err := run(t, env, "account", "bootstrap", "--space", "admin", "--username", "frank"); err == nil || !strings.Contains(out, "already has an active super admin") {
		t.Errorf("second bootstrap: %v\n%s", err, out)
	}
	if out, err := run(t, env, "account", "bootstrap", "--space", "admin", "--username", "other"); err == nil {
		t.Errorf("another name: %s", out)
	}
	// ops 空间独立判断（TC-CON-02-02）。
	if out, err := run(t, env, "account", "bootstrap", "--space", "ops", "--username", "frank"); err != nil {
		t.Errorf("ops bootstrap: %v\n%s", err, out)
	}
	var n int
	if err := c.QueryRow(ctx, `SELECT count(*) FROM audit.records WHERE action = 'account.bootstrap' AND actor LIKE 'cli:%@%'`).Scan(&n); err != nil || n != 3 {
		t.Errorf("bootstrap audit = %d %v", n, err)
	}
	var leaked int
	if err := c.QueryRow(ctx, `SELECT count(*) FROM audit.records WHERE params LIKE '%' || $1 || '%' OR target LIKE '%' || $1 || '%'`, code).Scan(&leaked); err != nil || leaked != 0 {
		t.Errorf("activation code in audit: %d %v", leaked, err)
	}
}

func postJSON(t *testing.T, url, body string) int {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// AC-CON-02-2、02-3、02-4、02-10、02-11、12-2（激活）：新账号的完整生命周期。
func TestCON02Lifecycle(t *testing.T) {
	w := newWorld(t, nil)
	a1 := w.super("adm1")
	aud := a1.create("aud1", "auditor")

	a1.stepUp()
	r := a1.do("POST", "/console/api/accounts", map[string]any{"username": "kf1", "displayName": "客服一", "roles": []string{"support"}})
	expect(t, "create kf1", r, 200, 0)
	code, id := r.str("activationCode"), r.str("id")
	if len(code) != 20 {
		t.Errorf("code = %q", code)
	}
	if s := fmt.Sprint(w.auditRows(`action = 'account.create'`)); strings.Contains(s, code) {
		t.Error("activation code in audit")
	}

	// 同名 4092，跨空间同名成功（AC-CON-02-10）。
	expect(t, "same name", a1.do("POST", "/console/api/accounts", map[string]any{"username": "kf1", "displayName": "x", "roles": []string{"support"}}), 409, 4092)
	o1 := w.opsSuper("opsa1")
	o1.stepUp()
	expect(t, "same name in ops", o1.do("POST", "/console/api/accounts", map[string]any{"username": "kf1", "displayName": "x", "roles": []string{"ops_viewer"}}), 200, 0)

	// DELETE 405（AC-CON-02-11）。
	if r := a1.do("DELETE", "/console/api/accounts/"+id, nil); r.status != 405 {
		t.Errorf("delete = %d", r.status)
	}

	// 激活前不能登录。
	kf1 := w.client("kf1")
	r = kf1.do("POST", "/console/api/auth/login", map[string]any{"username": "kf1", "password": goodPass, "otp": "000000"})
	expect(t, "pending login", r, 401, 4015)
	// 错误激活码 4015。
	expect(t, "wrong code", kf1.do("POST", "/console/api/auth/activate", map[string]any{"username": "kf1", "code": "AAAAAAAAAAAAAAAAAAAA", "newPassword": goodPass}), 401, 4015)
	// 密码不合规：激活码正确才会提示。
	r = kf1.do("POST", "/console/api/auth/activate", map[string]any{"username": "kf1", "code": code, "newPassword": "short"})
	if r.status != 400 || r.reason() != "tooShort" {
		t.Errorf("weak password: %s", r.raw)
	}

	// setup 会话只能调设置接口（AC-CON-02-4）。
	r = kf1.do("POST", "/console/api/auth/activate", map[string]any{"username": "kf1", "code": code, "newPassword": goodPass})
	expect(t, "activate", r, 200, 0)
	if r.str("state") != "setup" {
		t.Errorf("state = %s", r.raw)
	}
	expect(t, "setup session", kf1.do("GET", "/console/api/users?q=u", nil), 401, 4016)
	expect(t, "setup session on a real route", kf1.do("GET", "/console/api/notifications", nil), 401, 4016)
	expect(t, "setup session step-up", kf1.do("POST", "/console/api/auth/step-up", map[string]any{"otp": "1"}), 401, 4016)
	r = kf1.do("GET", pathSession, nil)
	if r.status != 200 || r.str("state") != "setup" {
		t.Errorf("session = %s", r.raw)
	}
	// 同一个激活码不能再用。
	other := w.client("kf1")
	expect(t, "reuse code", other.do("POST", "/console/api/auth/activate", map[string]any{"username": "kf1", "code": code, "newPassword": goodPass}), 401, 4015)

	// 绑定：错误的码不升级；正确的码发 10 个恢复码。
	s := kf1.do("POST", "/console/api/auth/totp/setup", map[string]any{})
	expect(t, "totp setup", s, 200, 0)
	if !strings.HasPrefix(s.str("otpauthUri"), "otpauth://totp/") {
		t.Errorf("uri = %s", s.raw)
	}
	expect(t, "wrong otp", kf1.do("POST", "/console/api/auth/totp/confirm", map[string]any{"otp": "000000"}), 401, 4015)
	secret := regexp.MustCompile(`secret=([A-Z2-7]+)`).FindStringSubmatch(s.str("otpauthUri"))[1]
	kf1.seed = decodeSeed(t, secret)
	r = kf1.do("POST", "/console/api/auth/totp/confirm", map[string]any{"otp": kf1.otp()})
	expect(t, "confirm", r, 200, 0)
	if r.str("state") != "full" || len(r.body["recoveryCodes"].([]any)) != 10 {
		t.Errorf("confirm = %s", r.raw)
	}
	if perms := fmt.Sprint(r.body["perms"]); !strings.Contains(perms, "user.kick") || strings.Contains(perms, "admin.manage") {
		t.Errorf("perms = %s", perms)
	}
	// 通知超管和审计员（AC-CON-02-2、12-2），内容没有凭证。
	for _, u := range []*user{a1, aud} {
		n := w.notifications(u)
		if !hasNotice(n, "account.activated", "kf1") {
			t.Errorf("%s notifications = %v", u.name, n)
		}
		if s := strings.Join(n, " "); strings.Contains(s, code) || strings.Contains(s, kf1.otp()) {
			t.Errorf("credential in notification: %s", s)
		}
	}
	if n := w.notifications(kf1); hasNotice(n, "account.activated", "kf1") {
		t.Errorf("kf1 is neither super admin nor auditor: %v", n)
	}
	if rows := w.auditRows(`action = 'auth.totp_bound' AND username = 'kf1'`); len(rows) != 1 || rows[0]["ip"] != "10.0.0.1" {
		t.Errorf("bound audit = %v", rows)
	}
}

func decodeSeed(t *testing.T, s string) []byte {
	t.Helper()
	b, err := totpDecode(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// AC-CON-02-3：激活码 24 小时后失效。
func TestCON02ActivationExpires(t *testing.T) {
	w := newWorld(t, nil)
	a1 := w.super("adm1")
	a1.stepUp()
	r := a1.do("POST", "/console/api/accounts", map[string]any{"username": "kf2", "displayName": "x", "roles": []string{"support"}})
	code := r.str("activationCode")
	w.advance(24*time.Hour + time.Minute)
	expect(t, "expired", w.client("kf2").do("POST", "/console/api/auth/activate", map[string]any{"username": "kf2", "code": code, "newPassword": goodPass}), 401, 4015)
}

// AC-CON-02-6：跨空间隔离。
func TestCON02CrossSpace(t *testing.T) {
	w := newWorld(t, nil)
	a1 := w.super("adm1")
	o1 := w.opsSuper("ops1")
	a1.stepUp()
	r := a1.do("GET", "/console/api/accounts?username=ops1", nil)
	if strings.Contains(r.raw, "ops1") {
		t.Errorf("list shows ops account: %s", r.raw)
	}
	expect(t, "reset across spaces", a1.do("POST", "/console/api/accounts/"+o1.id+"/reset", map[string]any{}), 404, 4040)
	expect(t, "read across spaces", a1.do("GET", "/console/api/accounts/"+o1.id, nil), 404, 4040)
	rows := w.auditRows(`action = 'account.reset' AND phase = 'result'`)
	if len(rows) != 1 || rows[0]["result"] != "denied" || rows[0]["code"] != int32(4040) {
		t.Errorf("audit = %v", rows)
	}
	expect(t, "ops account intact", o1.do("GET", pathSession, nil), 200, 0)
	// 不是 UUID 的 ID 也是 404。
	expect(t, "bad id", a1.do("POST", "/console/api/accounts/not-a-uuid/reset", map[string]any{}), 404, 4040)

	// AC-CON-01-3：管理空间的 Cookie 值放到运维地址上：401 / 4014。
	crossed := w.opsClient("x")
	crossed.cookie = a1.cookie
	r = crossed.do("GET", pathSession, nil)
	expect(t, "cookie across spaces", r, 401, 4014)
}

// AC-CON-02-7：自我保护。
func TestCON02SelfProtection(t *testing.T) {
	w := newWorld(t, nil)
	a1 := w.super("adm1")
	a1.stepUp()
	expect(t, "own roles", a1.do("POST", "/console/api/accounts/"+a1.id+"/roles", map[string]any{"roles": []string{"support"}}), 409, 4093)
	expect(t, "disable self", a1.do("POST", "/console/api/accounts/"+a1.id+"/disable", map[string]any{}), 409, 4093)
	expect(t, "reset self", a1.do("POST", "/console/api/accounts/"+a1.id+"/reset", map[string]any{}), 409, 4093)
	a1.create("adm2", "super_admin")
	a1.stepUp()
	expect(t, "own roles with a second super", a1.do("POST", "/console/api/accounts/"+a1.id+"/roles", map[string]any{"roles": []string{"support"}}), 409, 4093)
	expect(t, "still works", a1.do("GET", pathSession, nil), 200, 0)
}

// AC-CON-02-8：并发互相停用，每轮恰好一个成功，启用的超管不少于 1。
func TestCON02ConcurrentDisable(t *testing.T) {
	w := newWorld(t, nil)
	a1 := w.super("adm1")
	a2 := a1.create("adm2", "super_admin")
	for round := range 20 {
		a1.stepUp()
		a2.stepUp()
		var wg sync.WaitGroup
		var ra, rb reply
		wg.Add(2)
		go func() {
			defer wg.Done()
			ra = a1.do("POST", "/console/api/accounts/"+a2.id+"/disable", map[string]any{})
		}()
		go func() {
			defer wg.Done()
			rb = a2.do("POST", "/console/api/accounts/"+a1.id+"/disable", map[string]any{})
		}()
		wg.Wait()
		wins := 0
		for _, r := range []reply{ra, rb} {
			switch {
			case r.status == 200:
				wins++
			case r.status == 409 && r.code() == 4093, r.status == 401 && r.code() == 4014:
			default:
				t.Fatalf("round %d: %d %s", round, r.status, r.raw)
			}
		}
		var active int
		if err := w.db.QueryRow(context.Background(), `SELECT count(*) FROM auth.accounts a JOIN auth.account_roles r ON r.account_id = a.id WHERE a.space = 'admin' AND a.status = 'active' AND r.role = 'super_admin'`).Scan(&active); err != nil {
			t.Fatal(err)
		}
		if wins != 1 || active != 1 {
			t.Fatalf("round %d: wins=%d active=%d (%s / %s)", round, wins, active, ra.raw, rb.raw)
		}
		// 恢复初始状态：胜者启用败者，败者重新登录。
		winner, loser := a1, a2
		if rb.status == 200 {
			winner, loser = a2, a1
		}
		winner.stepUp()
		expect(t, "enable", winner.do("POST", "/console/api/accounts/"+loser.id+"/enable", map[string]any{}), 200, 0)
		w.tick()
		loser.cookie, loser.csrf = "", ""
		expect(t, "login again", loser.login(), 200, 0)
	}
}

// AC-CON-02-9：重置后旧 Cookie、旧密码 + TOTP、旧恢复码都失败；新激活码可以激活；通知。
func TestCON02Reset(t *testing.T) {
	w := newWorld(t, nil)
	a1 := w.super("adm1")
	aud := a1.create("aud1", "auditor")
	a2 := a1.create("adm2", "super_admin")
	kf1 := a1.create("kf1", "support")
	oldSeed, oldRecovery := kf1.seed, kf1.recovery
	a1.stepUp()
	r := a1.do("POST", "/console/api/accounts/"+kf1.id+"/reset", map[string]any{})
	expect(t, "reset", r, 200, 0)
	code := r.str("activationCode")

	r = kf1.do("GET", pathSession, nil)
	expect(t, "old cookie", r, 401, 4014)
	if r.reason() != "revoked" {
		t.Errorf("reason = %s", r.reason())
	}
	w.tick()
	c := w.client("kf1")
	c.seed = oldSeed
	expect(t, "old password + totp", c.do("POST", "/console/api/auth/login", map[string]any{"username": "kf1", "password": goodPass, "otp": c.otp()}), 401, 4015)
	expect(t, "old recovery", c.do("POST", "/console/api/auth/login", map[string]any{"username": "kf1", "password": goodPass, "recoveryCode": oldRecovery[0]}), 401, 4015)
	c.password = "Another-Good-Pass-77"
	c.activate(code)

	for _, u := range []*user{a2, aud} {
		if !hasNotice(w.notifications(u), "account.reset", "kf1") {
			t.Errorf("%s not notified", u.name)
		}
	}
	if hasNotice(w.notifications(kf1), "account.reset", "kf1") {
		t.Error("the reset account itself should not be notified")
	}
}

// AC-CON-03-2：6 种失败响应相同。
func TestCON03UniformFailure(t *testing.T) {
	w := newWorld(t, map[string]string{"CON_TEST_DISABLE_LOCKOUT": "1"})
	a1 := w.super("adm1")
	kf1 := a1.create("kf1", "support")
	dis := a1.create("dis1", "support")
	a1.stepUp()
	expect(t, "disable", a1.do("POST", "/console/api/accounts/"+dis.id+"/disable", map[string]any{}), 200, 0)
	a1.do("POST", "/console/api/accounts", map[string]any{"username": "pend1", "displayName": "x", "roles": []string{"support"}})
	w.tick()
	login := func(name, password string, extra map[string]any) reply {
		body := map[string]any{"username": name, "password": password}
		for k, v := range extra {
			body[k] = v
		}
		return w.client(name).do("POST", "/console/api/auth/login", body)
	}
	cases := map[string]reply{
		"notFound": login("ghost", goodPass, map[string]any{"otp": "123456"}),
		"password": login("kf1", "wrong-password-xx", map[string]any{"otp": kf1.otp()}),
		"otp":      login("kf1", goodPass, map[string]any{"otp": "000000"}),
		"recovery": login("kf1", goodPass, map[string]any{"recoveryCode": "AAAAAAAAAAAAAAAA"}),
		"disabled": login("dis1", goodPass, map[string]any{"otp": dis.otp()}),
		"pending":  login("pend1", goodPass, map[string]any{"otp": "123456"}),
	}
	first := cases["notFound"]
	names := func(h http.Header) string {
		var k []string
		for n := range h {
			if n != "Date" {
				k = append(k, n)
			}
		}
		sort.Strings(k)
		return strings.Join(k, ",")
	}
	for name, r := range cases {
		expect(t, name, r, 401, 4015)
		if r.raw != first.raw || names(r.header) != names(first.header) {
			t.Errorf("%s differs:\n%s %v\n%s %v", name, r.raw, names(r.header), first.raw, names(first.header))
		}
		if r.header.Get("Set-Cookie") != "" {
			t.Errorf("%s sets a cookie", name)
		}
	}
	// 类别只进审计。
	rows := w.auditRows(`action = 'auth.login' AND result = 'failure'`)
	seen := map[string]bool{}
	for _, row := range rows {
		seen[row["params"].(string)] = true
	}
	for _, cat := range []string{"notFound", "password", "otp", "recovery", "disabled", "pending"} {
		if !seen[fmt.Sprintf(`{"category":%q}`, cat)] {
			t.Errorf("audit misses category %s: %v", cat, seen)
		}
	}
}

// AC-CON-03-1、05-1、03-7、05-15：登录成功、Cookie 属性、防会话固定、库里只有哈希。
func TestCON03LoginAndCookie(t *testing.T) {
	w := newWorld(t, nil)
	a1 := w.super("adm1")
	w.tick()
	u := w.client("adm1")
	u.seed = a1.seed
	u.cookie = "attacker-chosen"
	r := u.login()
	expect(t, "login", r, 200, 0)
	sc := r.header.Get("Set-Cookie")
	for _, want := range []string{"__Host-adm_sid=", "HttpOnly", "Secure", "SameSite=Strict", "Path=/"} {
		if !strings.Contains(sc, want) {
			t.Errorf("Set-Cookie = %s, missing %s", sc, want)
		}
	}
	if strings.Contains(strings.ToLower(sc), "domain") {
		t.Errorf("Set-Cookie has Domain: %s", sc)
	}
	if u.cookie == "attacker-chosen" || len(u.cookie) < 22 {
		t.Errorf("cookie = %s", u.cookie)
	}
	if r.str("csrfToken") == "" || r.body["account"] == nil || r.body["roles"] == nil || r.body["perms"] == nil {
		t.Errorf("login response = %s", r.raw)
	}
	fixed := w.client("adm1")
	fixed.cookie = "attacker-chosen"
	expect(t, "fixed session", fixed.do("GET", pathSession, nil), 401, 4014)
	// 库里只有 SHA-256（AC-CON-05-15）。
	var hits int
	if err := w.db.QueryRow(context.Background(), `SELECT count(*) FROM auth.sessions WHERE id_hash = $1 OR csrf_token_hash = $1`, u.cookie).Scan(&hits); err != nil || hits != 0 {
		t.Errorf("cookie stored in the clear: %d %v", hits, err)
	}
	// CSRF 令牌不轮换（AC-CON-05-10 的服务端部分）。
	if s := u.do("GET", pathSession, nil); s.str("csrfToken") != r.str("csrfToken") {
		t.Errorf("csrf rotated: %s vs %s", s.str("csrfToken"), r.str("csrfToken"))
	}
	// 密码哈希（AC-CON-04-2）。
	var h1 string
	if err := w.db.QueryRow(context.Background(), `SELECT password_hash FROM auth.accounts WHERE username = 'adm1'`).Scan(&h1); err != nil || !strings.HasPrefix(h1, "$argon2id$") {
		t.Errorf("hash = %s %v", h1, err)
	}
}

// AC-CON-03-4、03-5：动态码防重放、窗口。
func TestCON03TOTP(t *testing.T) {
	w := newWorld(t, nil)
	a1 := w.super("adm1")
	w.tick()
	code := a1.otp()
	u := w.client("adm1")
	expect(t, "first use", u.do("POST", "/console/api/auth/login", map[string]any{"username": "adm1", "password": goodPass, "otp": code}), 200, 0)
	replay := w.client("adm1")
	replay.ip = "10.0.0.2"
	expect(t, "replay at login", replay.do("POST", "/console/api/auth/login", map[string]any{"username": "adm1", "password": goodPass, "otp": code}), 401, 4015)
	expect(t, "replay at step-up", u.do("POST", "/console/api/auth/step-up", map[string]any{"otp": code}), 401, 4015)
	// 计入失败次数。
	var n int
	if err := w.db.QueryRow(context.Background(), `SELECT count FROM auth.login_failures WHERE key = 'n|admin|adm1|10.0.0.2'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("failures = %d %v", n, err)
	}

	step := func(d int64) string { return totp.Code(a1.seed, totp.Step(w.now)+d) }
	w.advance(5 * time.Minute)
	expect(t, "T-2", w.client("adm1").do("POST", "/console/api/auth/login", map[string]any{"username": "adm1", "password": goodPass, "otp": step(-2)}), 401, 4015)
	expect(t, "T+1", w.client("adm1").do("POST", "/console/api/auth/login", map[string]any{"username": "adm1", "password": goodPass, "otp": step(1)}), 200, 0)
	// T+1 用过之后 T、T-1 都不能用（步长 ≤ last_step）。
	expect(t, "older after newer", w.client("adm1").do("POST", "/console/api/auth/login", map[string]any{"username": "adm1", "password": goodPass, "otp": step(0)}), 401, 4015)
	w.advance(5 * time.Minute)
	expect(t, "T-1", w.client("adm1").do("POST", "/console/api/auth/login", map[string]any{"username": "adm1", "password": goodPass, "otp": step(-1)}), 200, 0)

	// 同一个码并发：恰好一个成功。
	w.advance(5 * time.Minute)
	code = a1.otp()
	var wg sync.WaitGroup
	oks := make(chan int, 8)
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := w.client("adm1")
			c.ip = fmt.Sprintf("10.1.0.%d", i)
			oks <- c.do("POST", "/console/api/auth/login", map[string]any{"username": "adm1", "password": goodPass, "otp": code}).status
		}()
	}
	wg.Wait()
	close(oks)
	wins := 0
	for s := range oks {
		if s == 200 {
			wins++
		}
	}
	if wins != 1 {
		t.Errorf("concurrent replay: %d wins", wins)
	}
}

// AC-CON-03-6、03-9：恢复码。
func TestCON03Recovery(t *testing.T) {
	w := newWorld(t, nil)
	a1 := w.super("adm1")
	kf := a1.create("kf1", "support")
	r1 := kf.recovery[0]
	c := w.client("kf1")
	expect(t, "recovery login", c.do("POST", "/console/api/auth/login", map[string]any{"username": "kf1", "password": goodPass, "recoveryCode": r1}), 200, 0)
	if rows := w.auditRows(`action = 'auth.recovery_code_used' AND username = 'kf1'`); len(rows) != 1 {
		t.Errorf("audit = %v", rows)
	}
	if !hasNotice(w.notifications(kf), "auth.recovery_code_used", "kf1") {
		t.Error("no notification")
	}
	expect(t, "reused", w.client("kf1").do("POST", "/console/api/auth/login", map[string]any{"username": "kf1", "password": goodPass, "recoveryCode": r1}), 401, 4015)
	// 不区分大小写和分隔符的输入，但错的还是错。
	r2 := kf.recovery[1]
	expect(t, "formatted", w.client("kf1").do("POST", "/console/api/auth/login", map[string]any{"username": "kf1", "password": goodPass, "recoveryCode": strings.ToLower(r2[:4]) + "-" + r2[4:]}), 200, 0)

	// 用到只剩 2 个时提示。
	for _, code := range kf.recovery[2:8] {
		expect(t, "use", w.client("kf1").do("POST", "/console/api/auth/login", map[string]any{"username": "kf1", "password": goodPass, "recoveryCode": code}), 200, 0)
	}
	w.tick()
	u := w.client("kf1")
	u.seed = kf.seed
	r := u.login()
	expect(t, "login", r, 200, 0)
	if r.body["recoveryCodesLeft"] != float64(2) {
		t.Errorf("left = %v", r.body["recoveryCodesLeft"])
	}
	if !hasNotice(w.notifications(kf), "auth.recovery_codes_low", "kf1") {
		t.Error("no low notification")
	}

	// 重新生成要 step-up（AC-CON-03-9）。
	expect(t, "no step-up", u.do("POST", "/console/api/me/recovery-codes", map[string]any{}), 403, 4038)
	u.stepUp()
	r = u.do("POST", "/console/api/me/recovery-codes", map[string]any{})
	expect(t, "regenerate", r, 200, 0)
	if len(r.body["recoveryCodes"].([]any)) != 10 {
		t.Errorf("codes = %s", r.raw)
	}
	if rows := w.auditRows(`action = 'auth.recovery_codes_regenerated' AND phase = 'result' AND result = 'success'`); len(rows) != 1 {
		t.Errorf("audit = %v", rows)
	}
	expect(t, "old code gone", w.client("kf1").do("POST", "/console/api/auth/login", map[string]any{"username": "kf1", "password": goodPass, "recoveryCode": kf.recovery[8]}), 401, 4015)
}

// AC-CON-03-8：密码、动态码不进日志和审计。
func TestCON03NoCredentialsInLogsOrAudit(t *testing.T) {
	w := newWorld(t, nil)
	w.super("adm1")
	const pw, otp = "Pw-CANARY-7f3a91", "123456"
	expect(t, "login", w.client("adm1").do("POST", "/console/api/auth/login", map[string]any{"username": "adm1", "password": pw, "otp": otp}), 401, 4015)
	if strings.Contains(w.logs.String(), pw) {
		t.Errorf("password in logs: %s", w.logs.String())
	}
	dump := fmt.Sprint(w.auditRows(`true`))
	if strings.Contains(dump, pw) || strings.Contains(dump, `"otp"`) || strings.Contains(dump, otp) {
		t.Errorf("credential in audit: %s", dump)
	}
}

// AC-CON-03-3：响应时间。默认 Argon2id 参数下比较中位数。
func TestCON03Timing(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	w := newWorld(t, map[string]string{"CON_TEST_DISABLE_LOCKOUT": "1", "CON_ARGON_MEMORY_KIB": "65536", "CON_ARGON_TIME": "3"})
	w.super("adm1")
	measure := func(name string) time.Duration {
		var d []time.Duration
		for range 15 {
			start := time.Now()
			expect(t, name, w.client(name).do("POST", "/console/api/auth/login", map[string]any{"username": name, "password": "wrong-password-xx", "otp": "123456"}), 401, 4015)
			d = append(d, time.Since(start))
		}
		slices.Sort(d)
		return d[len(d)/2]
	}
	ghost, real := measure("ghost"), measure("adm1")
	diff := ghost - real
	if diff < 0 {
		diff = -diff
	}
	if diff > 30*time.Millisecond {
		t.Errorf("median: ghost %v, real %v", ghost, real)
	}
}

// AC-CON-04-1、改密码（F-CON-04 规则 2）。
func TestCON04PasswordPolicy(t *testing.T) {
	w := newWorld(t, nil)
	a1 := w.super("adm1")
	kf := a1.create("kf1", "support")
	second := w.client("kf1")
	second.seed = kf.seed
	w.tick()
	expect(t, "second session", second.login(), 200, 0)
	change := func(next string) reply {
		w.tick()
		return kf.do("POST", "/console/api/me/password", map[string]any{"currentPassword": kf.password, "otp": kf.otp(), "newPassword": next})
	}
	for next, reason := range map[string]string{
		"abc12345678":   "tooShort",
		"password1234":  "weak",
		"PASSWORD1234":  "weak",
		"xkf1yzzzzzzzz": "containsUsername",
		goodPass:        "reused",
	} {
		r := change(next)
		if r.status != 400 || r.code() != 4000 || r.reason() != reason {
			t.Errorf("%s: %s, want %s", next, r.raw, reason)
		}
	}
	if r := change(strings.Repeat("x", 129)); r.reason() != "tooLong" {
		t.Errorf("tooLong: %s", r.raw)
	}
	expect(t, "strong", change("Rand0m-Sixteen-Ch"), 200, 0)
	kf.password = "Rand0m-Sixteen-Ch"
	expect(t, "current session stays", kf.do("GET", pathSession, nil), 200, 0)
	r := second.do("GET", pathSession, nil)
	expect(t, "other session revoked", r, 401, 4014)
	if r.reason() != "revoked" {
		t.Errorf("reason = %s", r.reason())
	}
	// 最近 5 次：换 5 次之后第一个才能用回。
	for i := range 4 {
		next := fmt.Sprintf("Rotate-Pass-%d-Xq9z", i)
		expect(t, "rotate", change(next), 200, 0)
		kf.password = next
	}
	if r := change("Rand0m-Sixteen-Ch"); r.reason() != "reused" {
		t.Errorf("within 5: %s", r.raw)
	}
	expect(t, "fifth rotation", change("Rotate-Pass-Final-9"), 200, 0)
	kf.password = "Rotate-Pass-Final-9"
	expect(t, "first password out of history", change(goodPass), 200, 0)
	// 错误的当前密码。
	w.tick()
	expect(t, "wrong current", kf.do("POST", "/console/api/me/password", map[string]any{"currentPassword": "nope-nope-nope", "otp": kf.otp(), "newPassword": "Anything-Strong-7"}), 401, 4015)
}

func lockableWorld(t *testing.T) (*world, *user) {
	w := newWorld(t, nil)
	a1 := w.super("adm1")
	return w, a1.create("kf1", "support")
}

func failLogin(w *world, name, ip string) reply {
	c := w.client(name)
	c.ip = ip
	return c.do("POST", "/console/api/auth/login", map[string]any{"username": name, "password": "wrong-password-xx", "otp": "000000"})
}

// AC-CON-04-3、04-4：按账号名 + IP 锁定；不存在的账号响应相同。
func TestCON04Lockout(t *testing.T) {
	w, kf := lockableWorld(t)
	for i := range 5 {
		expect(t, fmt.Sprint("fail ", i), failLogin(w, "kf1", "10.2.0.1"), 401, 4015)
	}
	good := func(ip string) reply {
		w.tick()
		c := w.client("kf1")
		c.ip, c.seed = ip, kf.seed
		return c.login()
	}
	locked := good("10.2.0.1")
	expect(t, "locked", locked, 429, 4291)
	expect(t, "other ip", good("10.2.0.2"), 200, 0)
	for range 5 {
		failLogin(w, "ghost", "10.2.0.1")
	}
	ghost := failLogin(w, "ghost", "10.2.0.1")
	expect(t, "ghost locked", ghost, 429, 4291)
	if ghost.raw != locked.raw || headerNames(ghost.header) != headerNames(locked.header) {
		t.Errorf("responses differ:\n%s\n%s", ghost.raw, locked.raw)
	}
	w.advance(15 * time.Minute)
	expect(t, "after 15 minutes", good("10.2.0.1"), 200, 0)
	if rows := w.auditRows(`action = 'auth.lockout' AND username = 'kf1'`); len(rows) != 1 {
		t.Errorf("lockout audit = %v", rows)
	}
}

func headerNames(h http.Header) string {
	var k []string
	for n := range h {
		if n != "Date" {
			k = append(k, n)
		}
	}
	sort.Strings(k)
	return strings.Join(k, ",")
}

// AC-CON-04-5：成功登录清零。
func TestCON04SuccessClears(t *testing.T) {
	w, kf := lockableWorld(t)
	for range 4 {
		failLogin(w, "kf1", "10.3.0.1")
	}
	w.tick()
	c := w.client("kf1")
	c.ip, c.seed = "10.3.0.1", kf.seed
	expect(t, "success", c.login(), 200, 0)
	for i := range 4 {
		expect(t, fmt.Sprint("fail again ", i), failLogin(w, "kf1", "10.3.0.1"), 401, 4015)
	}
}

// AC-CON-04-6：账号名全局 50 次。
func TestCON04GlobalLock(t *testing.T) {
	w, kf := lockableWorld(t)
	for ip := range 11 {
		n := 5
		if ip == 10 {
			n = 0
		}
		for range n {
			// 每个 IP 分钟内限流 20 次，5 次不会触发。
			failLogin(w, "kf1", fmt.Sprintf("10.4.0.%d", ip))
		}
	}
	good := func(ip string) reply {
		w.tick()
		c := w.client("kf1")
		c.ip, c.seed = ip, kf.seed
		return c.login()
	}
	expect(t, "new ip", good("10.4.1.1"), 429, 4291)
	w.advance(time.Hour)
	expect(t, "after an hour", good("10.4.1.1"), 200, 0)
}

// AC-CON-04-7：同一 IP 每分钟 20 次。
func TestCON04IPRate(t *testing.T) {
	w := newWorld(t, nil)
	for i := range 20 {
		r := failLogin(w, fmt.Sprintf("user%d", i), "10.5.0.1")
		expect(t, fmt.Sprint("attempt ", i), r, 401, 4015)
	}
	expect(t, "21st", failLogin(w, "user99", "10.5.0.1"), 429, 4290)
	expect(t, "other ip", failLogin(w, "user99", "10.5.0.2"), 401, 4015)
	// 激活共用同一个计数。
	c := w.client("x")
	c.ip = "10.5.0.1"
	expect(t, "activate shares the limit", c.do("POST", "/console/api/auth/activate", map[string]any{"username": "x", "code": "A", "newPassword": "B"}), 429, 4290)
	w.advance(time.Minute)
	expect(t, "next minute", failLogin(w, "user99", "10.5.0.1"), 401, 4015)
}

// AC-CON-04-9、12-1：解锁要 step-up；锁定通知本人和超管。
func TestCON04Unlock(t *testing.T) {
	w := newWorld(t, nil)
	a1 := w.super("adm1")
	kf := a1.create("kf1", "support")
	for range 5 {
		failLogin(w, "kf1", "10.6.0.1")
	}
	w.tick()
	c := w.client("kf1")
	c.ip, c.seed = "10.6.0.1", kf.seed
	expect(t, "locked", c.login(), 429, 4291)
	w.advance(6 * time.Minute) // 让 a1 的 step-up 过期
	expect(t, "unlock without step-up", a1.do("POST", "/console/api/accounts/"+kf.id+"/unlock", map[string]any{}), 403, 4038)
	a1.stepUp()
	expect(t, "unlock", a1.do("POST", "/console/api/accounts/"+kf.id+"/unlock", map[string]any{}), 200, 0)
	w.tick()
	expect(t, "after unlock", c.login(), 200, 0)
	if rows := w.auditRows(`action = 'account.unlock' AND phase = 'result' AND result = 'success'`); len(rows) != 1 {
		t.Errorf("audit = %v", rows)
	}
	for _, u := range []*user{kf, a1} {
		if !hasNotice(w.notifications(u), "account.locked", "kf1") {
			t.Errorf("%s not notified", u.name)
		}
	}
	// 命令行解锁见 TestCON04CLIUnlock。
}

// F-CON-04 规则 6：命令行解锁写审计。
func TestCON04CLIUnlock(t *testing.T) {
	_, appURL := newDB(t)
	env := []string{"CON_DATABASE_URL=" + appURL}
	if out, err := run(t, env, "account", "unlock", "--space", "admin", "--username", "kf1"); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	c, err := pgx.Connect(context.Background(), appURL)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(context.Background())
	var actor string
	if err := c.QueryRow(context.Background(), `SELECT actor FROM audit.records WHERE action = 'account.unlock'`).Scan(&actor); err != nil || !strings.HasPrefix(actor, "cli:") {
		t.Errorf("actor = %q %v", actor, err)
	}
}

// AC-CON-04-8、01-5：两个实例共享计数和会话。
func TestCON04TwoInstances(t *testing.T) {
	w, kf := lockableWorld(t)
	second, err := newAppSameDB(w)
	if err != nil {
		t.Fatal(err)
	}
	fails := func(u *user, n int) {
		for range n {
			u.ip = "10.7.0.1"
			u.do("POST", "/console/api/auth/login", map[string]any{"username": "kf1", "password": "wrong-password-xx", "otp": "000000"})
		}
	}
	a := w.client("kf1")
	b := w.client("kf1")
	b.srv = second
	fails(a, 3)
	fails(b, 2)
	for _, srv := range []*user{a, b} {
		srv.ip = "10.7.0.1"
		expect(t, "locked on both", srv.do("POST", "/console/api/auth/login", map[string]any{"username": "kf1", "password": goodPass, "otp": "000000"}), 429, 4291)
	}
	// 在 A 登录的会话在 B 可用；在 B 退出后 A 401。
	s := w.client("kf1")
	s.seed, s.ip = kf.seed, "10.7.0.9"
	w.tick()
	expect(t, "login on A", s.login(), 200, 0)
	s.srv = second
	expect(t, "session on B", s.do("GET", pathSession, nil), 200, 0)
	expect(t, "logout on B", s.do("POST", "/console/api/auth/logout", map[string]any{}), 200, 0)
	s.srv = w.admin
	expect(t, "gone on A", s.do("GET", pathSession, nil), 401, 4014)
}

// AC-CON-05-3、05-4、05-5：过期。
func TestCON05Expiry(t *testing.T) {
	w := newWorld(t, nil)
	a1 := w.super("adm1")
	expect(t, "T", a1.do("GET", pathSession, nil), 200, 0)
	w.advance(29 * time.Minute)
	expect(t, "T+29", a1.do("GET", pathSession, nil), 200, 0)
	w.advance(31 * time.Minute)
	r := a1.do("GET", pathSession, nil)
	expect(t, "T+60", r, 401, 4014)
	if r.reason() != "idle" {
		t.Errorf("reason = %s", r.reason())
	}

	// 绝对过期。
	w.tick()
	u := w.client("adm1")
	u.seed = a1.seed
	expect(t, "login", u.login(), 200, 0)
	for range 72 {
		w.advance(10 * time.Minute)
		if r := u.do("GET", pathSession, nil); r.status != 200 {
			t.Fatalf("still within 12 hours: %s", r.raw)
		}
	}
	w.advance(time.Minute)
	r = u.do("GET", pathSession, nil)
	if r.status != 401 || r.reason() != "absolute" {
		t.Errorf("absolute: %s", r.raw)
	}

	// 后台请求不续期。
	w.tick()
	b := w.client("adm1")
	b.seed = a1.seed
	expect(t, "login", b.login(), 200, 0)
	for range 30 {
		w.advance(time.Minute)
		expect(t, "background", b.do("GET", "/console/api/notifications/unread-count", nil, background), 200, 0)
	}
	w.advance(time.Minute)
	r = b.do("GET", pathSession, nil)
	if r.status != 401 || r.reason() != "idle" {
		t.Errorf("background must not renew: %s", r.raw)
	}
}

// AC-CON-05-6～05-9、05-11、05-13。
func TestCON05SessionRules(t *testing.T) {
	w := newWorld(t, nil)
	a1 := w.super("adm1")
	r := a1.do("GET", pathSession, nil)
	if r.header.Get("Cache-Control") != "no-store" {
		t.Errorf("headers = %v", r.header)
	}

	// CSRF：不带、错误、错误 Origin（业务不执行，不进审计）。
	before := len(w.auditRows(`true`))
	path := "/console/api/notifications/read"
	expect(t, "no token", a1.do("POST", path, map[string]any{}, func(r *http.Request) { r.Header.Del("X-CSRF-Token") }), 403, 4037)
	expect(t, "bad token", a1.do("POST", path, map[string]any{}, func(r *http.Request) { r.Header.Set("X-CSRF-Token", "wrong") }), 403, 4037)
	expect(t, "evil origin", a1.do("POST", path, map[string]any{}, func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }), 403, 4037)
	expect(t, "no origin", a1.do("POST", path, map[string]any{}, func(r *http.Request) { r.Header.Del("Origin") }), 403, 4037)
	if after := len(w.auditRows(`true`)); after != before {
		t.Errorf("csrf rejections wrote audit: %d -> %d", before, after)
	}
	// 登录也校验 Origin（防登录 CSRF）。
	expect(t, "login from evil origin", w.client("adm1").do("POST", "/console/api/auth/login", map[string]any{"username": "adm1"}, func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }), 403, 4037)

	// 退出后重放。
	w.tick()
	s := w.client("adm1")
	s.seed = a1.seed
	expect(t, "login", s.login(), 200, 0)
	cookie := s.cookie
	expect(t, "logout", s.do("POST", "/console/api/auth/logout", map[string]any{}), 200, 0)
	s.cookie = cookie
	r = s.do("GET", pathSession, nil)
	if r.status != 401 || r.reason() != "loggedOut" {
		t.Errorf("after logout: %s", r.raw)
	}

	// 第 4 个会话挤掉最早的。
	kf := a1.create("kf1", "support")
	sessions := []*user{kf}
	for range 3 {
		w.tick()
		c := w.client("kf1")
		c.seed = kf.seed
		expect(t, "login", c.login(), 200, 0)
		sessions = append(sessions, c)
	}
	r = sessions[0].do("GET", pathSession, nil)
	if r.status != 401 || r.reason() != "replaced" {
		t.Errorf("first session: %s", r.raw)
	}
	for _, c := range sessions[1:] {
		expect(t, "others still valid", c.do("GET", pathSession, nil), 200, 0)
	}

	// 改角色：全部会话 revoked，重新登录后按新角色。
	a1.stepUp()
	expect(t, "change roles", a1.do("POST", "/console/api/accounts/"+kf.id+"/roles", map[string]any{"roles": []string{"operator"}}), 200, 0)
	for _, c := range sessions[1:] {
		r := c.do("GET", pathSession, nil)
		if r.status != 401 || r.reason() != "revoked" {
			t.Errorf("after role change: %s", r.raw)
		}
	}
	w.tick()
	n := w.client("kf1")
	n.seed = kf.seed
	r = n.login()
	expect(t, "login", r, 200, 0)
	if p := fmt.Sprint(r.body["perms"]); !strings.Contains(p, "user.import") || strings.Contains(p, "user.kick") {
		t.Errorf("perms = %s", p)
	}
	// 没带 Cookie：reason=none（AC-CON-06-5 的计数在 TestCON06Denied）。
	r = w.client("x").do("GET", pathSession, nil)
	if r.status != 401 || r.reason() != "none" {
		t.Errorf("no cookie: %s", r.raw)
	}
}

// AC-CON-06-2～06-6、06-9、06-10。
func TestCON06Roles(t *testing.T) {
	w := newWorld(t, nil)
	a1 := w.super("adm1")
	aud := a1.create("aud1", "auditor")

	// 敏感角色通知审计员（AC-CON-06-9）；非敏感不通知。
	before := len(w.notifications(aud))
	both := a1.create("both1", "support", "operator")
	if got := w.notifications(aud); hasNotice(got[before:], "account.sensitive_role", "both1") {
		t.Errorf("non-sensitive role notified: %v", got)
	}
	a1.create("mod1", "moderator")
	if !hasNotice(w.notifications(aud), "account.sensitive_role", "mod1") {
		t.Error("auditor not notified of moderator")
	}

	// 叠加角色取并集（AC-CON-06-2）。
	r := both.do("GET", pathSession, nil)
	for _, p := range []string{"user.kick", "user.import"} {
		if !strings.Contains(fmt.Sprint(r.body["perms"]), p) {
			t.Errorf("perms = %v", r.body["perms"])
		}
	}

	// 无权限 403 + denied 审计（AC-CON-06-3 的机制，用账号接口）。
	kf := a1.create("kf1", "support")
	expect(t, "support lists accounts", kf.do("GET", "/console/api/accounts", nil), 403, 4030)
	rows := w.auditRows(`action = 'account.list' AND result = 'denied'`)
	if len(rows) != 1 || rows[0]["username"] != "kf1" || rows[0]["code"] != int32(4030) {
		t.Errorf("denied audit = %v", rows)
	}

	// 互斥角色（AC-CON-06-6）。
	a1.stepUp()
	expect(t, "support + auditor", a1.do("POST", "/console/api/accounts/"+kf.id+"/roles", map[string]any{"roles": []string{"support", "auditor"}}), 409, 4093)
	expect(t, "auditor + support at creation", a1.do("POST", "/console/api/accounts", map[string]any{"username": "x12", "displayName": "x", "roles": []string{"auditor", "support"}}), 409, 4093)
	expect(t, "ops role in admin space", a1.do("POST", "/console/api/accounts/"+kf.id+"/roles", map[string]any{"roles": []string{"ops_viewer"}}), 400, 4000)
	if r := kf.do("GET", pathSession, nil); r.status != 200 {
		t.Errorf("roles changed: %s", r.raw)
	}

	// 运维空间（AC-CON-06-10）；没有应急授权（PRD-ops AC-OPS-02-9）。
	o1 := w.opsSuper("opsa1")
	eng := o1.create("eng1", "ops_engineer")
	o1.stepUp()
	for _, role := range []string{"ops_superadmin", "ops_auditor"} {
		expect(t, role, o1.do("POST", "/console/api/accounts/"+eng.id+"/roles", map[string]any{"roles": []string{"ops_engineer", role}}), 409, 4093)
	}
	expect(t, "no emergency in ops", o1.do("POST", "/console/api/me/emergency-grants", map[string]any{"role": "ops_viewer", "minutes": 30, "reason": "检查线上问题"}), 403, 4030)
}

// AC-CON-06-4、06-5：拒绝合并；未认证的拒绝不进审计。
func TestCON06Denied(t *testing.T) {
	w := newWorld(t, nil)
	a1 := w.super("adm1")
	kf := a1.create("kf1", "support")
	base := len(w.auditRows(`true`))
	for range 100 {
		expect(t, "no session", w.client("x").do("GET", "/console/api/users", nil), 401, 4014)
	}
	if got := len(w.auditRows(`true`)); got != base {
		t.Errorf("unauthenticated requests wrote audit: %d", got-base)
	}
	if v := metricValue(t, w, `console_rejected_total{reason="noSession"}`); v != 100 {
		t.Errorf("noSession = %v", v)
	}

	// 等到一分钟开头：30 次都在同一分钟。
	w.advance(time.Duration(60_000-w.now.UnixMilli()%60_000) * time.Millisecond)
	for range 30 {
		expect(t, "denied", kf.do("GET", "/console/api/accounts", nil), 403, 4030)
	}
	if rows := w.auditRows(`username = 'kf1' AND result = 'denied'`); len(rows) != 20 {
		t.Errorf("individual denied = %d", len(rows))
	}
	w.advance(time.Minute)
	if err := w.a.FlushDenied(context.Background()); err != nil {
		t.Fatal(err)
	}
	merged := w.auditRows(`action = 'authz.denied_merged' AND username = 'kf1'`)
	if len(merged) != 1 || !strings.Contains(merged[0]["params"].(string), `"count":10`) || !strings.Contains(merged[0]["params"].(string), "account.list") {
		t.Errorf("merged = %v", merged)
	}
	if err := w.a.FlushDenied(context.Background()); err != nil {
		t.Fatal(err)
	}
	if again := w.auditRows(`action = 'authz.denied_merged'`); len(again) != 1 {
		t.Errorf("flushed twice: %d", len(again))
	}
}

// AC-CON-06-7、06-8：应急授权。
func TestCON06Emergency(t *testing.T) {
	w := newWorld(t, nil)
	a1 := w.super("adm1")
	a2 := a1.create("adm2", "super_admin")
	aud := a1.create("aud1", "auditor")
	path := "/console/api/me/emergency-grants"
	w.advance(6 * time.Minute)
	expect(t, "without step-up", a1.do("POST", path, map[string]any{"role": "moderator", "minutes": 30, "reason": "处理举报 T-1"}), 403, 4038)
	a1.stepUp()
	expect(t, "auditor", a1.do("POST", path, map[string]any{"role": "auditor", "minutes": 30, "reason": "处理举报 T-1"}), 400, 4000)
	expect(t, "300 minutes", a1.do("POST", path, map[string]any{"role": "moderator", "minutes": 300, "reason": "处理举报 T-1"}), 400, 4000)
	expect(t, "no reason", a1.do("POST", path, map[string]any{"role": "moderator", "minutes": 30}), 400, 4000)
	expect(t, "repeated char reason", a1.do("POST", path, map[string]any{"role": "moderator", "minutes": 30, "reason": "aaaa"}), 400, 4000)
	expect(t, "super admin", a1.do("POST", path, map[string]any{"role": "super_admin", "minutes": 30, "reason": "处理举报 T-1"}), 400, 4000)
	expect(t, "grant", a1.do("POST", path, map[string]any{"role": "moderator", "minutes": 30, "reason": "处理举报 T-1"}), 200, 0)
	if r := a1.do("GET", pathSession, nil); !strings.Contains(fmt.Sprint(r.body["perms"]), "user.kick") {
		t.Errorf("perms = %v", r.body["perms"])
	}
	rows := w.auditRows(`action = 'account.emergency_grant' AND phase = 'result'`)
	if len(rows) != 1 || rows[0]["reason"] != "处理举报 T-1" || rows[0]["result"] != "success" {
		t.Errorf("audit = %v", rows)
	}
	for _, u := range []*user{a2, aud} {
		if !hasNotice(w.notifications(u), "account.emergency_grant", "adm1") {
			t.Errorf("%s not notified", u.name)
		}
	}
	if hasNotice(w.notifications(a1), "account.emergency_grant", "adm1") {
		t.Error("grantee should not be notified")
	}
	w.advance(29 * time.Minute)
	expect(t, "keep alive", a1.do("GET", pathSession, nil), 200, 0)
	w.advance(2 * time.Minute)
	if r := a1.do("GET", pathSession, nil); strings.Contains(fmt.Sprint(r.body["perms"]), "user.kick") {
		t.Errorf("expired grant still applies: %v", r.body["perms"])
	}
}

// AC-CON-07-1、07-2（窗口）、07-5。
func TestCON07StepUp(t *testing.T) {
	w := newWorld(t, nil)
	a1 := w.super("adm1")
	kf := a1.create("kf1", "support")
	w.advance(10 * time.Minute)
	a1.do("GET", pathSession, nil)
	acct := "/console/api/accounts/" + kf.id
	expect(t, "never verified", a1.do("POST", acct+"/unlock", map[string]any{}), 403, 4038)
	a1.stepUp()
	w.advance(4 * time.Minute)
	expect(t, "T+4", a1.do("POST", acct+"/unlock", map[string]any{}), 200, 0)
	w.advance(2*time.Minute + time.Second)
	expect(t, "T+6", a1.do("POST", acct+"/unlock", map[string]any{}), 403, 4038)

	// 连续 5 次失败：前 4 次 4015，第 5 次后会话 revoked，任意 IP 登录 4291。通知本人和超管。
	kf2 := w.client("kf1")
	kf2.seed = kf.seed
	w.tick()
	expect(t, "login", kf2.login(), 200, 0)
	for i := range 5 {
		expect(t, fmt.Sprint("wrong ", i), kf2.do("POST", "/console/api/auth/step-up", map[string]any{"otp": "000000"}), 401, 4015)
	}
	r := kf2.do("GET", pathSession, nil)
	if r.status != 401 || r.reason() != "revoked" {
		t.Errorf("session: %s", r.raw)
	}
	w.tick()
	other := w.client("kf1")
	other.seed, other.ip = kf.seed, "10.9.9.9"
	expect(t, "login from any ip", other.login(), 429, 4291)
	for _, u := range []*user{kf, a1} {
		if !hasNotice(w.notifications(u), "account.locked", "kf1") {
			t.Errorf("%s not notified", u.name)
		}
	}
	if rows := w.auditRows(`action = 'auth.step_up' AND result = 'failure'`); len(rows) != 5 {
		t.Errorf("step-up failures = %d", len(rows))
	}
}

// AC-CON-08-4（账号写操作部分）、08-9：intent 写失败不执行；result 写失败照常返回。
func TestCON08AuditFailure(t *testing.T) {
	w := newWorld(t, nil)
	a1 := w.super("adm1")
	kf := a1.create("kf1", "support")
	a1.stepUp()
	setFault := func(v string) {
		u := w.client("x")
		expect(t, "fault", u.do("POST", "/console/test/faults", map[string]any{"auditWrite": v}), 200, 0)
	}
	setFault("fail")
	expect(t, "intent fails", a1.do("POST", "/console/api/accounts/"+kf.id+"/disable", map[string]any{}), 503, 5031)
	setFault("ok")
	if r := kf.do("GET", pathSession, nil); r.status != 200 {
		t.Errorf("account was disabled anyway: %s", r.raw)
	}
	setFault("failResult")
	expect(t, "result fails", a1.do("POST", "/console/api/accounts/"+kf.id+"/disable", map[string]any{}), 200, 0)
	setFault("ok")
	if r := kf.do("GET", pathSession, nil); r.status != 401 {
		t.Errorf("should be disabled: %s", r.raw)
	}
	// 第一次 intent 就失败，没有记录；第二次只有 intent，result 写失败。
	rows := w.auditRows(`action = 'account.disable'`)
	if len(rows) != 1 || rows[0]["phase"] != "intent" {
		t.Errorf("rows = %v", rows)
	}
	if !strings.Contains(w.logs.String(), "audit result write failed") {
		t.Error("result failure must be logged")
	}
}

// AC-CON-08-8：并发写：seq 连续，链完整。
func TestCON08ChainConcurrent(t *testing.T) {
	w := newWorld(t, nil)
	second, err := newAppSameDB(w)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 2 {
		for range 10 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := range 10 {
					c := w.client(fmt.Sprintf("ghost%d", j))
					c.ip = fmt.Sprintf("10.8.%d.%d", i, j)
					if i == 1 {
						c.srv = second
					}
					c.do("POST", "/console/api/auth/login", map[string]any{"username": c.name, "password": "x", "otp": "1"})
				}
			}()
		}
	}
	wg.Wait()
	rows := w.auditRows(`true`)
	if len(rows) == 0 {
		t.Fatal("no records")
	}
	for i, r := range rows {
		if r["seq"] != int64(i+1) {
			t.Fatalf("seq %v at %d", r["seq"], i)
		}
	}
	ctx := context.Background()
	c, err := pgx.Connect(ctx, w.owner)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	var broken int
	if err := c.QueryRow(ctx, `SELECT count(*) FROM (SELECT hash, lead(prev_hash) OVER (ORDER BY seq) AS next FROM audit.records) x WHERE next IS NOT NULL AND next <> hash`).Scan(&broken); err != nil || broken != 0 {
		t.Errorf("broken links = %d %v", broken, err)
	}
}

// AC-CON-06-1：未声明权限点的路由在注册时失败（internal/app 的单测）。这里确认运行中的服务没有漏网：未知路由未登录 401，登录后 404。
func TestCON06UnknownRoute(t *testing.T) {
	w := newWorld(t, nil)
	a1 := w.super("adm1")
	expect(t, "anonymous", w.client("x").do("GET", "/console/api/nope", nil), 401, 4014)
	expect(t, "signed in", a1.do("GET", "/console/api/nope", nil), 404, 4040)
}

// AC-CON-11-1：TOTP 种子不在库里。
func TestCON11SeedNotInDatabase(t *testing.T) {
	w := newWorld(t, nil)
	a1 := w.super("adm1")
	b32 := totp.Encode(a1.seed)
	ctx := context.Background()
	c, err := pgx.Connect(ctx, w.owner)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	rows, err := c.Query(ctx, `SELECT table_schema, table_name FROM information_schema.tables WHERE table_schema IN ('auth', 'audit', 'biz') AND table_type = 'BASE TABLE'`)
	if err != nil {
		t.Fatal(err)
	}
	type tbl struct{ s, n string }
	var tables []tbl
	for rows.Next() {
		var x tbl
		if err := rows.Scan(&x.s, &x.n); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, x)
	}
	rows.Close()
	if len(tables) < 8 {
		t.Fatalf("tables = %v", tables)
	}
	for _, x := range tables {
		var n int
		q := fmt.Sprintf(`SELECT count(*) FROM %s.%s t WHERE t::text LIKE '%%' || $1 || '%%' OR t::text LIKE '%%' || $2 || '%%'`, x.s, x.n)
		if err := c.QueryRow(ctx, q, b32, strconv.Quote(string(a1.seed))).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("seed found in %s.%s", x.s, x.n)
		}
	}
}

// AC-CON-11-4：默认参数下 50 个并发登录：同时最多 4 个计算（单测），RSS 增量 ≤ 300MB，排队超过 2 秒的返回 503。
func TestCON11ArgonUnderLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	_, appURL := newDB(t)
	p := start(t, "CON_DATABASE_URL="+appURL, "CON_TEST_MODE=1", "CON_TEST_DISABLE_LOCKOUT=1")
	rss := func() int {
		out, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(p.cmd.Process.Pid)).Output()
		if err != nil {
			t.Fatal(err)
		}
		n, _ := strconv.Atoi(strings.TrimSpace(string(out)))
		return n
	}
	postJSON(t, "http://"+p.admin+"/console/api/auth/login", `{"username":"warmup","password":"x","otp":"1"}`) // 算一次假哈希
	base := rss()
	peak := base
	stop, sampled := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(sampled)
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
				if n := rss(); n > peak {
					peak = n
				}
			}
		}
	}()
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := postJSON(t, "http://"+p.admin+"/console/api/auth/login", fmt.Sprintf(`{"username":"user%d","password":"x","otp":"1"}`, i))
			mu.Lock()
			codes[s]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	close(stop)
	<-sampled
	if d := (peak - base) / 1024; d > 300 {
		t.Errorf("RSS grew by %d MB", d)
	}
	if codes[401]+codes[503] != 50 || codes[401] == 0 {
		t.Errorf("codes = %v", codes)
	}
}

// 过期数据要清理：失败计数按任意账号名和 IP 写入，不清理会被刷爆。
func TestHousekeeping(t *testing.T) {
	w := newWorld(t, nil)
	adm := w.super("adm1")
	failLogin(w, "ghost1", "10.0.5.1")
	w.tick()
	count := func(table string) int {
		var n int
		if err := w.db.QueryRow(context.Background(), `SELECT count(*) FROM auth.`+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if err := w.a.Housekeeping(context.Background()); err != nil {
		t.Fatal(err)
	}
	if count("login_failures") == 0 || count("ip_rate") == 0 {
		t.Fatal("fresh rows must survive")
	}
	sessions := count("sessions")
	w.advance(2 * time.Hour)
	if err := w.a.Housekeeping(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n, m := count("login_failures"), count("ip_rate"); n != 0 || m != 0 {
		t.Errorf("stale rows: failures=%d ip_rate=%d", n, m)
	}
	// 还在锁定中的不能清。
	for range 5 {
		failLogin(w, "ghost2", "10.0.5.2")
	}
	w.advance(14 * time.Minute)
	if err := w.a.Housekeeping(context.Background()); err != nil {
		t.Fatal(err)
	}
	expect(t, "still locked", failLogin(w, "ghost2", "10.0.5.2"), 429, 4291)
	// 过期的会话 12 小时之后清掉；未读通知保留 90 天。
	if err := w.a.Notifier().ToAccount(context.Background(), w.db, adm.id, "admin", "account.locked", map[string]any{"who": "x"}); err != nil {
		t.Fatal(err)
	}
	w.advance(25 * time.Hour)
	if err := w.a.Housekeeping(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := count("sessions"); n >= sessions {
		t.Errorf("sessions = %d, was %d", n, sessions)
	}
	if count("notifications") == 0 {
		t.Error("notification removed too early")
	}
	w.advance(91 * 24 * time.Hour)
	if err := w.a.Housekeeping(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := count("notifications"); n != 0 {
		t.Errorf("notifications = %d", n)
	}
}
