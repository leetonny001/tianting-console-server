package e2e

// CS-200：邀请码接口和用户详情的账号信息（PRD-chat F-ACC-09、第 14.1 节）。
// 对真实的 im-server（SQLite）和真实的 Postgres，调用方只有主凭证的 scope，没有测试专用的 token.issue。

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"tianting/console/internal/clock"
	"tianting/console/internal/imclient"
)

const (
	invitesURL  = "/console/api/invites"
	accountPass = "Tt-pass-2026!"
)

// inviteBody 的到期时间按真实时钟：im-server 没有被冻结，[C 钟] 在 2027 年。
func inviteBody(count, maxUses int) map[string]any {
	return map[string]any{"count": count, "maxUses": maxUses, "expiresAt": time.Now().Add(24 * time.Hour).UnixMilli(), "note": "n"}
}

type inviteJSON struct {
	ID         string `json:"inviteId"`
	Code       string `json:"code"`
	Last4      string `json:"codeLast4"`
	MaxUses    int    `json:"maxUses"`
	UsedCount  int    `json:"usedCount"`
	DisabledAt int64  `json:"disabledAt"`
	CreatedBy  string `json:"createdBy"`
}

func invitesOf(t *testing.T, r reply) []inviteJSON {
	t.Helper()
	var out struct {
		Invites []inviteJSON `json:"invites"`
	}
	if err := json.Unmarshal([]byte(r.raw), &out); err != nil {
		t.Fatalf("%s: %v", r.raw, err)
	}
	return out.Invites
}

func firstInvite(t *testing.T, r reply) inviteJSON {
	t.Helper()
	list := invitesOf(t, r)
	if r.status != 200 || len(list) == 0 {
		t.Fatalf("no invite: %d %s", r.status, r.raw)
	}
	return list[0]
}

// inviteWorld 是 console + 真实 im-server（invite 模式），调用方的 scope 和生产的主凭证完全一样。
type inviteWorld struct {
	*bizWorld
	proc   *imProc
	nextIP atomic.Int64
}

func newInviteWorld(t *testing.T, scopes ...string) *inviteWorld {
	t.Helper()
	if len(scopes) == 0 {
		scopes = mainCredentialScopes
	}
	p := startIMProc(t, scopes, "IM_REGISTER_MODE=invite", "IM_TRUSTED_PROXIES=127.0.0.1/32,::1/128")
	return &inviteWorld{bizWorld: newBizWorldWith(t, p.admin, p.ws, p.key), proc: p}
}

// realClock 让 [C 钟] 从"比真实时间早 lead"开始：对账按 intent 的时间查 im-server 的审计（前后 1 分钟）。
// 要在登录之前调用；lead 抵消建账号时 TOTP 步长把钟往前推的那部分（审计的时间只增不减，不能事后往回拨）。
func (w *inviteWorld) realClock(lead time.Duration) {
	w.now = time.Now().Add(-lead)
	w.a.Clock.Freeze(w.now)
}

// imPost 走客户端端口，每次一个来源 IP，不碰注册限流。
func (w *inviteWorld) imPost(path, bearer string, body any) (int, map[string]any, string) {
	w.t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, "http://"+w.proc.ws+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	n := w.nextIP.Add(1)
	req.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.%d.%d", 100+n/250, 1+n%250))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return resp.StatusCode, m, string(b)
}

func (w *inviteWorld) register(username, code string) (int, map[string]any, string) {
	w.t.Helper()
	return w.imPost("/v1/account/register", "", map[string]any{"username": username, "password": accountPass, "platform": "android", "inviteCode": code})
}

// imAuditDump 是 im-server 审计的全文（console 的 requestId 也在里面）。
func (w *inviteWorld) imAuditDump() string {
	w.t.Helper()
	now := time.Now().UnixMilli()
	var raw json.RawMessage
	q := url.Values{"from": {fmt.Sprint(now - 3_600_000)}, "to": {fmt.Sprint(now + 60_000)}, "limit": {"200"}}
	if err := w.sys.Do(context.Background(), imclient.Call{Operator: "test", RequestID: "dump-" + uniq("a")}, "GET", "/admin/audit", q, nil, &raw); err != nil {
		w.t.Fatal(err)
	}
	return string(raw)
}

// imFiles 是 im-server 数据库文件（含 WAL）的全部字节。
func (w *inviteWorld) imFiles() string {
	w.t.Helper()
	paths, _ := filepath.Glob(filepath.Join(w.proc.dir, "im.db*"))
	if len(paths) == 0 {
		w.t.Fatal("no im-server database files")
	}
	var b bytes.Buffer
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			w.t.Fatal(err)
		}
		b.Write(data)
	}
	return b.String()
}

// dumpDB 是 console 库里所有表（审计、业务、账号）的全文。
func (w *world) dumpDB() string {
	w.t.Helper()
	ctx := context.Background()
	c, err := pgx.Connect(ctx, w.owner)
	if err != nil {
		w.t.Fatal(err)
	}
	defer c.Close(ctx)
	rows, err := c.Query(ctx, `SELECT quote_ident(table_schema) || '.' || quote_ident(table_name) FROM information_schema.tables
		WHERE table_type = 'BASE TABLE' AND table_schema NOT IN ('pg_catalog', 'information_schema')`)
	if err != nil {
		w.t.Fatal(err)
	}
	tables, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		w.t.Fatal(err)
	}
	if !slices.Contains(tables, "audit.records") {
		w.t.Fatalf("tables = %v", tables)
	}
	var b strings.Builder
	for _, tbl := range tables {
		rows, err := c.Query(ctx, `SELECT t::text FROM `+tbl+` t`)
		if err != nil {
			w.t.Fatal(err)
		}
		lines, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			w.t.Fatal(err)
		}
		b.WriteString(strings.Join(lines, "\n"))
	}
	return b.String()
}

func noneContains(t *testing.T, label, haystack string, needles map[string]string) {
	t.Helper()
	for name, n := range needles {
		if n == "" {
			t.Fatalf("empty marker %s", name)
		}
		if strings.Contains(haystack, n) {
			t.Errorf("%s contains %s", label, name)
		}
	}
}

// TC-ACC-09-01（AC-ACC-09-1 的后端部分，页面随 FE-619）：运营经 console 生成 maxUses=2，三个用户注册，前两个成功，第三个 403；列表已用 2 次、只有后 4 位。
func TestTC_ACC_09_01_ConsoleInvite(t *testing.T) {
	w := newInviteWorld(t)
	op := w.super("adm1").create("op1", "operator")
	r := op.do("POST", invitesURL, inviteBody(1, 2))
	expect(t, "create", r, 200, 0)
	inv := firstInvite(t, r)
	if r.header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", r.header.Get("Cache-Control"))
	}
	raw, err := base64.RawURLEncoding.DecodeString(inv.Code)
	if err != nil || len(raw) < 16 {
		t.Errorf("code is not 128 bits: %d %v", len(raw), err)
	}
	if inv.Last4 != inv.Code[len(inv.Code)-4:] || inv.MaxUses != 2 || inv.UsedCount != 0 {
		t.Errorf("%+v", inv)
	}
	for _, name := range []string{"reg_user1", "reg_user2"} {
		if c, _, b := w.register(name, inv.Code); c != 200 {
			t.Fatalf("%s: %d %s", name, c, b)
		}
	}
	if c, m, b := w.register("reg_user3", inv.Code); c != 403 || m["code"] != float64(4030) || m["reason"] != "inviteInvalid" {
		t.Errorf("third: %d %s", c, b)
	}
	l := op.do("GET", invitesURL, nil)
	expect(t, "list", l, 200, 0)
	got := firstInvite(t, l)
	if got.ID != inv.ID || got.UsedCount != 2 || got.Last4 != inv.Last4 || got.Code != "" {
		t.Errorf("list = %s", l.raw)
	}
	if strings.Contains(l.raw, inv.Code) {
		t.Error("the plaintext is in the list")
	}
	if !strings.HasPrefix(got.CreatedBy, "console:admin:") {
		t.Errorf("createdBy = %q", got.CreatedBy)
	}
}

// 列表分页：cursor 不校验就不转发；满一页才有 nextCursor；im-server 多返回的字段（例如 code）不透传。
func TestInviteListPaging(t *testing.T) {
	w := newInviteWorld(t)
	op := w.super("adm1").create("op1", "operator")
	if e := op.do("GET", invitesURL, nil); e.status != 200 || e.raw != "{\"invites\":[]}\n" {
		t.Errorf("empty = %d %q", e.status, e.raw)
	}
	expect(t, "create", op.do("POST", invitesURL, inviteBody(25, 1)), 200, 0)
	p1 := op.do("GET", invitesURL+"?limit=20", nil)
	first := invitesOf(t, p1)
	if len(first) != 20 || p1.str("nextCursor") != first[19].ID {
		t.Fatalf("page 1: %d %s", len(first), p1.str("nextCursor"))
	}
	p2 := op.do("GET", invitesURL+"?limit=20&cursor="+p1.str("nextCursor"), nil)
	second := invitesOf(t, p2)
	if len(second) != 5 || p2.str("nextCursor") != "" {
		t.Fatalf("page 2: %d %q", len(second), p2.str("nextCursor"))
	}
	if slices.ContainsFunc(second, func(i inviteJSON) bool { return i.ID == first[0].ID }) {
		t.Error("pages overlap")
	}
	expect(t, "bad limit", op.do("GET", invitesURL+"?limit=7", nil), 400, 4000)
	expect(t, "bad cursor", op.do("GET", invitesURL+"?cursor=a%20b", nil), 400, 4004)

	w.im.mu.Lock()
	w.im.rewrite = func(path string, body []byte) []byte {
		if path != "/admin/invites" {
			return body
		}
		return bytes.ReplaceAll(body, []byte(`"inviteId"`), []byte(`"code":"ZXQLEAKED","codeHash":"ZXQHASH","inviteId"`))
	}
	w.im.mu.Unlock()
	if l := op.do("GET", invitesURL, nil); l.status != 200 || strings.Contains(l.raw, "ZXQ") || strings.Contains(l.raw, "codeHash") {
		t.Errorf("list forwards extra fields: %s", l.raw)
	}
}

// TC-ACC-09-02（AC-ACC-09-2）：明文只在生成响应里。console 全库（审计在内）、两边日志、im-server 库文件和审计都搜不到。
func TestTC_ACC_09_02_NoPlaintext(t *testing.T) {
	w := newInviteWorld(t)
	op := w.super("adm1").create("op1", "operator")
	r := op.do("POST", invitesURL, inviteBody(3, 1))
	expect(t, "create", r, 200, 0)
	list := invitesOf(t, r)
	if len(list) != 3 {
		t.Fatal(r.raw)
	}
	expect(t, "disable", op.do("POST", invitesURL+"/"+list[0].ID+"/disable", map[string]any{}), 200, 0)
	l := op.do("GET", invitesURL, nil)
	if c, _, b := w.register("np_user1", list[1].Code); c != 200 {
		t.Fatal(b)
	}
	if c, _, _ := w.register("np_user2", list[0].Code); c != 403 {
		t.Errorf("disabled: %d", c)
	}
	dump, logs, im := w.dumpDB(), w.logs.String(), w.proc.logs.String()
	files, imAudit := w.imFiles(), w.imAuditDump()
	if !strings.Contains(dump, "invite.create") || !strings.Contains(imAudit, "/admin/invites") || !strings.Contains(files, list[0].Last4) {
		t.Fatal("the scan looked at the wrong data")
	}
	for i, inv := range list {
		needle := map[string]string{fmt.Sprintf("plaintext #%d", i): inv.Code}
		noneContains(t, "console database", dump, needle)
		noneContains(t, "console log", logs, needle)
		noneContains(t, "im-server log", im, needle)
		noneContains(t, "im-server database files", files, needle)
		noneContains(t, "im-server audit", imAudit, needle)
		noneContains(t, "list response", l.raw, needle)
		// 审计也不记后 4 位和备注：只记数量和 inviteId。
		for _, row := range w.auditRows(`action LIKE 'invite.%'`) {
			if strings.Contains(fmt.Sprint(row["params"])+fmt.Sprint(row["target"]), `"`+inv.Last4+`"`) {
				t.Errorf("last 4 in audit: %v", row)
			}
		}
	}
	intent := w.auditRows(`action = 'invite.create' AND phase = 'intent'`)
	res := w.auditRows(`action = 'invite.create' AND phase = 'result' AND result = 'success'`)
	if len(intent) != 1 || len(res) != 1 || intent[0]["request_id"] != res[0]["request_id"] {
		t.Fatalf("audit: %v %v", intent, res)
	}
	if p := fmt.Sprint(intent[0]["params"]); !strings.Contains(p, `"count":3`) || !strings.Contains(p, `"maxUses":1`) || !strings.Contains(p, `"hasNote":true`) || strings.Contains(p, `"note"`) {
		t.Errorf("intent params = %s", p)
	}
	if p := fmt.Sprint(res[0]["params"]); !strings.Contains(p, `"count":3`) || !strings.Contains(p, list[2].ID) {
		t.Errorf("result params = %s", p)
	}
}

// TC-ACC-09-03（AC-ACC-09-5）：经 console 停用立即生效，重复停用幂等；没有的邀请码 404 / 4040，不说成"接口没上线"。
func TestTC_ACC_09_03_Disable(t *testing.T) {
	w := newInviteWorld(t)
	op := w.super("adm1").create("op1", "operator")
	inv := firstInvite(t, op.do("POST", invitesURL, inviteBody(1, 5)))
	path := invitesURL + "/" + inv.ID + "/disable"
	expect(t, "disable", op.do("POST", path, map[string]any{}), 200, 0)
	expect(t, "again", op.do("POST", path, map[string]any{}), 200, 0)
	if c, m, b := w.register("dis_user1", inv.Code); c != 403 || m["code"] != float64(4030) || m["reason"] != "inviteInvalid" {
		t.Errorf("disabled: %d %s", c, b)
	}
	if got := firstInvite(t, op.do("GET", invitesURL, nil)); got.DisabledAt == 0 || got.UsedCount != 0 {
		t.Errorf("%+v", got)
	}
	r := op.do("POST", invitesURL+"/nope/disable", map[string]any{})
	expect(t, "missing", r, 404, 4040)
	if r.reason() != "" {
		t.Errorf("reason = %q", r.reason())
	}
	expect(t, "bad id", op.do("POST", invitesURL+"/a%20b/disable", map[string]any{}), 400, 4004)
	rows := w.auditRows(`action = 'invite.disable' AND phase = 'result' AND target LIKE $1`, "%"+inv.ID+"%")
	if len(rows) != 2 || rows[0]["result"] != "success" {
		t.Errorf("audit = %v", rows)
	}
	// 404 是真实失败，不是越权（account. 开头的动作才记 denied）。
	if rows := w.auditRows(`action = 'invite.disable' AND phase = 'result' AND target LIKE '%nope%'`); len(rows) != 1 || rows[0]["result"] != "failure" || rows[0]["code"] != int32(4040) {
		t.Errorf("audit missing = %v", rows)
	}
}

// TC-ACC-09-04（AC-ACC-09-6）：只有 operator 成功。其他角色三个路由都 403 / 4030，不调用 im-server，写 denied 审计。
func TestTC_ACC_09_04_Roles(t *testing.T) {
	w := newInviteWorld(t)
	super := w.super("adm1")
	op := super.create("op1", "operator")
	denied := map[string]*user{"support": super.create("kf1", "support"), "auditor": super.create("aud1", "auditor"), "moderator": super.create("mod1", "moderator"), "super_admin": super}
	inv := firstInvite(t, op.do("POST", invitesURL, inviteBody(1, 1)))
	calls := func() int {
		return w.im.count("POST", "/admin/invites") + w.im.count("GET", "/admin/invites") + w.im.count("POST", "/admin/invites/"+inv.ID+"/disable")
	}
	before := calls()
	for role, c := range denied {
		expect(t, role+" create", c.do("POST", invitesURL, inviteBody(1, 1)), 403, 4030)
		expect(t, role+" list", c.do("GET", invitesURL, nil), 403, 4030)
		expect(t, role+" disable", c.do("POST", invitesURL+"/"+inv.ID+"/disable", map[string]any{}), 403, 4030)
		if rows := w.auditRows(`action = 'invite.create' AND result = 'denied' AND username = $1`, c.name); len(rows) != 1 {
			t.Errorf("%s: denied audit = %v", role, rows)
		}
		if rows := w.auditRows(`action = 'invite.disable' AND result = 'denied' AND username = $1`, c.name); len(rows) != 1 {
			t.Errorf("%s: denied audit = %v", role, rows)
		}
	}
	if n := calls(); n != before {
		t.Errorf("denied requests reached im-server: %d", n-before)
	}
	expect(t, "anonymous", w.client("nobody").do("POST", invitesURL, inviteBody(1, 1)), 401, 4014)
	expect(t, "no csrf", op.do("POST", invitesURL, inviteBody(1, 1), func(r *http.Request) { r.Header.Del("X-CSRF-Token") }), 403, 4037)
	// 没有调用次数以外的副作用：邀请码还是只有那一个，没被停用。
	if l := invitesOf(t, op.do("GET", invitesURL, nil)); len(l) != 1 || l[0].DisabledAt != 0 {
		t.Errorf("list = %+v", l)
	}
	// 权限点在 session 里：页面靠它决定显示菜单。
	if s := op.do("GET", "/console/api/session", nil); !strings.Contains(s.raw, `"account.invite"`) {
		t.Errorf("session = %s", s.raw)
	}
}

// TC-ACC-09-05（AC-ACC-09-7）：4131、4000 透传；100 个、maxUses=1000 的边界成功。结论进审计。
func TestTC_ACC_09_05_Limits(t *testing.T) {
	w := newInviteWorld(t)
	op := w.super("adm1").create("op1", "operator")
	expect(t, "101", op.do("POST", invitesURL, inviteBody(101, 1)), 400, 4131)
	expect(t, "1001", op.do("POST", invitesURL, inviteBody(1, 1001)), 400, 4000)
	expect(t, "maxUses 0", op.do("POST", invitesURL, inviteBody(1, 0)), 400, 4000)
	expect(t, "expired", op.do("POST", invitesURL, map[string]any{"maxUses": 1, "expiresAt": time.Now().Add(-time.Hour).UnixMilli()}), 400, 4000)
	expect(t, "note", op.do("POST", invitesURL, map[string]any{"maxUses": 1, "expiresAt": time.Now().Add(time.Hour).UnixMilli(), "note": strings.Repeat("x", 201)}), 400, 4000)
	expect(t, "bad JSON", op.do("POST", invitesURL, []byte(`{"maxUses":1.5}`)), 400, 4000)
	if rows := w.auditRows(`action = 'invite.create' AND phase = 'result' AND result = 'failure' AND code = 4131`); len(rows) != 1 {
		t.Errorf("audit 4131 = %v", rows)
	}
	if l := op.do("GET", invitesURL, nil); len(invitesOf(t, l)) != 0 {
		t.Errorf("rejected requests created invites: %s", l.raw)
	}
	r := op.do("POST", invitesURL, inviteBody(100, 1000))
	expect(t, "boundary", r, 200, 0)
	list := invitesOf(t, r)
	seen := map[string]bool{}
	for _, i := range list {
		if len(i.Code) < 22 || seen[i.Code] {
			t.Fatalf("code %q", i.Code)
		}
		seen[i.Code] = true
	}
	if len(list) != 100 || list[0].MaxUses != 1000 {
		t.Errorf("%d %+v", len(list), list[0])
	}
	// 目标和 inviteId 超过 50 个时只记数量和前 50 个（F-CON-08 规则 2）。
	rows := w.auditRows(`action = 'invite.create' AND phase = 'result' AND result = 'success'`)
	var p struct {
		Count     int      `json:"count"`
		InviteIDs []string `json:"inviteIds"`
	}
	if len(rows) != 1 || json.Unmarshal([]byte(rows[0]["params"].(string)), &p) != nil || p.Count != 100 || len(p.InviteIDs) != 50 {
		t.Errorf("result params = %v", rows)
	}
	// 省略 count 就是 1 个（im-server 的默认）。
	if l := invitesOf(t, op.do("POST", invitesURL, map[string]any{"maxUses": 1, "expiresAt": time.Now().Add(time.Hour).UnixMilli()})); len(l) != 1 {
		t.Errorf("default count = %d", len(l))
	}
}

// TC-ACC-09-06（AC-ACC-09-8）：审计写失败 503 / 5031，不调用 im-server，邀请码没有产生；停用同样不执行。
func TestTC_ACC_09_06_AuditFailure(t *testing.T) {
	w := newInviteWorld(t)
	op := w.super("adm1").create("op1", "operator")
	before := w.im.count("POST", "/admin/invites")
	w.a.SetAuditFault("fail")
	r := op.do("POST", invitesURL, inviteBody(1, 1))
	expect(t, "create", r, 503, 5031)
	w.a.SetAuditFault("ok")
	if n := w.im.count("POST", "/admin/invites"); n != before {
		t.Errorf("im-server called %d times", n-before)
	}
	var page struct {
		Invites []map[string]any `json:"invites"`
	}
	if err := w.sysDo("GET", "/admin/invites", nil, &page); err != nil || len(page.Invites) != 0 {
		t.Errorf("invites = %v %v", page.Invites, err)
	}
	if rows := w.auditRows(`action = 'invite.create'`); len(rows) != 0 {
		t.Errorf("audit = %v", rows)
	}

	inv := firstInvite(t, op.do("POST", invitesURL, inviteBody(1, 1)))
	w.a.SetAuditFault("fail")
	expect(t, "disable", op.do("POST", invitesURL+"/"+inv.ID+"/disable", map[string]any{}), 503, 5031)
	w.a.SetAuditFault("ok")
	if w.im.count("POST", "/admin/invites/"+inv.ID+"/disable") != 0 {
		t.Error("disable reached im-server")
	}
	if c, _, b := w.register("af_user1", inv.Code); c != 200 {
		t.Errorf("still usable: %d %s", c, b)
	}
}

// F-CON-08 规则 4 + F-CON-09 规则 4：邀请码是 im-server 的写操作，对账查得到。
// result 写失败：操作已生效、照常回明文；响应丢了：504 / 5040、没有明文，对账补 success；到期也不会写成 localOnly。
func TestInviteReconcile(t *testing.T) {
	w := newInviteWorld(t)
	w.realClock(90 * time.Second) // super、create 一共推进 3 个步长
	op := w.super("adm1").create("op1", "operator")
	if d := w.now.Sub(time.Now()).Abs(); d > 30*time.Second {
		t.Fatalf("[C clock] is %v away from the real clock", d)
	}

	w.a.SetAuditFault("failResult")
	r := op.do("POST", invitesURL, inviteBody(1, 1))
	w.a.SetAuditFault("ok")
	expect(t, "result write failed", r, 200, 0)
	if firstInvite(t, r).Code == "" {
		t.Error("the plaintext must still come back: the invite exists")
	}

	var drop atomic.Bool
	drop.Store(true)
	dropping, err := imclient.New(imclient.Config{BaseURL: w.im.srv.URL, Caller: "console", Key: w.key, Clock: clock.New(), DropResponse: &drop})
	if err != nil {
		t.Fatal(err)
	}
	normal := w.a.IM
	w.a.IM = dropping
	lost := op.do("POST", invitesURL, inviteBody(1, 1))
	w.a.IM = normal
	expect(t, "response lost", lost, 504, 5040)
	if strings.Contains(lost.raw, `"code":"`) || strings.Contains(lost.raw, "invites") {
		t.Errorf("response = %s", lost.raw)
	}
	if rows := w.auditRows(`action = 'invite.create' AND phase = 'result' AND result = 'unknown'`); len(rows) != 1 {
		t.Fatalf("unknown = %v", rows)
	}
	// 没有明文，但邀请码确实生成了：页面要提示去列表停用（FE-619）。
	if l := invitesOf(t, op.do("GET", invitesURL, nil)); len(l) != 2 {
		t.Fatalf("list = %+v", l)
	}

	w.advance(6 * time.Minute)
	if err := w.a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	rows := w.auditRows(`action = 'invite.create' AND phase = 'result' AND params LIKE '%"reconciled"%'`)
	if len(rows) != 2 {
		t.Fatalf("reconciled = %v", rows)
	}
	for _, row := range rows {
		if row["result"] != "success" || strings.Contains(row["params"].(string), "localOnly") {
			t.Errorf("reconcile = %v", row)
		}
	}
}

// 主凭证缺 account.invite：透传 403 / 4030，审计记失败。部署漏配时运营看到的就是这个。
func TestInviteScopeMissing(t *testing.T) {
	w := newInviteWorld(t, slices.DeleteFunc(slices.Clone(mainCredentialScopes), func(s string) bool { return s == "account.invite" })...)
	op := w.super("adm1").create("op1", "operator")
	expect(t, "create", op.do("POST", invitesURL, inviteBody(1, 1)), 403, 4030)
	expect(t, "list", op.do("GET", invitesURL, nil), 403, 4030)
	if rows := w.auditRows(`action = 'invite.create' AND phase = 'result' AND result = 'failure' AND code = 4030`); len(rows) != 1 {
		t.Errorf("audit = %v", rows)
	}
}

var accountFields = []string{"createdAt", "hasAccount", "lastLoginAt", "sessions"}

// TC-ACC-09-11（AC-ACC-09-13）、TC-ACC-09-09 的接口部分（AC-ACC-09-11）、AC-ACC-03-33 的后台响应部分：
// 客服看账号用户：有账号、两个时间、会话数 2；响应没有哈希、令牌、sid。演示用户 hasAccount=false。
func TestTC_ACC_09_11_UserDetail(t *testing.T) {
	w := newInviteWorld(t)
	super := w.super("adm1")
	op := super.create("op1", "operator")
	kf := super.create("kf1", "support")
	aud := super.create("aud1", "auditor")
	inv := firstInvite(t, op.do("POST", invitesURL, inviteBody(1, 1)))
	c, reg, b := w.register("alice_1", inv.Code)
	if c != 200 {
		t.Fatal(b)
	}
	if c, _, b := w.imPost("/v1/account/login", "", map[string]any{"username": "alice_1", "password": accountPass, "platform": "ios"}); c != 200 {
		t.Fatal(b)
	}
	refresh, _ := reg["refreshToken"].(string)
	parts := strings.Split(refresh, ".")
	if len(parts) != 5 {
		t.Fatalf("refresh token has %d parts", len(parts))
	}
	userID, _ := reg["userId"].(string)

	r := kf.do("GET", "/console/api/users/"+userID, nil)
	expect(t, "support", r, 200, 0)
	acct, _ := r.body["account"].(map[string]any)
	if acct == nil || acct["hasAccount"] != true || acct["sessions"] != float64(2) || acct["createdAt"] == nil || acct["lastLoginAt"] == nil {
		t.Fatalf("account = %s", r.raw)
	}
	keys := make([]string, 0, len(acct))
	for k := range acct {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, accountFields) {
		t.Errorf("account fields = %v", keys)
	}
	if r.body["userId"] != userID || r.body["accountUnavailable"] != nil {
		t.Errorf("profile = %s", r.raw)
	}
	lower := strings.ToLower(r.raw)
	for _, bad := range []string{"hash", "token", "sid", "password", "recovery", strings.ToLower(parts[1])} {
		if strings.Contains(lower, bad) {
			t.Errorf("response contains %q: %s", bad, r.raw)
		}
	}
	noneContains(t, "console log", w.logs.String(), map[string]string{"sid": parts[1]})
	noneContains(t, "im-server log", w.proc.logs.String(), map[string]string{"sid": parts[1]})

	w.users("demo_1")
	d := kf.do("GET", "/console/api/users/demo_1", nil)
	expect(t, "demo", d, 200, 0)
	if a, _ := d.body["account"].(map[string]any); a == nil || a["hasAccount"] != false || a["sessions"] != float64(0) || a["createdAt"] != nil || a["lastLoginAt"] != nil {
		t.Errorf("demo = %s", d.raw)
	}

	// 权限沿用 user.read。
	expect(t, "auditor", aud.do("GET", "/console/api/users/"+userID, nil), 403, 4030)
	expect(t, "operator", op.do("GET", "/console/api/users/"+userID, nil), 200, 0)
	expect(t, "super", super.do("GET", "/console/api/users/"+userID, nil), 200, 0)
	expect(t, "missing", kf.do("GET", "/console/api/users/ghost_1", nil), 404, 4042)
	// 只读，不写审计（F-CON-08 规则 1）。
	if rows := w.auditRows(`target LIKE $1 AND username = 'kf1'`, "%"+userID+"%"); len(rows) != 0 {
		t.Errorf("audit = %v", rows)
	}

	// im-server 多返回字段（令牌、哈希、将来的字段）也出不去。
	w.im.mu.Lock()
	w.im.rewrite = func(path string, body []byte) []byte {
		if !strings.HasPrefix(path, "/admin/accounts/") {
			return body
		}
		return bytes.Replace(body, []byte(`{`), []byte(`{"refreshToken":"ZXQRT","accessToken":"ZXQAT","passwordHash":"ZXQPH","sid":"ZXQSID","deleteRequestedAt":7,`), 1)
	}
	w.im.mu.Unlock()
	leak := kf.do("GET", "/console/api/users/"+userID, nil)
	if leak.status != 200 || strings.Contains(leak.raw, "ZXQ") || strings.Contains(leak.raw, "deleteRequestedAt") {
		t.Errorf("extra fields forwarded: %s", leak.raw)
	}
	w.im.mu.Lock()
	w.im.rewrite = nil
	w.im.inject = func(c imCall) int {
		if strings.HasPrefix(c.Path, "/admin/accounts/") {
			return 5000
		}
		return 0
	}
	w.im.mu.Unlock()

	// 账号信息取不到：详情照常，明确标"不可用"，不能说成没有账号；日志不带 userId。
	before := len(w.logs.String())
	down := kf.do("GET", "/console/api/users/"+userID, nil)
	expect(t, "account read failed", down, 200, 0)
	if down.body["accountUnavailable"] != true || down.body["account"] != nil || strings.Contains(down.raw, "hasAccount") || down.body["userId"] != userID {
		t.Errorf("degraded = %s", down.raw)
	}
	added := w.logs.String()[before:]
	if !strings.Contains(added, "account info unavailable") || strings.Contains(added, userID) {
		t.Errorf("log = %s", added)
	}
}

var credentialWords = regexp.MustCompile(`(?i)password|recovery|reset`)

// TC-ACC-05-08（AC-ACC-05-9，console 部分，路由和源码的枚举在 internal/app/route_test.go）：
// 主凭证的 scope 就是 PRD 那些；用它走完全部账号相关请求，没有一次调用碰到改密码、改恢复码的路径。
func TestTC_ACC_05_08_ConsoleScopeAndCalls(t *testing.T) {
	for _, s := range mainCredentialScopes {
		if credentialWords.MatchString(s) {
			t.Errorf("scope %s", s)
		}
		// 永远不含这些（F-KEY-02 规则 4）；C6 的词库、举报 scope 在主凭证上，证据（正文类）只在 console-msgread（AC-MOD-04-4、04-8）。
		if s == "token.issue" || s == "test" || strings.HasPrefix(s, "msg.body") || s == "msg.quarantine" || s == "report.evidence" {
			t.Errorf("scope %s must not be on the main credential", s)
		}
	}
	// 部署示例和这份一致。没有 tianting-server 时跳过这一步（CI 上是私有仓库）。
	src := os.Getenv("TIANTING_SERVER_DIR")
	if src == "" {
		src = "../../im-mvp/server"
	}
	if raw, err := os.ReadFile(filepath.Join(src, "..", "deploy", "im-admin-callers.example.json")); err == nil {
		var callers []struct {
			ID     string   `json:"id"`
			Scopes []string `json:"scopes"`
		}
		if err := json.Unmarshal(raw, &callers); err != nil {
			t.Fatal(err)
		}
		i := slices.IndexFunc(callers, func(c struct {
			ID     string   `json:"id"`
			Scopes []string `json:"scopes"`
		}) bool {
			return c.ID == "console"
		})
		if i < 0 {
			t.Fatal("no console caller")
		}
		got, want := slices.Sorted(slices.Values(callers[i].Scopes)), slices.Sorted(slices.Values(mainCredentialScopes))
		if !slices.Equal(got, want) {
			t.Errorf("deploy example scopes = %v, want %v", got, want)
		}
		// C6：证据 scope 只在正文调用方（PRD-chat 第 14.1 节，BE-498 第 2 条）。
		j := slices.IndexFunc(callers, func(c struct {
			ID     string   `json:"id"`
			Scopes []string `json:"scopes"`
		}) bool {
			return c.ID == "console-msgread"
		})
		if j < 0 || !slices.Contains(callers[j].Scopes, "report.evidence") {
			t.Errorf("console-msgread in the deploy example lacks report.evidence: %v", callers)
		}
	} else {
		t.Logf("deploy example not checked: %v", err)
	}

	w := newInviteWorld(t)
	super := w.super("adm1")
	op := super.create("op1", "operator")
	inv := firstInvite(t, op.do("POST", invitesURL, inviteBody(1, 1)))
	if c, _, b := w.register("cred_user1", inv.Code); c != 200 {
		t.Fatal(b)
	}
	expect(t, "disable", op.do("POST", invitesURL+"/"+inv.ID+"/disable", map[string]any{}), 200, 0)
	expect(t, "detail", op.do("GET", "/console/api/users/cred_user1", nil), 200, 0)
	for _, sub := range []string{"password", "reset-password", "recovery-code", "recovery-codes", "reset"} {
		for _, c := range []*user{op, super} {
			expect(t, sub, c.do("POST", "/console/api/users/cred_user1/"+sub, map[string]any{"newPassword": "Other-pass-2026!"}), 404, 4040)
		}
	}
	// 后台账号的重置只认后台账号：拿 im 用户名调用，不会到 im-server。
	expect(t, "account reset", op.do("POST", "/console/api/accounts/cred_user1/reset", map[string]any{}), 403, 4030)
	w.im.mu.Lock()
	defer w.im.mu.Unlock()
	if len(w.im.calls) == 0 {
		t.Fatal("no calls recorded")
	}
	for _, c := range w.im.calls {
		if credentialWords.MatchString(c.Path) {
			t.Errorf("im-server call: %s %s", c.Method, c.Path)
		}
	}
}

// TC-CHAT-90-04（AC-CHAT-90-5，C1 流程，后端 e2e 部分）：走注册、登录、刷新、改密、找回和后台的邀请码、详情，含失败路径；
// 两边日志、console 全库、im-server 审计都搜不到密码、恢复码、邀请码、令牌、deviceName、sid。用 deploy/ops/scan-logs 再扫一次。
func TestTC_CHAT_90_04_NoSecretsInLogsAndAudit(t *testing.T) {
	w := newInviteWorld(t)
	super := w.super("adm1")
	op := super.create("op1", "operator")
	kf := super.create("kf1", "support")
	const (
		pw1    = "ZXQPW-first-2026!"
		pw2    = "ZXQPW-second-2026!"
		pw3    = "ZXQPW-third-2026!"
		device = "ZXQDEV-phone"
		badInv = "ZXQIN-not-a-real-invite"
	)
	markers := map[string]string{"password 1": pw1, "password 2": pw2, "password 3": pw3, "deviceName": device, "bad invite": badInv}
	add := func(name string, m map[string]any, key string) string {
		t.Helper()
		v, _ := m[key].(string)
		if v == "" {
			t.Fatalf("%s: no %s in %v", name, key, m)
		}
		markers[name] = v
		return v
	}
	post := func(label, path, bearer string, body map[string]any, want int) map[string]any {
		t.Helper()
		c, m, b := w.imPost(path, bearer, body)
		if c != want {
			t.Fatalf("%s: %d %s", label, c, b)
		}
		return m
	}

	r := op.do("POST", invitesURL, map[string]any{"maxUses": 1, "expiresAt": time.Now().Add(time.Hour).UnixMilli(), "note": "ZXQ-note-is-not-audited"})
	inv := firstInvite(t, r)
	markers["invite"] = inv.Code
	markers["invite note"] = "ZXQ-note-is-not-audited"

	// 注册（含错误邀请码）。
	post("bad invite", "/v1/account/register", "", map[string]any{"username": "scan_user", "password": pw1, "platform": "android", "deviceName": device, "inviteCode": badInv}, 403)
	reg := post("register", "/v1/account/register", "", map[string]any{"username": "scan_user", "password": pw1, "platform": "android", "deviceName": device, "inviteCode": inv.Code}, 200)
	recovery := add("recovery code", reg, "recoveryCode")
	add("access 1", reg, "accessToken")
	refresh := add("refresh 1", reg, "refreshToken")
	sid := strings.Split(refresh, ".")[1]
	markers["sid"] = sid
	userID := reg["userId"].(string)
	// 登录（含错误密码）。
	post("bad login", "/v1/account/login", "", map[string]any{"username": "scan_user", "password": pw2, "platform": "android", "deviceName": device}, 401)
	login := post("login", "/v1/account/login", "", map[string]any{"username": "scan_user", "password": pw1, "platform": "android", "deviceName": device}, 200)
	add("access 2", login, "accessToken")
	add("refresh 2", login, "refreshToken")
	// 刷新（含错误令牌）。
	post("bad refresh", "/v1/account/token/refresh", "", map[string]any{"refreshToken": "ZXQ.bad.0.x.y"}, 401)
	ref := post("refresh", "/v1/account/token/refresh", "", map[string]any{"refreshToken": refresh}, 200)
	access := add("access 3", ref, "accessToken")
	// 改密（含旧密码错误）。
	post("bad password", "/v1/account/password", access, map[string]any{"oldPassword": pw3, "newPassword": pw2}, 401)
	changed := post("password", "/v1/account/password", access, map[string]any{"oldPassword": pw1, "newPassword": pw2}, 200)
	add("access after password", changed, "accessToken")
	add("refresh after password", changed, "refreshToken")
	recovery = add("recovery code after password", changed, "recoveryCode") // 改密换了恢复码
	// 找回（含错误恢复码）。
	post("bad recover", "/v1/account/recover", "", map[string]any{"username": "scan_user", "recoveryCode": "ZXQR-ZXQR", "newPassword": pw3, "platform": "android", "deviceName": device}, 401)
	rec := post("recover", "/v1/account/recover", "", map[string]any{"username": "scan_user", "recoveryCode": recovery, "newPassword": pw3, "platform": "android", "deviceName": device}, 200)
	add("recovery code 2", rec, "recoveryCode")
	add("access 4", rec, "accessToken")
	add("refresh 3", rec, "refreshToken")

	// 后台：详情、列表、停用，和审计写失败、im-server 报错的路径。
	expect(t, "detail", kf.do("GET", "/console/api/users/"+userID, nil), 200, 0)
	expect(t, "list", op.do("GET", invitesURL, nil), 200, 0)
	expect(t, "limit", op.do("POST", invitesURL, inviteBody(101, 1)), 400, 4131)
	w.a.SetAuditFault("fail")
	expect(t, "audit down", op.do("POST", invitesURL, inviteBody(1, 1)), 503, 5031)
	w.a.SetAuditFault("failResult")
	second := firstInvite(t, op.do("POST", invitesURL, inviteBody(1, 1)))
	markers["invite 2"] = second.Code
	w.a.SetAuditFault("ok")
	expect(t, "disable", op.do("POST", invitesURL+"/"+inv.ID+"/disable", map[string]any{}), 200, 0)

	logs, imLogs := w.logs.String(), w.proc.logs.String()
	if imLogs == "" {
		t.Fatal("the im-server log was not captured")
	}
	dump, imAudit := w.dumpDB(), w.imAuditDump()
	if !strings.Contains(imAudit, "/admin/invites") {
		t.Fatal("im-server audit has no invite calls")
	}
	for label, data := range map[string]string{"console log": logs, "im-server log": imLogs, "console database": dump, "im-server audit": imAudit} {
		noneContains(t, label, data, markers)
	}

	// TC-CHAT-90-04 指定的工具再扫一次。
	src := os.Getenv("TIANTING_SERVER_DIR")
	if src == "" {
		src = "../../im-mvp/server"
	}
	scanner := filepath.Join(src, "..", "deploy", "ops", "scan-logs")
	if _, err := os.Stat(scanner); err != nil {
		t.Logf("scan-logs not available: %v", err)
		return
	}
	dir := t.TempDir()
	files := []string{filepath.Join(dir, "console.log"), filepath.Join(dir, "im.log"), filepath.Join(dir, "console-db.txt"), filepath.Join(dir, "im-audit.txt")}
	for i, data := range []string{logs, imLogs, dump, imAudit} {
		if err := os.WriteFile(files[i], []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"-I", scanner}
	for _, m := range markers {
		args = append(args, "--marker="+m) // 随机值可能以 - 开头，分开写 argparse 会当成选项
	}
	if out, err := exec.Command("python3", append(args, files...)...).CombinedOutput(); err != nil {
		t.Errorf("scan-logs: %v: %s", err, out)
	}
	// 对照：扫描工具确实能发现。
	hit := filepath.Join(dir, "hit.log")
	if err := os.WriteFile(hit, []byte("x "+inv.Code+" y\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("python3", append(args, hit)...).Run(); err == nil {
		t.Error("scan-logs found nothing in a file that has the marker")
	}
}
