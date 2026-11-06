package e2e

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"tianting/console/internal/app"
	"tianting/console/internal/audit"
	"tianting/console/internal/imclient"
)

const goodReason = "工单 T-100 处理"

// 用同一个 im-server 跑全部业务用例：启动一次 2 秒，每个用例各用各的数据。
func TestBusiness(t *testing.T) {
	admin, ws, priv := startRealIMWS(t)
	for name, fn := range map[string]func(*testing.T, *bizWorld){
		"Search": testBizSearch, "Kick": testBizKick, "Sessions": testBizSessions, "Import": testBizImport, "Friends": testBizFriends, "Settings": testBizSettings,
		"Official": testBizOfficial, "Groups": testBizGroups, "Members": testBizMembers, "Dissolve": testBizDissolve, "Owner": testBizOwner, "Meta": testBizMeta, "Audit": testBizAuditFaults, "ImportRace": testBizImportRace,
	} {
		t.Run(name, func(t *testing.T) {
			fn(t, newBizWorldWith(t, admin, ws, priv))
		})
	}
}

func uniq(prefix string) string {
	return fmt.Sprintf("%s%d", prefix, time.Now().UnixNano()%1_000_000_000)
}

// AC-ADM-10-1、10-2、10-3、10-6、10-7。
func testBizSearch(t *testing.T, b *bizWorld) {
	a1 := b.super("adm1")
	kf := a1.create("kf1", "support")
	p := uniq("s")
	b.users(p+"u100", p+"u101", p+"u2", strings.ToUpper(p)+"U100", p+"_1", p+"X1")
	ids := func(r reply) []string {
		var out []string
		for _, it := range r.body["users"].([]any) {
			out = append(out, it.(map[string]any)["userId"].(string))
		}
		return out
	}
	r := kf.do("GET", "/console/api/users?q="+p+"u10&limit=20", nil)
	expect(t, "search", r, 200, 0)
	if got := ids(r); len(got) != 2 || got[0] != p+"u100" || got[1] != p+"u101" {
		t.Errorf("prefix = %v", got)
	}
	r = kf.do("GET", "/console/api/users?q="+p+"_", nil)
	if got := ids(r); len(got) != 1 || got[0] != p+"_1" {
		t.Errorf("underscore = %v", got)
	}
	// 昵称。
	n := uniq("N")
	b.users(p+"a="+n+"小明", p+"b="+n+"小明明", p+"c="+n+"Tom", p+"d="+n+"tommy")
	r = kf.do("GET", "/console/api/users?q="+n+"小明", nil)
	if got := ids(r); len(got) != 2 {
		t.Errorf("nickname = %v", got)
	}
	// 关键字和 limit 校验不调用 im-server。
	before := b.im.count("GET", "/admin/users")
	expect(t, "blank", kf.do("GET", "/console/api/users?q=%20%20", nil), 400, 4000)
	expect(t, "long", kf.do("GET", "/console/api/users?q="+strings.Repeat("x", 65), nil), 400, 4000)
	expect(t, "limit", kf.do("GET", "/console/api/users?q=a&limit=30", nil), 400, 4000)
	expect(t, "nothing", kf.do("GET", "/console/api/users", nil), 400, 4000)
	if b.im.count("GET", "/admin/users") != before {
		t.Error("invalid search reached im-server")
	}
	// 官方筛选（AC-ADM-10-6）。
	op := a1.create("op1", "operator")
	off := uniq("kefu")
	b.users(off)
	expect(t, "official", op.do("PUT", "/console/api/users/"+off+"/official", map[string]any{"official": true, "reason": goodReason}), 200, 0)
	r = kf.do("GET", "/console/api/users?official=true&limit=100", nil)
	if got := fmt.Sprint(ids(r)); !strings.Contains(got, off) || strings.Contains(got, p) {
		t.Errorf("official = %v", got)
	}
	// 1000 个翻 10 页（AC-ADM-10-7）。
	q := uniq("p")
	b.users(numbered(q, 1000)...)
	seen := map[string]bool{}
	cursor := ""
	for page := range 11 {
		r := kf.do("GET", "/console/api/users?q="+q+"&limit=100"+cursor, nil)
		expect(t, "page", r, 200, 0)
		for _, id := range ids(r) {
			if seen[id] {
				t.Errorf("duplicate %s", id)
			}
			seen[id] = true
		}
		next := r.str("nextCursor")
		if next == "" {
			if page != 9 {
				t.Errorf("pages = %d", page+1)
			}
			break
		}
		cursor = "&cursor=" + next
	}
	if len(seen) != 1000 {
		t.Errorf("seen = %d", len(seen))
	}
	// 列表不写审计。
	if rows := b.auditRows(`username = 'kf1' AND action LIKE 'user.%'`); len(rows) != 0 {
		t.Errorf("list audited: %v", rows)
	}
}

// AC-ADM-10-4、12-1～12-4、AC-CON-08-1、08-2。
func testBizKick(t *testing.T, b *bizWorld) {
	a1 := b.super("adm1")
	kf := a1.create("kf1", "support")
	op := a1.create("op1", "operator")
	u := uniq("u")
	b.users(u)
	c1, c2 := b.dial(u, "web"), b.dial(u, "pc")
	r := kf.do("GET", "/console/api/users/"+u, nil)
	if r.body["online"] != true {
		t.Errorf("online = %s", r.raw)
	}
	// 没有理由：不踢（AC-ADM-12-4）。
	for _, bad := range []map[string]any{{}, {"reason": "abc"}, {"reason": "aaaa"}, {"reason": "   ab  "}, {"reason": strings.Repeat("长", 201)}} {
		r := kf.do("POST", "/console/api/users/"+u+"/kick", bad)
		expect(t, "bad reason", r, 400, 4000)
		if r.reason() != "reasonInvalid" {
			t.Errorf("reason = %s", r.raw)
		}
	}
	if n := b.im.count("POST", "/admin/users/"+u+"/force-logout"); n != 0 {
		t.Errorf("kicked without a reason: %d", n)
	}
	expect(t, "operator", op.do("POST", "/console/api/users/"+u+"/kick", map[string]any{"reason": goodReason}), 403, 4030)
	expect(t, "kick", kf.do("POST", "/console/api/users/"+u+"/kick", map[string]any{"reason": goodReason, "ticket": "T-100"}), 200, 0)
	for _, c := range []*wsClient{c1, c2} {
		f := c.wait("kicked")
		if f["data"].(map[string]any)["reason"] != "banned" {
			t.Errorf("kicked = %v", f)
		}
		if code := c.closed(); code != 4012 {
			t.Errorf("close = %d", code)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if r := kf.do("GET", "/console/api/users/"+u, nil); r.body["online"] != false {
		t.Errorf("after kick = %s", r.raw)
	}
	// 重新签发后能连（AC-ADM-12-2）。
	b.dial(u, "web")
	// 审计 intent + result（AC-CON-08-1）。
	rows := b.auditRows(`action = 'user.kick' AND target LIKE '%' || $1 || '%'`, u)
	if len(rows) != 2 || rows[0]["phase"] != "intent" || rows[1]["phase"] != "result" || rows[1]["result"] != "success" || rows[0]["request_id"] != rows[1]["request_id"] {
		t.Fatalf("audit = %v", rows)
	}
	for _, r := range rows {
		if r["actor"] != "kf1" || r["reason"] != goodReason || r["ip"] != "10.0.0.1" {
			t.Errorf("audit = %v", r)
		}
	}
	// 用户不存在（AC-ADM-12-3、AC-CON-08-2）。
	r = kf.do("POST", "/console/api/users/nobody-x/kick", map[string]any{"reason": goodReason})
	expect(t, "nobody", r, 404, 4042)
	rows = b.auditRows(`action = 'user.kick' AND phase = 'result' AND target LIKE '%nobody-x%'`)
	if len(rows) != 1 || rows[0]["result"] != "failure" || rows[0]["code"].(int32) != 4042 {
		t.Errorf("nobody audit = %v", rows)
	}
	expect(t, "bad id", kf.do("POST", "/console/api/users/a%20b/kick", map[string]any{"reason": goodReason}), 400, 4004)
}

// AC-ADM-14-1～14-5。
func testBizSessions(t *testing.T, b *bizWorld) {
	a1 := b.super("adm1")
	kf := a1.create("kf1", "support")
	op := a1.create("op1", "operator")
	u := uniq("u")
	b.users(u)
	b.dial(u, "web")
	b.dial(u, "pc")
	const path = "/console/api/users/sessions/query"
	r := kf.do("POST", path, map[string]any{"userId": u})
	expect(t, "no reason", r, 400, 4000)
	if strings.Contains(r.raw, "connId") {
		t.Error("data without reason")
	}
	expect(t, "operator", op.do("POST", path, map[string]any{"userId": u, "reason": goodReason}), 403, 4030)
	r = kf.do("POST", path, map[string]any{"userId": u, "reason": goodReason})
	expect(t, "query", r, 200, 0)
	sessions := r.body["sessions"].([]any)
	if len(sessions) != 2 || r.body["partial"] != true || r.str("scope") != "localNode" {
		t.Errorf("sessions = %s", r.raw)
	}
	rows := b.auditRows(`action = 'user.sessions.query' AND phase = 'result'`)
	if len(rows) != 1 || !strings.Contains(rows[0]["params"].(string), `"count":2`) || rows[0]["reason"] != goodReason {
		t.Errorf("audit = %v", rows)
	}
	// URL 和日志里没有 userId 和理由（AC-ADM-14-5）。
	if s := b.logs.String(); strings.Contains(s, u) || strings.Contains(s, goodReason) {
		t.Errorf("log leak:\n%s", s)
	}
	// 每分钟 30 次。
	for i := range 29 {
		if r := kf.do("POST", path, map[string]any{"userId": u, "reason": goodReason}); r.status != 200 {
			t.Fatalf("query %d: %s", i, r.raw)
		}
	}
	expect(t, "31st in a minute", kf.do("POST", path, map[string]any{"userId": u, "reason": goodReason}), 429, 4290)
	// 每天 50 个不同 userId；查过的不计。第 51 个 429，无数据。
	others := numbered(uniq("q"), 50)
	b.users(others...)
	for i, id := range others[:49] {
		if i%25 == 0 {
			b.advance(time.Minute)
		}
		if r := kf.do("POST", path, map[string]any{"userId": id, "reason": goodReason}); r.status != 200 {
			t.Fatalf("query %s: %s", id, r.raw)
		}
	}
	b.advance(time.Minute)
	r = kf.do("POST", path, map[string]any{"userId": others[49], "reason": goodReason})
	expect(t, "51st user", r, 429, 4292)
	if strings.Contains(r.raw, "sessions") {
		t.Error("data over quota")
	}
	expect(t, "already seen", kf.do("POST", path, map[string]any{"userId": u, "reason": goodReason}), 200, 0)
	// 第二天（Asia/Shanghai）重新计数。
	b.advance(24 * time.Hour)
	k2 := kf
	expect(t, "login again", k2.login(), 200, 0)
	expect(t, "next day", k2.do("POST", path, map[string]any{"userId": others[49], "reason": goodReason}), 200, 0)
}

func usersCSV(rows ...string) string {
	return "userId,nickname,avatar\n" + strings.Join(rows, "\n") + "\n"
}

// AC-ADM-11-1～11-5。
func testBizImport(t *testing.T, b *bizWorld) {
	a1 := b.super("adm1")
	op := a1.create("op1", "operator")
	kf := a1.create("kf1", "support")
	const validate, submit = "/console/api/users/import/validate", "/console/api/users/import"
	p := uniq("i")
	var rows []string
	for i := range 1200 {
		rows = append(rows, fmt.Sprintf("%s%d,昵称%d,", p, i, i))
	}
	r := op.upload(validate, usersCSV(rows...), nil)
	expect(t, "validate", r, 200, 0)
	if r.body["valid"] != true || r.body["total"].(float64) != 1200 || len(r.body["preview"].([]any)) != 20 {
		t.Fatalf("validate = %s", r.raw[:300])
	}
	token := r.str("importToken")
	if n := b.im.count("POST", "/admin/users/import"); n != 0 {
		t.Errorf("validate called im-server %d times", n)
	}
	expect(t, "support", kf.do("POST", submit, map[string]any{"importToken": token}), 403, 4030)
	// 别人的 token 不能用。
	op2 := a1.create("op2", "operator")
	expect(t, "other account", op2.do("POST", submit, map[string]any{"importToken": token}), 400, 4000)
	r = op.do("POST", submit, map[string]any{"importToken": token})
	expect(t, "submit", r, 200, 0)
	if r.body["succeededBatches"].(float64) != 3 || r.body["totalBatches"].(float64) != 3 || r.body["failedCode"] != nil {
		t.Errorf("submit = %s", r.raw)
	}
	calls := b.im.find("POST", "/admin/users/import")
	if len(calls) != 3 {
		t.Fatalf("calls = %d", len(calls))
	}
	audits := b.auditRows(`action = 'user.import' AND phase <> 'event'`)
	if len(audits) != 2 || audits[0]["phase"] != "intent" || audits[1]["result"] != "success" {
		t.Errorf("audit = %v", audits)
	}
	for i, c := range calls {
		if c.RequestID != fmt.Sprintf("%s.%d", audits[0]["request_id"], i+1) {
			t.Errorf("batch %d request id = %s", i, c.RequestID)
		}
	}
	if !strings.Contains(audits[0]["params"].(string), `"total":1200`) || !strings.Contains(audits[0]["params"].(string), "fileSha256") {
		t.Errorf("intent params = %v", audits[0]["params"])
	}
	// 只能用一次。
	expect(t, "token reused", op.do("POST", submit, map[string]any{"importToken": token}), 400, 4000)
	if r := kf.do("GET", "/console/api/users/"+p+"1199", nil); r.str("nickname") != "昵称1199" {
		t.Errorf("imported = %s", r.raw)
	}

	// 行错误：列出行号，不调用 im-server（AC-ADM-11-2）。
	var bad []string
	for i := range 40 {
		bad = append(bad, fmt.Sprintf("%sb%d,n,", p, i))
	}
	bad[5] = "has space,n,"
	bad[28] = p + "x," + strings.Repeat("长", 33) + ","
	r = op.upload(validate, usersCSV(bad...), nil)
	expect(t, "bad rows", r, 200, 0)
	errs := r.body["errors"].([]any)
	if r.body["valid"] != false || r.body["importToken"] != nil || len(errs) != 2 {
		t.Fatalf("bad rows = %s", r.raw)
	}
	e0, e1 := errs[0].(map[string]any), errs[1].(map[string]any)
	if e0["line"].(float64) != 7 || e0["code"].(float64) != 4004 || e1["line"].(float64) != 30 || e1["code"].(float64) != 4000 {
		t.Errorf("errors = %v", errs)
	}
	// 5001 行（AC-ADM-11-3）。
	rows = rows[:0]
	for i := range 5001 {
		rows = append(rows, fmt.Sprintf("%sz%d,,", p, i))
	}
	expect(t, "5001", op.upload(validate, usersCSV(rows...), nil), 400, 4131)
	expect(t, "5000", op.upload(validate, usersCSV(rows[:5000]...), nil), 200, 0)
	// 表头、编码。
	expect(t, "bad header", op.upload(validate, "id,name\nu,n\n", nil), 400, 4000)
	expect(t, "not utf8", op.upload(validate, "userId,nickname,avatar\nu,\xff\xfe,\n", nil), 400, 4000)
	// 文件内重复以最后一条为准；单个表单。
	r = op.upload(validate, usersCSV(p+"dup,first,", p+"dup,last,"), nil)
	if r.body["total"].(float64) != 1 || !strings.Contains(r.raw, "last") || strings.Contains(r.raw, "first") {
		t.Errorf("dup = %s", r.raw)
	}
	r = op.do("POST", validate, map[string]any{"userId": p + "one", "nickname": "单个"})
	expect(t, "single", r, 200, 0)
	expect(t, "single submit", op.do("POST", submit, map[string]any{"importToken": r.str("importToken")}), 200, 0)

	// 第 2 批失败：停止，第 3 批不调用（AC-ADM-11-4）。
	rows = rows[:0]
	for i := range 1200 {
		rows = append(rows, fmt.Sprintf("%sf%d,,", p, i))
	}
	r = op.upload(validate, usersCSV(rows...), nil)
	before := b.im.count("POST", "/admin/users/import")
	b.im.mu.Lock()
	b.im.inject = func(c imCall) int {
		if c.Path == "/admin/users/import" && strings.HasSuffix(c.RequestID, ".2") {
			return 5000
		}
		return 0
	}
	b.im.mu.Unlock()
	r = op.do("POST", submit, map[string]any{"importToken": r.str("importToken")})
	b.im.mu.Lock()
	b.im.inject = nil
	b.im.mu.Unlock()
	expect(t, "partial", r, 200, 0)
	if r.body["succeededBatches"].(float64) != 1 || r.body["totalBatches"].(float64) != 3 || r.body["failedCode"].(float64) != 5000 {
		t.Errorf("partial = %s", r.raw)
	}
	if n := b.im.count("POST", "/admin/users/import") - before; n != 2 {
		t.Errorf("calls after failure = %d", n)
	}
	results := b.auditRows(`action = 'user.import' AND phase = 'result'`)
	last := results[len(results)-1]
	if last["result"] != "failure" || last["code"].(int32) != 5000 || !strings.Contains(last["params"].(string), `"succeededBatches":1`) {
		t.Errorf("audit = %v", last)
	}
}

const remarkMark = "ZXQ-REMARK-789"

// AC-ADM-15-1～15-7。
func testBizFriends(t *testing.T, b *bizWorld) {
	a1 := b.super("adm1")
	op := a1.create("op1", "operator")
	kf := a1.create("kf1", "support")
	p := uniq("f")
	alice, bob, carol := p+"alice", p+"bob", p+"carol"
	b.users(alice, bob, carol)
	const validate, submit = "/console/api/friends/import/validate", "/console/api/friends/import"
	csv := fmt.Sprintf("%s,%s,%s,\n%s,%s,,\n", alice, bob, remarkMark, alice, carol)
	r := op.upload(validate, csv, nil)
	expect(t, "validate", r, 200, 0)
	if strings.Contains(r.raw, remarkMark) {
		t.Error("remark in preview")
	}
	token := r.str("importToken")
	// 没 step-up、没理由、文件变了。
	fields := func(reason string) map[string]string {
		return map[string]string{"importToken": token, "reason": reason}
	}
	b.tick()
	b.advance(6 * time.Minute)
	expect(t, "no step-up", op.upload(submit, csv, fields(goodReason)), 403, 4038)
	op.stepUp()
	expect(t, "no reason", op.upload(submit, csv, fields("")), 400, 4000)
	r = op.upload(submit, csv+carol+","+bob+",,\n", fields(goodReason))
	expect(t, "changed file", r, 400, 4000)
	if r.reason() != "fileChanged" {
		t.Errorf("changed = %s", r.raw)
	}
	if n := b.im.count("POST", "/admin/friends/import"); n != 0 {
		t.Errorf("im calls = %d", n)
	}
	r = op.upload(submit, csv, fields(goodReason))
	expect(t, "submit", r, 200, 0)
	if r.body["succeededBatches"].(float64) != 1 {
		t.Errorf("submit = %s", r.raw)
	}
	r = kf.do("GET", "/console/api/users/"+alice+"/friends", nil)
	expect(t, "friends", r, 200, 0)
	list := r.body["friends"].([]any)
	if len(list) != 2 || list[0].(map[string]any)["source"] != "admin" {
		t.Errorf("friends = %s", r.raw)
	}
	if strings.Contains(strings.ToLower(r.raw), "remark") {
		t.Errorf("remark in list: %s", r.raw)
	}
	// 备注只到 im-server（AC-ADM-15-3）。
	if calls := b.im.find("POST", "/admin/friends/import"); len(calls) != 1 || !strings.Contains(calls[0].Body, remarkMark) {
		t.Errorf("remark did not reach im-server: %v", calls)
	}
	if strings.Contains(b.logs.String(), remarkMark) {
		t.Error("remark in logs")
	}
	if rows := b.auditRows(`params LIKE '%' || $1 || '%' OR target LIKE '%' || $1 || '%' OR reason LIKE '%' || $1 || '%'`, remarkMark); len(rows) != 0 {
		t.Errorf("remark in audit: %v", rows)
	}
	var stored int
	if err := b.db.QueryRow(context.Background(), `SELECT count(*) FROM biz.import_jobs WHERE rows LIKE '%' || $1 || '%' OR preview LIKE '%' || $1 || '%'`, remarkMark).Scan(&stored); err != nil || stored != 0 {
		t.Errorf("remark in job table: %d %v", stored, err)
	}
	// a == b（AC-ADM-15-6）。
	r = op.upload(validate, alice+","+alice+"\n", nil)
	if r.body["valid"] != false || !strings.Contains(r.raw, `"code":4000`) {
		t.Errorf("a==b = %s", r.raw)
	}
	// 第 2 批有不存在的用户（AC-ADM-15-2）。
	people := numbered(uniq("g"), 1201)
	b.users(people...)
	ghost := "ghost" + p
	var pairs []string
	for i := range 1200 {
		pairs = append(pairs, people[i]+","+people[i+1])
	}
	pairs[700] = people[700] + "," + ghost
	big := strings.Join(pairs, "\n") + "\n"
	r = op.upload(validate, big, nil)
	expect(t, "big validate", r, 200, 0)
	before := b.im.count("POST", "/admin/friends/import")
	r = op.upload(submit, big, map[string]string{"importToken": r.str("importToken"), "reason": goodReason})
	expect(t, "ghost", r, 200, 0)
	if r.body["succeededBatches"].(float64) != 1 || r.body["totalBatches"].(float64) != 3 || r.body["failedCode"].(float64) != 4042 || !strings.Contains(r.str("failedMsg"), ghost) {
		t.Errorf("ghost = %s", r.raw)
	}
	if n := b.im.count("POST", "/admin/friends/import") - before; n != 2 {
		t.Errorf("calls = %d", n)
	}
	// 删除（AC-ADM-15-5）：两侧都没有；CSV 带备注列不行。
	const dv, ds = "/console/api/friends/delete/validate", "/console/api/friends/delete"
	if r := op.upload(dv, alice+","+bob+",x,y\n", nil); r.body["valid"] != false {
		t.Errorf("delete with remarks = %s", r.raw)
	}
	del := alice + "," + bob + "\n"
	r = op.upload(dv, del, nil)
	expect(t, "delete validate", r, 200, 0)
	expect(t, "delete", op.upload(ds, del, map[string]string{"importToken": r.str("importToken"), "reason": goodReason}), 200, 0)
	r = kf.do("GET", "/console/api/users/"+alice+"/friends", nil)
	if strings.Contains(r.raw, bob) || !strings.Contains(r.raw, carol) {
		t.Errorf("after delete = %s", r.raw)
	}
	if r := kf.do("GET", "/console/api/users/"+bob+"/friends", nil); strings.Contains(r.raw, alice) {
		t.Errorf("other side = %s", r.raw)
	}
	if rows := b.auditRows(`action = 'friend.delete' AND phase = 'result' AND result = 'success' AND reason = $1`, goodReason); len(rows) != 1 {
		t.Errorf("delete audit = %v", rows)
	}
	// 权限。
	expect(t, "support validate", kf.upload(validate, csv, nil), 403, 4030)
	expect(t, "support submit", kf.upload(submit, csv, fields(goodReason)), 403, 4030)
}

// AC-ADM-16-1、16-3～16-5。
func testBizSettings(t *testing.T, b *bizWorld) {
	a1 := b.super("adm1")
	op := a1.create("op1", "operator")
	kf := a1.create("kf1", "support")
	const path = "/console/api/settings/social"
	r := kf.do("GET", path, nil)
	expect(t, "support reads", r, 200, 0)
	mode := r.str("mode")
	next := "friends"
	if mode == "friends" {
		next = "open"
	}
	maxFriends := int(r.body["maxFriends"].(float64))
	expect(t, "support writes", kf.do("PATCH", path, map[string]any{"maxFriends": 10, "reason": goodReason}), 403, 4030)
	b.advance(6 * time.Minute)
	expect(t, "no step-up", op.do("PATCH", path, map[string]any{"maxFriends": 10, "reason": goodReason}), 403, 4038)
	op.stepUp()
	expect(t, "no reason", op.do("PATCH", path, map[string]any{"maxFriends": 10}), 400, 4000)
	// 切换模式要确认。
	r = op.do("PATCH", path, map[string]any{"mode": next, "reason": goodReason})
	expect(t, "no confirm", r, 400, 4000)
	expect(t, "wrong confirm", op.do("PATCH", path, map[string]any{"mode": next, "confirmMode": "friend", "reason": goodReason}), 400, 4000)
	if n := b.im.count("PATCH", "/admin/settings/social"); n != 0 {
		t.Errorf("patch calls = %d", n)
	}
	r = op.do("PATCH", path, map[string]any{"mode": next, "confirmMode": next, "reason": goodReason})
	expect(t, "switch", r, 200, 0)
	if r.str("mode") != next {
		t.Errorf("mode = %s", r.raw)
	}
	rows := b.auditRows(`action = 'social.settings' AND phase = 'intent'`)
	if len(rows) != 1 || !strings.Contains(rows[0]["params"].(string), mode+" → "+next) {
		t.Errorf("audit = %v", rows)
	}
	// 模式没变：confirmMode 不要求；只传改了的字段（AC-ADM-16-5）。
	r = op.do("PATCH", path, map[string]any{"mode": next, "maxFriends": maxFriends + 1, "reason": goodReason})
	expect(t, "only changed", r, 200, 0)
	calls := b.im.find("PATCH", "/admin/settings/social")
	if body := calls[len(calls)-1].Body; body != fmt.Sprintf(`{"maxFriends":%d}`, maxFriends+1) {
		t.Errorf("patch body = %s", body)
	}
	// 没有变化：不调用。
	n := b.im.count("PATCH", "/admin/settings/social")
	expect(t, "no change", op.do("PATCH", path, map[string]any{"maxFriends": maxFriends + 1, "reason": goodReason}), 200, 0)
	if b.im.count("PATCH", "/admin/settings/social") != n {
		t.Error("no-op reached im-server")
	}
	// 非法值（AC-ADM-16-3）：配置不变。
	expect(t, "invalid", op.do("PATCH", path, map[string]any{"strangerMsgLimit": -1, "reason": goodReason}), 400, 4000)
	// 还原，其他用例不受影响。
	expect(t, "restore", op.do("PATCH", path, map[string]any{"mode": mode, "confirmMode": mode, "maxFriends": maxFriends, "reason": goodReason}), 200, 0)
}

// AC-ADM-17-3、17-4，审计（17-1）。
func testBizOfficial(t *testing.T, b *bizWorld) {
	a1 := b.super("adm1")
	op := a1.create("op1", "operator")
	kf := a1.create("kf1", "support")
	u := uniq("k")
	b.users(u)
	path := "/console/api/users/" + u + "/official"
	expect(t, "support", kf.do("PUT", path, map[string]any{"official": true, "reason": goodReason}), 403, 4030)
	expect(t, "no reason", op.do("PUT", path, map[string]any{"official": true}), 400, 4000)
	expect(t, "no value", op.do("PUT", path, map[string]any{"reason": goodReason}), 400, 4000)
	expect(t, "set", op.do("PUT", path, map[string]any{"official": true, "reason": goodReason}), 200, 0)
	if r := kf.do("GET", "/console/api/users/"+u, nil); r.body["official"] != true {
		t.Errorf("official = %s", r.raw)
	}
	if rows := b.auditRows(`action = 'user.official.set' AND phase = 'result' AND result = 'success' AND reason = $1`, goodReason); len(rows) != 1 {
		t.Errorf("audit = %v", rows)
	}
	expect(t, "unset", op.do("PUT", path, map[string]any{"official": false, "reason": goodReason}), 200, 0)
	if rows := b.auditRows(`action = 'user.official.unset' AND phase = 'result'`); len(rows) != 1 {
		t.Errorf("audit = %v", rows)
	}
	expect(t, "nobody", op.do("PUT", "/console/api/users/nobody-y/official", map[string]any{"official": true, "reason": goodReason}), 404, 4042)
}

// AC-ADM-20-1～20-4、21-1～21-5、23-1。
func testBizGroups(t *testing.T, b *bizWorld) {
	a1 := b.super("adm1")
	op := a1.create("op1", "operator")
	kf := a1.create("kf1", "support")
	p := uniq("g")
	members := numbered(p+"m", 3)
	b.users(members...)
	conn := b.dial(members[0], "web")
	create := func(id string, extra map[string]any) reply {
		body := map[string]any{"groupId": id, "name": "活动群", "members": members}
		for k, v := range extra {
			body[k] = v
		}
		return op.do("POST", "/console/api/groups", body)
	}
	expect(t, "create", create(p+"-1", nil), 200, 0)
	if conn.wait("convAdded") == nil {
		t.Error("no convAdded")
	}
	expect(t, "create 2", create(p+"-2", nil), 200, 0)
	expect(t, "other", create(uniq("h"), nil), 200, 0)
	expect(t, "support", func() reply {
		return kf.do("POST", "/console/api/groups", map[string]any{"groupId": p + "-x", "name": "x"})
	}(), 403, 4030)
	r := create(p+"-1", nil)
	expect(t, "exists", r, 409, 4090)
	r = create(p+"-3", map[string]any{"members": []string{members[0], "ghost-z"}})
	expect(t, "ghost", r, 404, 4042)
	if !strings.Contains(r.raw, "ghost-z") {
		t.Errorf("ghost msg = %s", r.raw)
	}
	n := b.im.count("POST", "/admin/groups")
	expect(t, "ug-", create("ug-abc", nil), 400, 4004)
	expect(t, "bad id", create("a b", nil), 400, 4004)
	expect(t, "2001", create(p+"-4", map[string]any{"members": numbered("zz", 2001)}), 400, 4130)
	if b.im.count("POST", "/admin/groups") != n {
		t.Error("console checks reached im-server")
	}
	rows := b.auditRows(`action = 'group.create' AND phase = 'result' AND target LIKE '%' || $1 || '%'`, p+"-1")
	if len(rows) != 2 || rows[0]["result"] != "success" || rows[1]["code"].(int32) != 4090 {
		t.Errorf("audit = %v", rows)
	}
	// 搜索、成员数、详情不带成员列表。
	r = kf.do("GET", "/console/api/groups?q="+p+"-", nil)
	expect(t, "search", r, 200, 0)
	list := r.body["groups"].([]any)
	if len(list) != 2 || list[0].(map[string]any)["memberCount"].(float64) != 3 || list[0].(map[string]any)["type"] != "managed" {
		t.Errorf("list = %s", r.raw)
	}
	r = kf.do("GET", "/console/api/groups/"+p+"-1", nil)
	if r.body["memberCount"].(float64) != 3 || r.body["members"] != nil {
		t.Errorf("detail = %s", r.raw)
	}
	expect(t, "no group", kf.do("GET", "/console/api/groups/nope-x", nil), 404, 4043)
	// 改群名和历史可见：审计旧值 → 新值。
	expect(t, "patch empty", op.do("PATCH", "/console/api/groups/"+p+"-1", map[string]any{}), 400, 4000)
	expect(t, "patch", op.do("PATCH", "/console/api/groups/"+p+"-1", map[string]any{"name": "新名字", "historyVisible": true}), 200, 0)
	r = kf.do("GET", "/console/api/groups/"+p+"-1", nil)
	if r.str("name") != "新名字" || r.body["historyVisible"] != true {
		t.Errorf("patched = %s", r.raw)
	}
	rows = b.auditRows(`action = 'group.update' AND phase = 'intent'`)
	if len(rows) != 1 || !strings.Contains(rows[0]["params"].(string), "活动群 → 新名字") || !strings.Contains(rows[0]["params"].(string), "false → true") {
		t.Errorf("patch audit = %v", rows)
	}
	expect(t, "support patch", kf.do("PATCH", "/console/api/groups/"+p+"-1", map[string]any{"name": "x"}), 403, 4030)
}

// AC-ADM-22-1～22-6。
func testBizMembers(t *testing.T, b *bizWorld) {
	a1 := b.super("adm1")
	op := a1.create("op1", "operator")
	kf := a1.create("kf1", "support")
	p := uniq("m")
	first := numbered(p+"a", 1500)
	b.users(first...)
	g := p + "-g"
	expect(t, "create", op.do("POST", "/console/api/groups", map[string]any{"groupId": g, "name": "n", "members": first}), 200, 0)
	path := "/console/api/groups/" + g + "/members"
	// 1500 人 30 页。
	seen := map[string]bool{}
	cursor, pages := "", 0
	for {
		r := kf.do("GET", path+"?x=1"+cursor, nil)
		expect(t, "page", r, 200, 0)
		pages++
		ms := r.body["members"].([]any)
		if len(ms) != 50 {
			t.Fatalf("page %d = %d", pages, len(ms))
		}
		for _, m := range ms {
			seen[m.(map[string]any)["userId"].(string)] = true
		}
		next := r.str("nextCursor")
		if next == "" {
			break
		}
		cursor = "&cursor=" + next
	}
	if pages != 30 || len(seen) != 1500 {
		t.Errorf("pages=%d seen=%d", pages, len(seen))
	}
	// 筛选。
	r := kf.do("GET", path+"?prefix="+first[10][:len(first[10])-1], nil)
	if len(r.body["members"].([]any)) != 10 {
		t.Errorf("prefix = %s", r.raw[:200])
	}
	// 加 3 人：在线的人收到 convAdded。
	three := numbered(p+"t", 3)
	b.users(three...)
	conn := b.dial(three[0], "web")
	r = op.do("POST", path, map[string]any{"userIds": three})
	expect(t, "add", r, 200, 0)
	conn.wait("convAdded")
	if r := kf.do("GET", "/console/api/groups/"+g, nil); r.body["memberCount"].(float64) != 1503 {
		t.Errorf("count = %s", r.raw)
	}
	// 移除要理由；移除后发言 4033。
	expect(t, "remove no reason", op.do("DELETE", path, map[string]any{"userIds": three[:1]}), 400, 4000)
	expect(t, "remove", op.do("DELETE", path, map[string]any{"userIds": three[:1], "reason": goodReason}), 200, 0)
	if f := conn.wait("convRemoved"); f["data"].(map[string]any)["reason"] != "removed" {
		t.Errorf("removed = %v", f)
	}
	ack := conn.send("group:"+g, "hi")
	if e, _ := ack["error"].(map[string]any); e == nil || e["code"].(float64) != 4033 {
		t.Errorf("send after remove = %v", ack)
	}
	if rows := b.auditRows(`action = 'group.members.remove' AND phase = 'result' AND result = 'success' AND reason = $1`, goodReason); len(rows) != 1 {
		t.Errorf("remove audit = %v", rows)
	}
	// 超过 2000：一个都不加，不调用（AC-ADM-22-5）；留一条失败的审计。
	g2 := p + "-h"
	base := numbered(p+"b", 1999)
	b.users(base...)
	expect(t, "create 1999", op.do("POST", "/console/api/groups", map[string]any{"groupId": g2, "name": "n", "members": base}), 200, 0)
	two := numbered(p+"c", 2)
	b.users(two...)
	r = op.do("POST", "/console/api/groups/"+g2+"/members", map[string]any{"userIds": two})
	expect(t, "over 2000", r, 400, 4130)
	if n := b.im.count("POST", "/admin/groups/"+g2+"/members"); n != 0 {
		t.Errorf("add calls = %d", n)
	}
	// 1200 人分 3 批，一条 intent（AC-ADM-22-4）。
	g3 := p + "-i"
	expect(t, "create 500", op.do("POST", "/console/api/groups", map[string]any{"groupId": g3, "name": "n", "members": first[:500]}), 200, 0)
	r = op.do("POST", "/console/api/groups/"+g3+"/members", map[string]any{"userIds": append(first[500:1500], base[:200]...)})
	expect(t, "add 1200", r, 200, 0)
	if r.body["totalBatches"].(float64) != 3 || r.body["succeededBatches"].(float64) != 3 {
		t.Errorf("batches = %s", r.raw)
	}
	if n := b.im.count("POST", "/admin/groups/"+g3+"/members"); n != 3 {
		t.Errorf("calls = %d", n)
	}
	if r := kf.do("GET", "/console/api/groups/"+g3, nil); r.body["memberCount"].(float64) != 1700 {
		t.Errorf("count = %s", r.raw)
	}
	if rows := b.auditRows(`action = 'group.members.add' AND target LIKE '%' || $1 || '%'`, g3); len(rows) != 2 {
		t.Errorf("audit rows = %d", len(rows))
	}
	expect(t, "support add", kf.do("POST", path, map[string]any{"userIds": three}), 403, 4030)
	expect(t, "bad id", op.do("POST", path, map[string]any{"userIds": []string{"a b"}}), 400, 4004)
}

// AC-ADM-24-1、24-2、24-4、24-7。
func testBizDissolve(t *testing.T, b *bizWorld) {
	a1 := b.super("adm1")
	op := a1.create("op1", "operator")
	kf := a1.create("kf1", "support")
	mod := a1.create("mod1", "moderator")
	p := uniq("d")
	ms := numbered(p, 2)
	b.users(ms...)
	g := p + "-g"
	expect(t, "create", op.do("POST", "/console/api/groups", map[string]any{"groupId": g, "name": "n", "members": ms}), 200, 0)
	c := b.dial(ms[0], "web")
	for i := range 20 {
		if ack := c.send("group:"+g, fmt.Sprintf("m%d", i)); ack["error"] != nil {
			t.Fatalf("send: %v", ack)
		}
	}
	path := "/console/api/groups/" + g + "/dissolve"
	body := map[string]any{"reason": goodReason, "confirmGroupId": g}
	expect(t, "support", kf.do("POST", path, body), 403, 4030)
	b.advance(6 * time.Minute)
	expect(t, "no step-up", mod.do("POST", path, body), 403, 4038)
	mod.stepUp()
	expect(t, "no reason", mod.do("POST", path, map[string]any{"confirmGroupId": g}), 400, 4000)
	expect(t, "wrong confirm", mod.do("POST", path, map[string]any{"reason": goodReason, "confirmGroupId": "x"}), 400, 4000)
	if n := b.im.count("DELETE", "/admin/groups/"+g); n != 0 {
		t.Errorf("delete calls = %d", n)
	}
	expect(t, "dissolve", mod.do("POST", path, body), 200, 0)
	if f := c.wait("convRemoved"); f["data"].(map[string]any)["reason"] != "dissolved" {
		t.Errorf("event = %v", f)
	}
	expect(t, "gone", kf.do("GET", "/console/api/groups/"+g, nil), 404, 4043)
	expect(t, "again", mod.do("POST", path, body), 404, 4043)
	r := kf.do("GET", "/console/api/groups?q="+g, nil)
	if len(r.body["groups"].([]any)) != 0 {
		t.Errorf("default list = %s", r.raw)
	}
	r = kf.do("GET", "/console/api/groups?includeDissolved=true&q="+g, nil)
	if list := r.body["groups"].([]any); len(list) != 1 || list[0].(map[string]any)["dissolvedAt"] == nil {
		t.Errorf("dissolved list = %s", r.raw)
	}
	expect(t, "reuse", op.do("POST", "/console/api/groups", map[string]any{"groupId": g, "name": "n"}), 409, 4090)
	// 已解散群的元数据（AC-ADM-24-4）。
	r = kf.do("POST", "/console/api/messages/meta/query", map[string]any{"convId": "group:" + g})
	expect(t, "meta", r, 200, 0)
	if len(r.body["messages"].([]any)) != 20 {
		t.Errorf("meta = %s", r.raw)
	}
}

// AC-ADM-25-1～25-3、20-4。
func testBizOwner(t *testing.T, b *bizWorld) {
	a1 := b.super("adm1")
	op := a1.create("op1", "operator")
	kf := a1.create("kf1", "support")
	p := uniq("o")
	bob, eve := p+"bob", p+"eve"
	b.users(bob, eve)
	g := p + "-g"
	expect(t, "create", op.do("POST", "/console/api/groups", map[string]any{"groupId": g, "name": "n", "members": []string{bob}}), 200, 0)
	path := "/console/api/groups/" + g + "/owner"
	expect(t, "support", kf.do("PUT", path, map[string]any{"userId": bob, "reason": goodReason}), 403, 4030)
	expect(t, "no reason", op.do("PUT", path, map[string]any{"userId": bob}), 400, 4000)
	expect(t, "non member", op.do("PUT", path, map[string]any{"userId": eve, "reason": goodReason}), 404, 4046)
	expect(t, "set", op.do("PUT", path, map[string]any{"userId": bob, "reason": goodReason}), 200, 0)
	if r := kf.do("GET", "/console/api/groups/"+g, nil); r.body["owner"] != bob {
		t.Errorf("owner = %s", r.raw)
	}
	expect(t, "unset", op.do("PUT", path, map[string]any{"userId": nil, "reason": goodReason}), 200, 0)
	if r := kf.do("GET", "/console/api/groups/"+g, nil); r.body["owner"] != nil && r.body["owner"] != "" {
		t.Errorf("owner after unset = %s", r.raw)
	}
	if n := len(b.auditRows(`action = 'group.owner.set' AND phase = 'result' AND result = 'success'`)); n != 1 {
		t.Errorf("set audit = %d", n)
	}
	if n := len(b.auditRows(`action = 'group.owner.unset' AND phase = 'result' AND result = 'success'`)); n != 1 {
		t.Errorf("unset audit = %d", n)
	}
}

const bodyMark = "ZXQ-BODY-123"

// AC-ADM-30-1～30-8。
func testBizMeta(t *testing.T, b *bizWorld) {
	a1 := b.super("adm1")
	op := a1.create("op1", "operator")
	kf := a1.create("kf1", "support")
	p := uniq("x")
	u1, u2 := p+"a", p+"b"
	b.users(u1, u2)
	g := p + "-g"
	expect(t, "create", op.do("POST", "/console/api/groups", map[string]any{"groupId": g, "name": "n", "members": []string{u1, u2}}), 200, 0)
	c1, c2 := b.dial(u1, "web"), b.dial(u2, "web")
	for i := range 113 {
		if ack := c1.send("group:"+g, bodyMark); ack["error"] != nil {
			t.Fatalf("send %d: %v", i, ack)
		}
	}
	for range 7 {
		if ack := c2.send("group:"+g, bodyMark); ack["error"] != nil {
			t.Fatalf("send: %v", ack)
		}
	}
	const path = "/console/api/messages/meta/query"
	conv := "group:" + g
	q := func(extra map[string]any) reply {
		body := map[string]any{"convId": conv}
		for k, v := range extra {
			body[k] = v
		}
		return kf.do("POST", path, body)
	}
	seqs := func(r reply) (first, last float64, n int) {
		ms := r.body["messages"].([]any)
		if len(ms) == 0 {
			return 0, 0, 0
		}
		return ms[0].(map[string]any)["seq"].(float64), ms[len(ms)-1].(map[string]any)["seq"].(float64), len(ms)
	}
	r := q(nil)
	expect(t, "page 1", r, 200, 0)
	if f, l, n := seqs(r); f != 120 || l != 71 || n != 50 || r.body["hasMore"] != true {
		t.Errorf("page 1: %v %v %v", f, l, n)
	}
	r = q(map[string]any{"beforeSeq": 71})
	r = q(map[string]any{"beforeSeq": 21})
	if f, l, n := seqs(r); f != 20 || l != 1 || n != 20 || r.body["hasMore"] != false {
		t.Errorf("page 3: %v %v %v", f, l, n)
	}
	if rows := b.auditRows(`action = 'msg.meta.query' AND phase = 'intent' AND target LIKE '%' || $1 || '%'`, g); len(rows) != 1 {
		t.Errorf("audit rows = %d", len(rows))
	}
	// 两层响应都没有正文（AC-ADM-30-7）。
	if strings.Contains(r.raw, bodyMark) || strings.Contains(r.raw, `"body"`) {
		t.Errorf("body in response: %s", r.raw[:200])
	}
	if d := b.im.dump(); strings.Contains(d, bodyMark) {
		t.Error("body in im-server response")
	}
	// 按发送者。
	r = q(map[string]any{"from": u2})
	if _, _, n := seqs(r); n != 7 {
		t.Errorf("from = %d", n)
	}
	// 格式。
	expect(t, "bad conv", q(map[string]any{"convId": "c2c:a"}), 400, 4007)
	expect(t, "unsorted c2c", q(map[string]any{"convId": "c2c:b:a", "reason": goodReason}), 400, 4007)
	expect(t, "operator", op.do("POST", path, map[string]any{"convId": conv}), 403, 4030)
	expect(t, "super admin", a1.do("POST", path, map[string]any{"convId": conv}), 403, 4030)
	// 单聊要理由，15 分钟内翻页不用（AC-ADM-30-5）。
	x, y := p+"x", p+"y"
	c2c := "c2c:" + x + ":" + y
	r = q(map[string]any{"convId": c2c})
	expect(t, "no reason", r, 400, 4000)
	if strings.Contains(r.raw, "messages") {
		t.Error("data without reason")
	}
	// 一上来就带 beforeSeq 也绕不过理由。
	expect(t, "skip via beforeSeq", q(map[string]any{"convId": c2c, "beforeSeq": 10}), 400, 4000)
	r = q(map[string]any{"convId": c2c, "reason": goodReason})
	expect(t, "with reason", r, 200, 0)
	if len(r.body["messages"].([]any)) != 0 {
		t.Errorf("never chatted = %s", r.raw)
	}
	rows := b.auditRows(`action = 'msg.meta.query' AND phase = 'result' AND target LIKE '%' || $1 || '%'`, c2c)
	if len(rows) != 1 || rows[0]["reason"] != goodReason {
		t.Errorf("c2c audit = %v", rows)
	}
	expect(t, "page within window", q(map[string]any{"convId": c2c, "beforeSeq": 10}), 200, 0)
	if n := len(b.auditRows(`action = 'msg.meta.query' AND phase = 'result' AND target LIKE '%' || $1 || '%'`, c2c)); n != 1 {
		t.Errorf("paging wrote audit: %d", n)
	}
	b.advance(16 * time.Minute)
	expect(t, "window over", q(map[string]any{"convId": c2c, "beforeSeq": 10}), 400, 4000)
	// 换一个浏览器会话要重新填。
	expect(t, "with reason again", q(map[string]any{"convId": c2c, "reason": goodReason}), 200, 0)
	kf2 := b.client("kf1")
	kf2.seed = kf.seed
	b.tick()
	expect(t, "second login", kf2.login(), 200, 0)
	expect(t, "other session", kf2.do("POST", path, map[string]any{"convId": c2c, "beforeSeq": 10}), 400, 4000)
	// 每天 50 个不同单聊（已经用了 1 个）。
	for i := range 49 {
		conv := fmt.Sprintf("c2c:%sq%02d:%sr", p, i, p)
		if r := kf.do("POST", path, map[string]any{"convId": conv, "reason": goodReason}); r.status != 200 {
			t.Fatalf("c2c %d: %s", i, r.raw)
		}
	}
	r = kf.do("POST", path, map[string]any{"convId": "c2c:" + p + "zz:" + p + "zzz", "reason": goodReason})
	expect(t, "51st", r, 429, 4292)
	expect(t, "seen conv", q(map[string]any{"convId": c2c, "reason": goodReason}), 200, 0)
}

// AC-CON-08-4、08-9、08-10：故障注入。
func testBizAuditFaults(t *testing.T, b *bizWorld) {
	a1 := b.super("adm1")
	kf := a1.create("kf1", "support")
	mod := a1.create("mod1", "moderator")
	op := a1.create("op1", "operator")
	p := uniq("z")
	u := p + "u"
	b.users(u)
	g := p + "-g"
	expect(t, "create", op.do("POST", "/console/api/groups", map[string]any{"groupId": g, "name": "n", "members": []string{u}}), 200, 0)
	conn := b.dial(u, "web")
	mod.stepUp()

	// intent 写失败：不执行、不返回（AC-CON-08-4）。
	b.a.SetAuditFault("fail")
	expect(t, "dissolve", mod.do("POST", "/console/api/groups/"+g+"/dissolve", map[string]any{"reason": goodReason, "confirmGroupId": g}), 503, 5031)
	r := kf.do("POST", "/console/api/users/sessions/query", map[string]any{"userId": u, "reason": goodReason})
	expect(t, "sessions", r, 503, 5031)
	if strings.Contains(r.raw, "connId") {
		t.Error("data returned")
	}
	b.a.SetAuditFault("ok")
	if n := b.im.count("DELETE", "/admin/groups/"+g) + b.im.count("POST", "/admin/users/sessions/query"); n != 0 {
		t.Errorf("reached im-server %d times", n)
	}
	expect(t, "still there", kf.do("GET", "/console/api/groups/"+g, nil), 200, 0)

	// result 写失败：操作生效、照常返回；对账补上（AC-CON-08-9）。
	b.a.SetAuditFault("failResult")
	expect(t, "kick", kf.do("POST", "/console/api/users/"+u+"/kick", map[string]any{"reason": goodReason}), 200, 0)
	b.a.SetAuditFault("ok")
	conn.wait("kicked")
	if v := metricValue(t, b.world, "console_audit_result_failures_total"); v != 1 {
		t.Errorf("metric = %v", v)
	}
	rows := b.auditRows(`action = 'user.kick' AND target LIKE '%' || $1 || '%'`, u)
	if len(rows) != 1 || rows[0]["phase"] != "intent" {
		t.Fatalf("audit = %v", rows)
	}

	// im-server 执行了，console 没等到响应：504 / 5040，result 记 unknown（AC-CON-08-10）。
	u2 := p + "v"
	b.users(u2)
	conn2 := b.dial(u2, "web")
	slow, err := imclient.New(imclient.Config{BaseURL: b.im.srv.URL, Caller: "console", Key: b.key, Timeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	real := b.a.IM
	b.a.IM = slow
	b.im.mu.Lock()
	b.im.delay = 500 * time.Millisecond
	b.im.mu.Unlock()
	expect(t, "timeout", kf.do("POST", "/console/api/users/"+u2+"/kick", map[string]any{"reason": goodReason}), 504, 5040)
	b.im.mu.Lock()
	b.im.delay = 0
	b.im.mu.Unlock()
	b.a.IM = real
	conn2.wait("kicked")
	rows2 := b.auditRows(`action = 'user.kick' AND target LIKE '%' || $1 || '%'`, u2)
	if len(rows2) != 2 || rows2[1]["result"] != "unknown" || rows2[1]["code"].(int32) != 5040 {
		t.Fatalf("timeout audit = %v", rows2)
	}

	// 对账补齐这两条。[C 钟] 冻结在 2027 年，im-server 的审计是真实时间：把时钟和 intent 都对齐到现在。
	b.a.Clock.Unfreeze()
	ownerExec(t, b.owner, `UPDATE audit.records SET ts = $1 WHERE request_id = ANY($2)`, time.Now().Add(-6*time.Minute).UnixMilli(), []string{rows[0]["request_id"].(string), rows2[0]["request_id"].(string)})
	if err := b.a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{rows[0]["request_id"].(string), rows2[0]["request_id"].(string)} {
		got := b.auditRows(`request_id = $1 AND phase = 'result' AND params LIKE '%reconciled%'`, id)
		if len(got) != 1 || got[0]["result"] != "success" || !strings.Contains(got[0]["params"].(string), `"reconciled":true`) {
			t.Errorf("reconciled %s = %v", id, got)
		}
	}
}

// 同一个令牌并发提交：只有一个真正调用 im-server。
func testBizImportRace(t *testing.T, b *bizWorld) {
	a1 := b.super("adm1")
	op := a1.create("op1", "operator")
	r := op.upload("/console/api/users/import/validate", usersCSV(uniq("r")+",,"), nil)
	expect(t, "validate", r, 200, 0)
	token := r.str("importToken")
	// 占住链头锁：8 个请求都读过令牌、卡在写 intent，放开后一起去用令牌。否则请求一个接一个跑完，测不到并发。
	ctx := context.Background()
	lock, err := pgx.Connect(ctx, b.owner)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close(ctx)
	tx, err := lock.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT 1 FROM audit.chain_head WHERE id = 1 FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var okCount atomic.Int64
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r := op.do("POST", "/console/api/users/import", map[string]any{"importToken": token}); r.status == 200 {
				okCount.Add(1)
			}
		}()
	}
	time.Sleep(300 * time.Millisecond)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if okCount.Load() != 1 {
		t.Errorf("succeeded = %d", okCount.Load())
	}
	if n := b.im.count("POST", "/admin/users/import"); n != 1 {
		t.Errorf("im calls = %d", n)
	}
}

// 拆批操作的对账：按 {requestId}.{批号} 逐批查，否则已执行的批量操作会被判成 notExecuted。
func TestCON09ReconcileBatches(t *testing.T) {
	im := newFakeIM(t)
	w := newWorld(t, imEnv(im))
	ctx := context.Background()
	write := func(id string, batches int) {
		if err := w.a.Audit.Write(ctx, auditIntent(id, batches)); err != nil {
			t.Fatal(err)
		}
	}
	write("b-ok", 2)
	write("b-fail", 3)
	write("b-partial", 2)
	write("b-none", 2)
	ok := []map[string]any{{"phase": "intent", "code": 0}, {"phase": "result", "code": 0}}
	im.entries["b-ok.1"], im.entries["b-ok.2"] = ok, ok
	im.entries["b-fail.1"] = ok
	im.entries["b-fail.2"] = []map[string]any{{"phase": "result", "code": 4042}}
	im.entries["b-partial.1"] = ok
	w.advance(6 * time.Minute)
	if err := w.a.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	check := func(id, result string, code int, marker string) {
		t.Helper()
		rows := w.auditRows(`request_id = $1 AND phase = 'result'`, id)
		if len(rows) != 1 || rows[0]["result"] != result || int(rows[0]["code"].(int32)) != code || !strings.Contains(rows[0]["params"].(string), marker) {
			t.Errorf("%s = %v", id, rows)
		}
	}
	check("b-ok", "success", 0, `"reconciled":true`)
	check("b-fail", "failure", 4042, `"reconciled":true`)
	check("b-partial", "unknown", 0, `"reconciled":"partial"`)
	check("b-none", "failure", 0, `"reconciled":"notExecuted"`)
}

// 矩阵（AC-ADM-05-1）：路由表 × 5 个单角色。路由表是同一份数据，新路由没写样本这里就失败。
func TestAdminMatrix(t *testing.T) {
	b := newBizWorld(t)
	super := b.super("adm1")
	roles := map[string]*user{
		"super_admin": super, "operator": super.create("op1", "operator"), "support": super.create("kf1", "support"),
		"moderator": super.create("mod1", "moderator"), "auditor": super.create("aud1", "auditor"),
	}
	want := func(perm, role string) bool {
		return permMatrix[perm][role]
	}
	u := uniq("mx")
	b.users(u, u+"b")
	n := 0
	next := func(prefix string) string { n++; return fmt.Sprintf("%s%s%d", u, prefix, n) }
	// 群样本：每次一个新群，解散之类的操作不互相影响。
	newGroup := func() string {
		g := next("g")
		if err := b.sysDo("POST", "/admin/groups", map[string]any{"groupId": g, "name": "n", "members": []string{u}}, nil); err != nil {
			t.Fatal(err)
		}
		return g
	}
	samples := map[string]func(*user) reply{
		"GET /console/api/stats": func(c *user) reply { return c.do("GET", "/console/api/stats", nil) },
		"GET /console/api/users": func(c *user) reply { return c.do("GET", "/console/api/users?q="+u, nil) },
		"POST /console/api/users/import/validate": func(c *user) reply {
			return c.upload("/console/api/users/import/validate", usersCSV(next("i")+",,"), nil)
		},
		"POST /console/api/users/import": func(c *user) reply {
			r := c.upload("/console/api/users/import/validate", usersCSV(next("i")+",,"), nil)
			if r.status != 200 {
				return r
			}
			return c.do("POST", "/console/api/users/import", map[string]any{"importToken": r.str("importToken")})
		},
		"POST /console/api/users/sessions/query": func(c *user) reply {
			return c.do("POST", "/console/api/users/sessions/query", map[string]any{"userId": u, "reason": goodReason})
		},
		"GET /console/api/users/{id}": func(c *user) reply { return c.do("GET", "/console/api/users/"+u, nil) },
		"POST /console/api/users/{id}/kick": func(c *user) reply {
			return c.do("POST", "/console/api/users/"+u+"/kick", map[string]any{"reason": goodReason})
		},
		"PUT /console/api/users/{id}/official": func(c *user) reply {
			return c.do("PUT", "/console/api/users/"+u+"/official", map[string]any{"official": true, "reason": goodReason})
		},
		"POST /console/api/invites": func(c *user) reply {
			return c.do("POST", "/console/api/invites", inviteBody(1, 1))
		},
		"GET /console/api/invites": func(c *user) reply { return c.do("GET", "/console/api/invites", nil) },
		"POST /console/api/invites/{id}/disable": func(c *user) reply {
			r := roles["operator"].do("POST", "/console/api/invites", inviteBody(1, 1))
			return c.do("POST", "/console/api/invites/"+firstInvite(t, r).ID+"/disable", map[string]any{})
		},
		"GET /console/api/users/{id}/friends": func(c *user) reply { return c.do("GET", "/console/api/users/"+u+"/friends", nil) },
		"POST /console/api/friends/import/validate": func(c *user) reply {
			return c.upload("/console/api/friends/import/validate", u+","+u+"b\n", nil)
		},
		"POST /console/api/friends/import": func(c *user) reply {
			csv := u + "," + u + "b\n"
			if c.name != "op1" {
				return c.upload("/console/api/friends/import", csv, nil)
			}
			r := c.upload("/console/api/friends/import/validate", csv, nil)
			return c.upload("/console/api/friends/import", csv, map[string]string{"importToken": r.str("importToken"), "reason": goodReason})
		},
		"POST /console/api/friends/delete/validate": func(c *user) reply {
			return c.upload("/console/api/friends/delete/validate", u+","+u+"b\n", nil)
		},
		"POST /console/api/friends/delete": func(c *user) reply {
			csv := u + "," + u + "b\n"
			if c.name != "op1" {
				return c.upload("/console/api/friends/delete", csv, nil)
			}
			r := c.upload("/console/api/friends/delete/validate", csv, nil)
			return c.upload("/console/api/friends/delete", csv, map[string]string{"importToken": r.str("importToken"), "reason": goodReason})
		},
		"GET /console/api/settings/social": func(c *user) reply { return c.do("GET", "/console/api/settings/social", nil) },
		"PATCH /console/api/settings/social": func(c *user) reply {
			n++
			return c.do("PATCH", "/console/api/settings/social", map[string]any{"maxFriends": 1000 + n, "reason": goodReason})
		},
		"GET /console/api/groups": func(c *user) reply { return c.do("GET", "/console/api/groups", nil) },
		"POST /console/api/groups": func(c *user) reply {
			return c.do("POST", "/console/api/groups", map[string]any{"groupId": next("c"), "name": "n", "members": []string{u}})
		},
		"GET /console/api/groups/{id}": func(c *user) reply { return c.do("GET", "/console/api/groups/"+newGroup(), nil) },
		"PATCH /console/api/groups/{id}": func(c *user) reply {
			return c.do("PATCH", "/console/api/groups/"+newGroup(), map[string]any{"name": "x"})
		},
		"GET /console/api/groups/{id}/members": func(c *user) reply { return c.do("GET", "/console/api/groups/"+newGroup()+"/members", nil) },
		"POST /console/api/groups/{id}/members": func(c *user) reply {
			return c.do("POST", "/console/api/groups/"+newGroup()+"/members", map[string]any{"userIds": []string{u + "b"}})
		},
		"DELETE /console/api/groups/{id}/members": func(c *user) reply {
			return c.do("DELETE", "/console/api/groups/"+newGroup()+"/members", map[string]any{"userIds": []string{u}, "reason": goodReason})
		},
		"PUT /console/api/groups/{id}/owner": func(c *user) reply {
			return c.do("PUT", "/console/api/groups/"+newGroup()+"/owner", map[string]any{"userId": u, "reason": goodReason})
		},
		"POST /console/api/groups/{id}/dissolve": func(c *user) reply {
			g := newGroup()
			return c.do("POST", "/console/api/groups/"+g+"/dissolve", map[string]any{"reason": goodReason, "confirmGroupId": g})
		},
		"POST /console/api/messages/meta/query": func(c *user) reply {
			return c.do("POST", "/console/api/messages/meta/query", map[string]any{"convId": "group:" + newGroup()})
		},
		"POST /console/api/users/convs/query": func(c *user) reply {
			return c.do("POST", "/console/api/users/convs/query", map[string]any{"userId": u, "reason": "matrix test"})
		},
		"GET /console/api/users/{id}/groups": func(c *user) reply { return c.do("GET", "/console/api/users/"+u+"/groups", nil) },
		"POST /console/api/users/{id}/ban": func(c *user) reply {
			return c.do("POST", "/console/api/users/"+u+"b/ban", map[string]any{"duration": "1h", "reason": "matrix test"})
		},
		"POST /console/api/users/{id}/unban": func(c *user) reply {
			return c.do("POST", "/console/api/users/"+u+"b/unban", map[string]any{"reason": "matrix test"})
		},
		"POST /console/api/mutes": func(c *user) reply {
			return c.do("POST", "/console/api/mutes", map[string]any{"scope": "user", "userId": u, "duration": "10m", "reason": "matrix test"})
		},
		"POST /console/api/mutes/release": func(c *user) reply {
			return c.do("POST", "/console/api/mutes/release", map[string]any{"scope": "user", "userId": u, "reason": "matrix test"})
		},
		"POST /console/api/messages/delete": func(c *user) reply {
			g := newGroup()
			return c.do("POST", "/console/api/messages/delete", map[string]any{"convId": "group:" + g, "msgIds": []string{sendInto(t, b, u, g)}, "reason": "matrix test"})
		},
		"POST /console/api/messages/grants": func(c *user) reply {
			b.tick() // 同一个步长的动态码不能用两次
			return c.do("POST", "/console/api/messages/grants", map[string]any{"convId": "group:" + newGroup(), "ticket": "T-1", "reason": "matrix test", "otp": c.otp()})
		},
		"POST /console/api/messages/body": func(c *user) reply {
			g := newGroup()
			b.tick()
			c.do("POST", "/console/api/messages/grants", map[string]any{"convId": "group:" + g, "ticket": "T-1", "reason": "matrix test", "otp": c.otp()})
			return c.do("POST", "/console/api/messages/body", map[string]any{"convId": "group:" + g})
		},
		"GET /console/api/push/templates": func(c *user) reply { return c.do("GET", "/console/api/push/templates", nil) },
		"POST /console/api/push/targets/validate": func(c *user) reply {
			return c.upload("/console/api/push/targets/validate", "userId\n"+u+"\n", nil)
		},
		"POST /console/api/push/preview": func(c *user) reply {
			return c.do("POST", "/console/api/push/preview", map[string]any{"target": "user", "userIds": []string{u}, "type": "notice", "data": matrixNotice})
		},
		"POST /console/api/push/user": func(c *user) reply {
			return c.do("POST", "/console/api/push/user", map[string]any{"userIds": []string{u}, "type": "notice", "data": matrixNotice, "reason": "matrix test"})
		},
		"GET /console/api/push/all/drafts": func(c *user) reply { return c.do("GET", "/console/api/push/all/drafts", nil) },
		"POST /console/api/push/all/drafts": func(c *user) reply {
			return c.do("POST", "/console/api/push/all/drafts", map[string]any{"type": "notice", "data": matrixNotice, "reason": "matrix test"})
		},
		"GET /console/api/push/all/drafts/pending": func(c *user) reply { return c.do("GET", "/console/api/push/all/drafts/pending", nil) },
		"POST /console/api/push/all/drafts/{id}/approve": func(c *user) reply {
			d := roles["operator"].do("POST", "/console/api/push/all/drafts", map[string]any{"type": "notice", "data": matrixNotice, "reason": "matrix test"})
			return c.do("POST", "/console/api/push/all/drafts/"+d.str("draftId")+"/approve", map[string]any{"confirmText": "全员发送"})
		},
		"GET /console/api/push/records": func(c *user) reply { return c.do("GET", "/console/api/push/records", nil) },
	}
	routes := app.BusinessRouteInfo()
	if len(routes) != len(samples) {
		t.Errorf("routes = %d, samples = %d", len(routes), len(samples))
	}
	for _, rt := range routes {
		key := rt.Method + " " + rt.Path
		sample, ok := samples[key]
		if !ok {
			t.Errorf("no sample for %s", key)
			continue
		}
		if _, ok := permMatrix[rt.Perm]; !ok {
			t.Errorf("%s: permission %s is not in the matrix", key, rt.Perm)
		}
		for role, c := range roles {
			if rt.StepUp && want(rt.Perm, role) {
				c.stepUp()
			}
			r := sample(c)
			if want(rt.Perm, role) {
				if r.status != 200 {
					t.Errorf("%s as %s = %d %s", key, role, r.status, r.raw)
				}
			} else {
				if r.status != 403 || r.code() != 4030 {
					t.Errorf("%s as %s = %d %s, want 403 / 4030", key, role, r.status, r.raw)
				}
			}
			// 响应里不能有 im-server 的签名头和密钥（AC-CON-10-1、CS-017 内容 2）。
			for h := range r.header {
				if strings.HasPrefix(strings.ToLower(h), "x-im-") {
					t.Errorf("%s leaks header %s", key, h)
				}
			}
			if strings.Contains(r.raw, "X-IM-") {
				t.Errorf("%s leaks im-server headers: %s", key, r.raw)
			}
		}
	}
	// AC-CON-08-11：每类写操作和敏感查看都有字段齐全的审计。action 同一路由可能有变体（official.set / unset）。
	for _, rt := range routes {
		if rt.Action == "" {
			continue
		}
		rows := b.auditRows(`action = $1 AND phase = 'result' AND result = 'success'`, rt.Action)
		if len(rows) == 0 {
			t.Errorf("%s %s: no audit result for %s", rt.Method, rt.Path, rt.Action)
			continue
		}
		r := rows[0]
		for _, f := range []string{"request_id", "username", "actor", "ip", "action"} {
			if r[f] == "" {
				t.Errorf("%s: audit field %s is empty: %v", rt.Action, f, r)
			}
		}
		if len(b.auditRows(`request_id = $1 AND phase = 'intent' AND action = $2`, r["request_id"], rt.Action)) != 1 {
			t.Errorf("%s: no matching intent", rt.Action)
		}
	}

	// AC-ADM-05-4：超管没有审计和元数据。
	now := b.now.UnixMilli()
	expect(t, "super audit", super.do("GET", auditURL(now-1000, now, ""), nil), 403, 4030)
	expect(t, "super meta", super.do("POST", "/console/api/messages/meta/query", map[string]any{"convId": "group:x"}), 403, 4030)
	// 运维空间没有业务路由。
	ops := b.opsSuper("ops1")
	expect(t, "ops users", ops.do("GET", "/console/api/users?q=a", nil), 404, 4040)
	// 日志里没有签名密钥。
	if strings.Contains(b.logs.String(), "X-IM-Signature") {
		t.Error("signature header in logs")
	}
}

// 5.2 节矩阵。测试里手写一份，和 perm.Admin 互相校验：改了权限表这里要跟着改。
var matrixNotice = map[string]any{"title": "matrix", "text": "matrix"}

var permMatrix = map[string]map[string]bool{
	"user.read":         {"super_admin": true, "operator": true, "support": true, "moderator": true},
	"user.import":       {"operator": true},
	"account.invite":    {"operator": true},
	"user.kick":         {"support": true, "moderator": true},
	"user.sessions":     {"support": true, "moderator": true},
	"user.official":     {"operator": true},
	"social.read":       {"super_admin": true, "operator": true, "support": true, "moderator": true},
	"social.write":      {"operator": true},
	"social.settings":   {"operator": true},
	"group.read":        {"super_admin": true, "operator": true, "support": true, "moderator": true},
	"group.write":       {"operator": true},
	"group.owner":       {"operator": true},
	"group.dissolve":    {"operator": true, "moderator": true},
	"msg.meta":          {"support": true, "moderator": true},
	"mute.write":        {"support": true, "moderator": true},
	"user.ban":          {"moderator": true},
	"msg.delete":        {"moderator": true},
	"msg.read.group":    {"moderator": true},
	"push.user":         {"operator": true},
	"push.all.request":  {"operator": true},
	"push.all.approve":  {"super_admin": true},
	"push.records.read": {"super_admin": true, "auditor": true},
	"stats.read":        {"super_admin": true, "operator": true},
}

// AC-ADM-15-7：im-server 没有注册这个接口。
func TestSocialNotAvailable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	w := newWorld(t, map[string]string{"CON_IM_ADMIN_URL": srv.URL, "CON_IM_SIGNING_KEY": b64(testSeed)})
	a1 := w.super("adm1")
	op := a1.create("op1", "operator")
	csv := "alice,bob\n"
	r := op.upload("/console/api/friends/import/validate", csv, nil)
	expect(t, "validate", r, 200, 0)
	op.stepUp()
	r = op.upload("/console/api/friends/import", csv, map[string]string{"importToken": r.str("importToken"), "reason": goodReason})
	expect(t, "partial response", r, 200, 0)
	if r.body["failedCode"].(float64) != 4040 || !strings.Contains(r.str("failedMsg"), "not available") {
		t.Errorf("import = %s", r.raw)
	}
	r = op.do("GET", "/console/api/settings/social", nil)
	expect(t, "settings", r, 404, 4040)
	if r.reason() != "notAvailable" {
		t.Errorf("settings = %s", r.raw)
	}
}

// 理由规则。
func TestCheckReason(t *testing.T) {
	for in, ok := range map[string]bool{
		"": false, "abc": false, "aaaa": false, "   aaaa   ": false, "长长长长": false, "abcd": true, " 工单处理 ": true, "1234": true, "aaab": true,
		strings.Repeat("长", 200) + "x": false, strings.Repeat("长", 199) + "x": true,
	} {
		if _, e := app.CheckReason(in); (e == nil) != ok {
			t.Errorf("%q: %v", in, e)
		}
	}
}

// 导入 intent 的样本。
func auditIntent(id string, batches int) audit.Record {
	return audit.Record{Space: "admin", Phase: audit.PhaseIntent, RequestID: id, Actor: "op1", Action: "user.import", Params: map[string]any{"batches": batches}}
}
