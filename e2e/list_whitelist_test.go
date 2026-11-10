package e2e

// console-chat 第 22 条（CS-205 发现）：群列表、群成员、用户所在群、首页数据概览按白名单输出，和用户详情、用户列表一样
// 不透传 im-server 多出来的字段。字段以 tianting-admin 对应页面实际读的为准：
//   - Groups 页（GroupRow）、GroupDetail 页成员表（MemberRow）、UserDetail 页"所在群"（UserGroupRow 中页面读的部分）、
//     DataOverview（Stats）；分页列表外层只有列表本身和 nextCursor（useCursorList）。
// 每个用例：页面字段一个不少（键集合完全一致）、翻页照常、im-server 多返回的外层 / 行内字段出不去。

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

// injectIM 让代理改写 path 的响应：外层加未知字段，每一行（以 rowStart 开头的对象）前面加 convSettings 和未知字段。
// 返回一个函数，告诉用例改写确实发生过。
func injectIM(t *testing.T, b *bizWorld, match func(path string) bool, rowStart string) func() bool {
	t.Helper()
	var done atomic.Bool
	b.im.mu.Lock()
	b.im.rewrite = func(path string, body []byte) []byte {
		if !match(path) {
			return body
		}
		body = bytes.Replace(body, []byte(`{`), []byte(`{"zxqOuter":"ZXQ-LW-0","total":99,`), 1)
		if rowStart != "" {
			body = bytes.ReplaceAll(body, []byte(`{`+rowStart), []byte(`{"convSettings":[{"convId":"group:g1","pinned":true,"notifyOff":true,"clearedSeq":10}],"zxqRow":"ZXQ-LW-1",`+rowStart))
		}
		done.Store(true)
		return body
	}
	b.im.mu.Unlock()
	t.Cleanup(func() {
		b.im.mu.Lock()
		b.im.rewrite = nil
		b.im.mu.Unlock()
	})
	return done.Load
}

func noExtraFields(t *testing.T, label, raw string) {
	t.Helper()
	for _, bad := range []string{"ZXQ", "zxq", `"total":99`, "convSettings", `"pinned"`, `"notifyOff"`, `"clearedSeq"`} {
		if strings.Contains(raw, bad) {
			t.Errorf("%s: extra field %q forwarded: %s", label, bad, raw)
		}
	}
}

// listRows 检查外层正好是 listKey、nextCursor，返回按 idKey 索引的行。
func listRows(t *testing.T, label string, r reply, listKey, idKey string) map[string]map[string]any {
	t.Helper()
	expect(t, label, r, 200, 0)
	if got, want := sortedKeys(r.body), []string{listKey, "nextCursor"}; !slices.Equal(got, sortedStrings(want)) {
		t.Errorf("%s outer fields = %v, want %v: %s", label, got, sortedStrings(want), r.raw)
	}
	out := map[string]map[string]any{}
	list, _ := r.body[listKey].([]any)
	for _, it := range list {
		m := it.(map[string]any)
		id, _ := m[idKey].(string)
		if id == "" {
			t.Fatalf("%s row without %s: %s", label, idKey, r.raw)
		}
		out[id] = m
	}
	return out
}

func sortedStrings(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return out
}

func rowKeys(t *testing.T, label string, row map[string]any, want []string) {
	t.Helper()
	if row == nil {
		t.Errorf("%s: row missing", label)
		return
	}
	if got := sortedKeys(row); !slices.Equal(got, sortedStrings(want)) {
		t.Errorf("%s fields = %v, want %v (%v)", label, got, sortedStrings(want), row)
	}
}

// pages 按 limit=20 翻两页：第一页 20 个、有 nextCursor，第二页 rest 个、nextCursor 为空，两页不重复。
func pages(t *testing.T, u *user, path, listKey, idKey string, rest int) {
	t.Helper()
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	first := u.do("GET", path+sep+"limit=20", nil)
	p1 := listRows(t, "page 1", first, listKey, idKey)
	next := first.str("nextCursor")
	if len(p1) != 20 || next == "" {
		t.Fatalf("page 1 = %s", first.raw)
	}
	second := u.do("GET", path+sep+"limit=20&cursor="+next, nil)
	p2 := listRows(t, "page 2", second, listKey, idKey)
	if len(p2) != rest || second.str("nextCursor") != "" {
		t.Errorf("page 2 = %s", second.raw)
	}
	for id := range p2 {
		if p1[id] != nil {
			t.Errorf("%s on both pages", id)
		}
	}
}

// 群列表：GroupRow 的 groupId、name、type、owner、memberCount、historyVisible、createdAt、dissolvedAt（解散的才有）。
var groupListRowFields = []string{"groupId", "name", "type", "owner", "memberCount", "historyVisible", "createdAt"}

func TestGroupListWhitelist(t *testing.T) {
	b := newBizWorld(t)
	super := b.super("adm1")
	kf := super.create("kf1", "support")
	p := uniq("gl")
	u1, u2 := p+"a", p+"b"
	b.users(u1, u2)
	for i, g := range []string{p + "-own", p + "-gone"} {
		body := map[string]any{"groupId": g, "name": fmt.Sprintf("群%d", i), "members": []string{u1, u2}}
		if i == 0 {
			body["owner"] = u1
		}
		if err := b.sysDo("POST", "/admin/groups", body, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.sysDo("DELETE", "/admin/groups/"+p+"-gone", nil, nil); err != nil {
		t.Fatal(err)
	}
	check := func(label string, r reply) {
		t.Helper()
		rows := listRows(t, label, r, "groups", "groupId")
		own, gone := rows[p+"-own"], rows[p+"-gone"]
		rowKeys(t, label+" active", own, groupListRowFields)
		rowKeys(t, label+" dissolved", gone, append(slices.Clone(groupListRowFields), "dissolvedAt"))
		if own["owner"] != u1 || own["name"] != "群0" || own["memberCount"] != float64(2) || own["type"] == "" || own["dissolvedAt"] != nil {
			t.Errorf("%s active row = %v", label, own)
		}
		if gone["owner"] != nil || gone["dissolvedAt"] == nil {
			t.Errorf("%s dissolved row = %v", label, gone)
		}
	}
	path := "/console/api/groups?includeDissolved=true&q=" + p + "-"
	check("groups", kf.do("GET", path, nil))

	q := uniq("glp")
	for i := range 21 {
		if err := b.sysDo("POST", "/admin/groups", map[string]any{"groupId": fmt.Sprintf("%s-%02d", q, i), "name": "n", "members": []string{u1}}, nil); err != nil {
			t.Fatal(err)
		}
	}
	pages(t, kf, "/console/api/groups?q="+q+"-", "groups", "groupId", 1)

	done := injectIM(t, b, func(path string) bool { return path == "/admin/groups" }, `"groupId"`)
	leak := kf.do("GET", path, nil)
	if !done() {
		t.Fatal("im-server response was not rewritten")
	}
	noExtraFields(t, "groups", leak.raw)
	check("groups with extra fields", leak)
}

// 群成员：MemberRow 的 userId、role、joinedAt、mutedUntil（群内禁言中才有）。
var groupMemberRowFields = []string{"userId", "role", "joinedAt"}

func TestGroupMembersWhitelist(t *testing.T) {
	b := newBizWorld(t)
	super := b.super("adm1")
	kf := super.create("kf1", "support")
	p := uniq("gm")
	members := numbered(p, 51)
	b.users(members...)
	g := p + "-g"
	if err := b.sysDo("POST", "/admin/groups", map[string]any{"groupId": g, "name": "n", "members": members, "owner": members[0]}, nil); err != nil {
		t.Fatal(err)
	}
	expect(t, "group mute", kf.do("POST", "/console/api/mutes", map[string]any{"scope": "group", "groupId": g, "userId": members[1], "customSeconds": 600, "reason": "spam spam"}), 200, 0)
	path := "/console/api/groups/" + g + "/members"
	check := func(label string, r reply) {
		t.Helper()
		rows := listRows(t, label, r, "members", "userId")
		if len(rows) != 50 || r.str("nextCursor") == "" {
			t.Fatalf("%s page 1 = %d rows: %s", label, len(rows), r.raw)
		}
		owner, muted, plain := rows[members[0]], rows[members[1]], rows[members[2]]
		rowKeys(t, label+" owner", owner, groupMemberRowFields)
		rowKeys(t, label+" muted", muted, append(slices.Clone(groupMemberRowFields), "mutedUntil"))
		rowKeys(t, label+" member", plain, groupMemberRowFields)
		if owner["role"] != "owner" || plain["role"] != "member" || plain["joinedAt"] == nil || muted["mutedUntil"] == nil {
			t.Errorf("%s rows = %v / %v / %v", label, owner, muted, plain)
		}
	}
	first := kf.do("GET", path, nil)
	check("members", first)
	// 每页固定 50：第二页是剩下的 1 个。
	second := listRows(t, "members page 2", kf.do("GET", path+"?cursor="+first.str("nextCursor"), nil), "members", "userId")
	if len(second) != 1 || second[members[50]] == nil {
		t.Errorf("members page 2 = %v", second)
	}

	done := injectIM(t, b, func(path string) bool { return path == "/admin/groups/"+g+"/members" }, `"userId"`)
	leak := kf.do("GET", path, nil)
	if !done() {
		t.Fatal("im-server response was not rewritten")
	}
	noExtraFields(t, "members", leak.raw)
	check("members with extra fields", leak)
}

// 用户所在群：UserDetail 页"所在群"读的 groupId、name、role、memberCount、joinedAt。im-server 还返回 type，页面不读，不放。
var userGroupRowFields = []string{"groupId", "name", "role", "memberCount", "joinedAt"}

func TestUserGroupsWhitelist(t *testing.T) {
	b := newBizWorld(t)
	super := b.super("adm1")
	kf := super.create("kf1", "support")
	p := uniq("ugw")
	u, peer := p+"a", p+"b"
	b.users(u, peer)
	owned := p + "-own"
	if err := b.sysDo("POST", "/admin/groups", map[string]any{"groupId": owned, "name": "我的群", "members": []string{u, peer}, "owner": u}, nil); err != nil {
		t.Fatal(err)
	}
	for range 20 {
		b.group(u)
	}
	path := "/console/api/users/" + u + "/groups"
	check := func(label string, r reply) {
		t.Helper()
		rows := listRows(t, label, r, "groups", "groupId")
		if len(rows) != 21 {
			t.Fatalf("%s rows = %d: %s", label, len(rows), r.raw)
		}
		for id, row := range rows {
			rowKeys(t, label+" "+id, row, userGroupRowFields)
		}
		if g := rows[owned]; g["name"] != "我的群" || g["role"] != "owner" || g["memberCount"] != float64(2) || g["joinedAt"] == nil {
			t.Errorf("%s owned = %v", label, g)
		}
	}
	check("user groups", kf.do("GET", path+"?limit=50", nil))
	pages(t, kf, path, "groups", "groupId", 1)

	done := injectIM(t, b, func(path string) bool { return path == "/admin/users/"+u+"/groups" }, `"groupId"`)
	leak := kf.do("GET", path+"?limit=50", nil)
	if !done() {
		t.Fatal("im-server response was not rewritten")
	}
	noExtraFields(t, "user groups", leak.raw)
	check("user groups with extra fields", leak)
}

// 首页数据概览：DataOverview 的 Stats。
var (
	statsTopFields    = []string{"online", "newUsersToday", "messagesToday", "groupsTotal", "dayStart", "serverTime"}
	statsOnlineFields = []string{"total", "byPlatform", "partial", "scope"}
)

func TestStatsWhitelist(t *testing.T) {
	b := newBizWorld(t)
	super := b.super("adm1")
	op := super.create("op1", "operator")
	u := uniq("sw")
	b.users(u+"a", u+"b")
	b.dial(u+"a", "web")
	b.dial(u+"b", "pc")
	check := func(label string, r reply) {
		t.Helper()
		expect(t, label, r, 200, 0)
		if got := sortedKeys(r.body); !slices.Equal(got, sortedStrings(statsTopFields)) {
			t.Errorf("%s fields = %v, want %v: %s", label, got, sortedStrings(statsTopFields), r.raw)
		}
		online, _ := r.body["online"].(map[string]any)
		if got := sortedKeys(online); !slices.Equal(got, sortedStrings(statsOnlineFields)) {
			t.Errorf("%s online fields = %v: %s", label, got, r.raw)
		}
		by, _ := online["byPlatform"].(map[string]any)
		if online["total"] != float64(2) || by["web"] != float64(1) || by["pc"] != float64(1) || online["partial"] != true || online["scope"] != "localNode" {
			t.Errorf("%s online = %v", label, online)
		}
		for _, k := range []string{"newUsersToday", "messagesToday", "groupsTotal", "dayStart", "serverTime"} {
			if _, ok := r.body[k].(float64); !ok {
				t.Errorf("%s %s = %v", label, k, r.body[k])
			}
		}
	}
	check("stats", op.do("GET", "/console/api/stats", nil))

	// 外层、online 里的未知字段出不去；byPlatform 里不是数字的项丢掉，数字照常。
	var done atomic.Bool
	b.im.mu.Lock()
	b.im.rewrite = func(path string, body []byte) []byte {
		if path != "/admin/stats" {
			return body
		}
		body = bytes.Replace(body, []byte(`{`), []byte(`{"zxqOuter":"ZXQ-LW-0","convSettings":[{"pinned":true}],`), 1)
		body = bytes.Replace(body, []byte(`"online":{`), []byte(`"online":{"zxqOnline":"ZXQ-LW-2","nodes":["n1"],`), 1)
		body = bytes.Replace(body, []byte(`"byPlatform":{`), []byte(`"byPlatform":{"zxq":{"userId":"ZXQ-LW-3"},`), 1)
		done.Store(bytes.Contains(body, []byte("ZXQ-LW-3")))
		return body
	}
	b.im.mu.Unlock()
	defer func() {
		b.im.mu.Lock()
		b.im.rewrite = nil
		b.im.mu.Unlock()
	}()
	leak := op.do("GET", "/console/api/stats", nil)
	if !done.Load() {
		t.Fatal("im-server response was not rewritten")
	}
	noExtraFields(t, "stats", leak.raw)
	if strings.Contains(leak.raw, "nodes") {
		t.Errorf("stats online extra field forwarded: %s", leak.raw)
	}
	check("stats with extra fields", leak)
}
