package e2e

import (
	"testing"
	"time"
)

// AC-ADM-70-1：真实的 im-server，3 个 web、2 个 pc 在线；只有超管和运营能看；不写审计；单节点范围如实返回。
func TestStats_AC70_1(t *testing.T) {
	b := newBizWorld(t)
	super := b.super("adm1")
	op := super.create("op1", "operator")
	kf := super.create("kf1", "support")
	aud := super.create("aud1", "auditor")

	empty := op.do("GET", "/console/api/stats", nil)
	expect(t, "empty", empty, 200, 0)
	online, _ := empty.body["online"].(map[string]any)
	if online == nil || online["total"] != float64(0) {
		t.Fatalf("online = %s", empty.raw)
	}

	u := uniq("st")
	b.users(u+"a", u+"b", u+"c", u+"d", u+"e")
	for _, x := range []struct{ id, platform string }{{"a", "web"}, {"b", "web"}, {"c", "web"}, {"d", "pc"}, {"e", "pc"}} {
		b.dial(u+x.id, x.platform)
	}
	r := op.do("GET", "/console/api/stats", nil)
	expect(t, "stats", r, 200, 0)
	online, _ = r.body["online"].(map[string]any)
	by, _ := online["byPlatform"].(map[string]any)
	if online["total"] != float64(5) || by["web"] != float64(3) || by["pc"] != float64(2) {
		t.Errorf("online = %s", r.raw)
	}
	// B6 之前只能算一个节点：页面靠这两个字段标注，不能丢。
	if online["partial"] != true || online["scope"] != "localNode" {
		t.Errorf("scope = %s", r.raw)
	}
	for _, k := range []string{"newUsersToday", "messagesToday", "groupsTotal", "dayStart", "serverTime"} {
		if _, ok := r.body[k].(float64); !ok {
			t.Errorf("%s missing: %s", k, r.raw)
		}
	}
	expect(t, "super", super.do("GET", "/console/api/stats", nil), 200, 0)
	expect(t, "support", kf.do("GET", "/console/api/stats", nil), 403, 4030)
	expect(t, "auditor", aud.do("GET", "/console/api/stats", nil), 403, 4030)
	expect(t, "anonymous", b.client("nobody").do("GET", "/console/api/stats", nil), 401, 4014)
	// 只读接口：其他方法进不来，查询不写审计。
	if r := op.do("POST", "/console/api/stats", map[string]any{}); r.status != 405 && r.status != 404 {
		t.Errorf("POST = %d", r.status)
	}
	if rows := b.auditRows(`action LIKE '%stats%' AND username = 'op1'`); len(rows) != 0 {
		t.Errorf("audit = %v", rows)
	}
}

// AC-ADM-70-2 [C 钟]：首页开着、没有人操作：带 X-Console-Background 的刷新不续期，31 分钟后下一次刷新 401 / 4014。
func TestStats_AC70_2_BackgroundDoesNotRenew(t *testing.T) {
	b := newBizWorld(t)
	super := b.super("adm1")
	op := super.create("op1", "operator")
	expect(t, "login", op.do("GET", "/console/api/stats", nil), 200, 0) // 打开首页：最后一次用户活动

	// 每分钟一次后台刷新，一直刷到 30 分钟：都成功，但都不算活动。
	for i := 1; i <= 30; i++ {
		b.advance(time.Minute)
		expect(t, "refresh", op.do("GET", "/console/api/stats", nil, background), 200, 0)
	}
	b.advance(time.Minute) // 第 31 分钟
	r := op.do("GET", "/console/api/stats", nil, background)
	expect(t, "31 minutes", r, 401, 4014)
	if r.reason() != "idle" {
		t.Errorf("reason = %q", r.reason())
	}

	// 对照：不带后台头的请求是用户活动，会续期。所以上面的 401 确实是后台头的作用。
	b.tick()
	expect(t, "login again", op.login(), 200, 0)
	for range 4 {
		b.advance(10 * time.Minute)
		expect(t, "foreground", op.do("GET", "/console/api/stats", nil), 200, 0)
	}
}
