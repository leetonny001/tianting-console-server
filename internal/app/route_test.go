package app

import (
	"strings"
	"testing"

	"tianting/console/internal/perm"
)

// AC-CON-06-1：没有声明权限点的路由启动失败。
func TestRouteWithoutPermissionPanics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil || !strings.Contains(r.(string), "route without permission") {
			t.Errorf("recover = %v", r)
		}
	}()
	checkRoute(route{method: "GET", path: "/console/api/new-thing"})
}

// 全部路由都声明了：公开路由只有登录、激活和运维空间的引导状态；账号管理都要权限点，写操作都要 step-up。
func TestRouteTable(t *testing.T) {
	a := &App{}
	for _, ps := range []perm.Space{perm.Admin, perm.Ops} {
		for _, rt := range a.apiRoutes(ps) {
			checkRoute(rt)
			if rt.public && rt.path != "/console/api/auth/login" && rt.path != "/console/api/auth/activate" && rt.path != "/console/api/auth/bootstrap-status" {
				t.Errorf("public route: %s", rt.path)
			}
			if strings.HasPrefix(rt.path, "/console/api/accounts") {
				if rt.perm != ps.ManagePerm {
					t.Errorf("%s: perm %s", rt.path, rt.perm)
				}
				if rt.method != "GET" && !rt.stepUp {
					t.Errorf("%s %s: no step-up", rt.method, rt.path)
				}
			}
			if rt.method == "DELETE" && strings.HasPrefix(rt.path, "/console/api/accounts") {
				t.Errorf("accounts cannot be deleted: %s", rt.path)
			}
			// 带理由的敏感查询不能用 GET（CS-020 内容 3）。
			if rt.sensitive && rt.method == "GET" {
				t.Errorf("sensitive query uses GET: %s", rt.path)
			}
		}
	}
}

func TestValidReason(t *testing.T) {
	for s, want := range map[string]bool{"": false, "abc": false, "aaaa": false, "  处理举报 T-1 ": true, "abcd": true, "啊啊啊啊": false, strings.Repeat("ab", 100): true, strings.Repeat("ab", 101): false} {
		if validReason(s) != want {
			t.Errorf("validReason(%q) != %v", s, want)
		}
	}
}

func TestSensitiveGetPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("a sensitive GET route must not start")
		}
	}()
	checkRoute(route{method: "GET", path: "/x", perm: "user.read", sensitive: true})
}
