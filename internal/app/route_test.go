package app

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
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

var userCredentialWords = regexp.MustCompile(`(?i)password|recovery|reset`)

// TC-ACC-05-08（AC-ACC-05-9，console 路由）：路径带这些词的只有后台账号自己的 3 个接口，业务路由和权限点里一个都没有。
func TestTC_ACC_05_08_NoUserCredentialRoute(t *testing.T) {
	own := map[string]bool{"POST /console/api/me/password": true, "POST /console/api/me/recovery-codes": true, "POST /console/api/accounts/{id}/reset": true}
	a := &App{}
	seen := map[string]bool{}
	for _, ps := range []perm.Space{perm.Admin, perm.Ops} {
		for _, rt := range a.apiRoutes(ps) {
			key := rt.method + " " + rt.path
			if !userCredentialWords.MatchString(key) {
				continue
			}
			seen[key] = true
			if !own[key] {
				t.Errorf("route may change credentials: %s", key)
			}
		}
		for role, perms := range ps.Roles {
			for _, p := range perms {
				if userCredentialWords.MatchString(p) {
					t.Errorf("%s has permission %s", role, p)
				}
			}
		}
	}
	for key := range own {
		if !seen[key] {
			t.Errorf("the list of own-account routes is stale: %s", key)
		}
	}
	for _, rt := range BusinessRouteInfo() {
		if userCredentialWords.MatchString(rt.Path) || userCredentialWords.MatchString(rt.Action) {
			t.Errorf("business route: %s %s", rt.Method, rt.Path)
		}
	}
}

// TC-ACC-05-08（请求字段和上游调用）：业务代码的请求字段、im-server 路径都不带这些词；后台账号自己的 3 个接口不调用 im-server。
func TestTC_ACC_05_08_SourceHasNoUserCredentialCalls(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("%v %v", files, err)
	}
	ownHandlers := map[string]bool{"changePassword": true, "regenerateRecovery": true, "resetAccount": true}
	found := map[string]bool{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.BasicLit:
				// im-server 路径（整个包）；业务文件里的 JSON 字段。
				if v.Kind == token.STRING && userCredentialWords.MatchString(v.Value) {
					if strings.Contains(v.Value, "/admin/") || (strings.HasPrefix(name, "biz") && strings.Contains(v.Value, "json:")) {
						t.Errorf("%s: %s", fset.Position(v.Pos()), v.Value)
					}
				}
			case *ast.FuncDecl:
				if ownHandlers[v.Name.Name] {
					found[v.Name.Name] = true
					ast.Inspect(v.Body, func(m ast.Node) bool {
						if s, ok := m.(*ast.SelectorExpr); ok && (s.Sel.Name == "im" || s.Sel.Name == "imDo" || s.Sel.Name == "IM" || s.Sel.Name == "imList") {
							t.Errorf("%s calls im-server", v.Name.Name)
						}
						return true
					})
				}
			}
			return true
		})
	}
	if len(found) != len(ownHandlers) {
		t.Errorf("handlers found: %v", found)
	}
}
