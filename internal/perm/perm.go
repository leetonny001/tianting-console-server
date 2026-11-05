// Package perm 是权限点注册表（PRD-admin F-CON-06、第 5 节；PRD-ops F-OPS-02）。权限只在服务端判断。
package perm

import (
	"slices"
	"sort"
)

// 只需要登录的路由用这个标记；路由必须显式声明，未声明的启动失败。
const LoginOnly = "@login"

// Space 是一个空间的角色和权限点。
type Space struct {
	Name       string
	SuperAdmin string              // 空间超管角色
	Auditor    string              // 审计员角色：收安全通知
	Roles      map[string][]string // 角色 → 权限点
	Exclusive  []string            // 互斥角色：不能和任何其他角色叠加
	Sensitive  []string            // 敏感角色：授予时通知审计员
	ManagePerm string              // 账号管理权限点
	Emergency  string              // 应急授权权限点；空表示这个空间没有应急授权
	AuditPerm  string              // 查看审计的权限点
	AuditAll   bool                // 审计员可以选"全部空间"（F-CON-09 规则 1：只有运维空间）
	// ApprovalRoles 是授予后要第二个超管批准才生效的角色（PRD-ops F-OPS-02 规则 6）。
	ApprovalRoles []string
}

// Admin 是管理空间（第 5.2 节）。
var Admin = Space{
	Name: "admin", SuperAdmin: "super_admin", Auditor: "auditor", ManagePerm: "admin.manage", Emergency: "admin.emergency", AuditPerm: "audit.read",
	Exclusive: []string{"auditor"}, Sensitive: []string{"moderator", "auditor", "super_admin"},
	Roles: map[string][]string{
		"super_admin": {"user.read", "social.read", "group.read", "admin.manage", "admin.emergency", "push.all.approve", "push.records.read", "stats.read"},
		"operator":    {"user.read", "user.import", "user.official", "social.read", "social.write", "social.settings", "group.read", "group.write", "group.owner", "group.dissolve", "push.user", "push.all.request", "stats.read"},
		"support":     {"user.read", "user.kick", "user.sessions", "social.read", "group.read", "msg.meta", "mute.write"},
		"moderator":   {"user.read", "user.kick", "user.sessions", "social.read", "group.read", "group.dissolve", "msg.meta", "mute.write", "user.ban", "msg.delete", "msg.read.group", "msg.read.c2c", "msg.quarantine.read"},
		"auditor":     {"audit.read", "push.records.read"},
	},
}

// Ops 是运维空间（PRD-ops F-OPS-02，第一批）。没有应急授权。
var Ops = Space{
	Name: "ops", SuperAdmin: "ops_superadmin", Auditor: "ops_auditor", ManagePerm: "ops.account.manage", AuditPerm: "ops.audit.read", AuditAll: true, ApprovalRoles: []string{"ops_engineer"},
	Exclusive: []string{"ops_superadmin", "ops_auditor"}, Sensitive: []string{"ops_superadmin", "ops_engineer", "ops_auditor"},
	Roles: map[string][]string{
		"ops_viewer":     {"ops.overview.read", "ops.config.read"},
		"ops_engineer":   {"ops.overview.read", "ops.config.read", "ops.troubleshoot", "ops.silence.write"},
		"ops_auditor":    {"ops.audit.read"},
		"ops_superadmin": {"ops.account.manage"},
	},
}

// For 返回空间的定义。
func For(name string) Space {
	if name == Ops.Name {
		return Ops
	}
	return Admin
}

// Perms 返回角色集合的权限点并集，排序后返回。
func (s Space) Perms(roles []string) []string {
	seen := map[string]bool{}
	for _, r := range roles {
		for _, p := range s.Roles[r] {
			seen[p] = true
		}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Has 判断角色集合是否有权限点。
func (s Space) Has(roles []string, perm string) bool {
	if perm == LoginOnly {
		return true
	}
	for _, r := range roles {
		if slices.Contains(s.Roles[r], perm) {
			return true
		}
	}
	return false
}

// ValidRole 判断角色是否属于这个空间。
func (s Space) ValidRole(role string) bool {
	_, ok := s.Roles[role]
	return ok
}

// RolesConflict 判断角色组合是否违反职责分离。
func (s Space) RolesConflict(roles []string) bool {
	if len(roles) < 2 {
		return false
	}
	for _, r := range roles {
		if slices.Contains(s.Exclusive, r) {
			return true
		}
	}
	return false
}
