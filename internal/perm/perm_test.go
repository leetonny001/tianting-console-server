package perm

import (
	"slices"
	"testing"
)

// 第 5.2 节矩阵逐行（第一批）。
func TestAdminMatrix(t *testing.T) {
	for perm, want := range map[string][]string{
		"user.read":           {"super_admin", "operator", "support", "moderator"},
		"user.import":         {"operator"},
		"user.kick":           {"support", "moderator"},
		"user.sessions":       {"support", "moderator"},
		"user.official":       {"operator"},
		"social.read":         {"super_admin", "operator", "support", "moderator"},
		"social.write":        {"operator"},
		"social.settings":     {"operator"},
		"group.read":          {"super_admin", "operator", "support", "moderator"},
		"group.write":         {"operator"},
		"group.owner":         {"operator"},
		"group.dissolve":      {"operator", "moderator"},
		"msg.meta":            {"support", "moderator"},
		"mute.write":          {"support", "moderator"},
		"user.ban":            {"moderator"},
		"msg.delete":          {"moderator"},
		"msg.read.group":      {"moderator"},
		"msg.read.c2c":        {"moderator"},
		"msg.quarantine.read": {"moderator"},
		"audit.read":          {"auditor"},
		"admin.manage":        {"super_admin"},
		"admin.emergency":     {"super_admin"},
	} {
		var got []string
		for r := range Admin.Roles {
			if Admin.Has([]string{r}, perm) {
				got = append(got, r)
			}
		}
		slices.Sort(got)
		w := slices.Clone(want)
		slices.Sort(w)
		if !slices.Equal(got, w) {
			t.Errorf("%s: %v, want %v", perm, got, w)
		}
	}
}

func TestUnionAndConflict(t *testing.T) {
	p := Admin.Perms([]string{"support", "operator"})
	if !slices.Contains(p, "user.kick") || !slices.Contains(p, "user.import") {
		t.Errorf("union = %v", p)
	}
	if !Admin.RolesConflict([]string{"support", "auditor"}) || Admin.RolesConflict([]string{"auditor"}) || Admin.RolesConflict([]string{"support", "operator"}) {
		t.Error("admin conflicts")
	}
	if !Ops.RolesConflict([]string{"ops_engineer", "ops_superadmin"}) || !Ops.RolesConflict([]string{"ops_engineer", "ops_auditor"}) || Ops.RolesConflict([]string{"ops_viewer", "ops_engineer"}) {
		t.Error("ops conflicts")
	}
	if Ops.Emergency != "" || Admin.Emergency == "" {
		t.Error("emergency grants are admin-only")
	}
	if Admin.ValidRole("ops_engineer") || Ops.ValidRole("support") {
		t.Error("roles leak across spaces")
	}
	if !Admin.Has(nil, LoginOnly) {
		t.Error("login only")
	}
}
