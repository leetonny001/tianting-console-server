package app

// businessRoutes 是管理后台第一批业务路由（PRD-admin 5.2、5.3 节）。只在管理空间注册。
func businessRoutes() []route {
	return []route{
		// 用户（CS-021、CS-022）
		{method: "GET", path: "/console/api/users", perm: "user.read", h: (*rc).listUsers},
		{method: "POST", path: "/console/api/users/import/validate", perm: "user.import", h: (*rc).validateUsers},
		{method: "POST", path: "/console/api/users/import", perm: "user.import", action: "user.import", h: (*rc).importUsers},
		{method: "POST", path: "/console/api/users/sessions/query", perm: "user.sessions", sensitive: true, action: "user.sessions.query", h: (*rc).queryUserSessions},
		{method: "GET", path: "/console/api/users/{id}", perm: "user.read", h: (*rc).getUser},
		{method: "POST", path: "/console/api/users/{id}/kick", perm: "user.kick", action: "user.kick", h: (*rc).kickUser},
		{method: "PUT", path: "/console/api/users/{id}/official", perm: "user.official", action: "user.official.set", h: (*rc).setOfficial},
		// 社交（CS-023）
		{method: "GET", path: "/console/api/users/{id}/friends", perm: "social.read", h: (*rc).listFriends},
		{method: "POST", path: "/console/api/friends/import/validate", perm: "social.write", h: (*rc).validateFriendsImport},
		{method: "POST", path: "/console/api/friends/import", perm: "social.write", stepUp: true, action: "friend.import", h: (*rc).importFriends},
		{method: "POST", path: "/console/api/friends/delete/validate", perm: "social.write", h: (*rc).validateFriendsDelete},
		{method: "POST", path: "/console/api/friends/delete", perm: "social.write", stepUp: true, action: "friend.delete", h: (*rc).deleteFriends},
		{method: "GET", path: "/console/api/settings/social", perm: "social.read", h: (*rc).getSocialSettings},
		{method: "PATCH", path: "/console/api/settings/social", perm: "social.settings", stepUp: true, action: "social.settings", h: (*rc).patchSocialSettings},
		// 群（CS-024、CS-025）
		{method: "GET", path: "/console/api/groups", perm: "group.read", h: (*rc).listGroups},
		{method: "POST", path: "/console/api/groups", perm: "group.write", action: "group.create", h: (*rc).createGroup},
		{method: "GET", path: "/console/api/groups/{id}", perm: "group.read", h: (*rc).getGroup},
		{method: "PATCH", path: "/console/api/groups/{id}", perm: "group.write", action: "group.update", h: (*rc).patchGroup},
		{method: "GET", path: "/console/api/groups/{id}/members", perm: "group.read", h: (*rc).listGroupMembers},
		{method: "POST", path: "/console/api/groups/{id}/members", perm: "group.write", action: "group.members.add", h: (*rc).addGroupMembers},
		{method: "DELETE", path: "/console/api/groups/{id}/members", perm: "group.write", action: "group.members.remove", h: (*rc).removeGroupMembers},
		{method: "PUT", path: "/console/api/groups/{id}/owner", perm: "group.owner", action: "group.owner.set", h: (*rc).setGroupOwner},
		{method: "POST", path: "/console/api/groups/{id}/dissolve", perm: "group.dissolve", stepUp: true, action: "group.dissolve", h: (*rc).dissolveGroup},
		// 元数据（CS-026）
		{method: "POST", path: "/console/api/messages/meta/query", perm: "msg.meta", sensitive: true, action: "msg.meta.query", h: (*rc).queryMeta},
	}
}

// RouteInfo 是路由表的公开信息：矩阵测试用同一份数据，新路由没有样本时测试失败（AC-ADM-05-1）。
type RouteInfo struct {
	Method, Path, Perm string
	StepUp             bool
	Action             string
}

// BusinessRouteInfo 返回管理后台业务路由的列表。
func BusinessRouteInfo() []RouteInfo {
	rs := businessRoutes()
	out := make([]RouteInfo, 0, len(rs))
	for _, r := range rs {
		out = append(out, RouteInfo{r.method, r.path, r.perm, r.stepUp, r.action})
	}
	return out
}
