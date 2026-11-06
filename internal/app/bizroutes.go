package app

// businessRoutes 是管理后台业务路由（PRD-admin 5.2、5.3 节）。只在管理空间注册。
func businessRoutes() []route {
	return []route{
		// 数据概览（CS-060）：只读、不写审计。首页的定时刷新带 X-Console-Background，不续期会话（CS-009）。
		{method: "GET", path: "/console/api/stats", perm: "stats.read", h: (*rc).getStats},
		// 用户（CS-021、CS-022）
		{method: "GET", path: "/console/api/users", perm: "user.read", h: (*rc).listUsers},
		{method: "POST", path: "/console/api/users/import/validate", perm: "user.import", h: (*rc).validateUsers},
		{method: "POST", path: "/console/api/users/import", perm: "user.import", action: "user.import", h: (*rc).importUsers},
		{method: "POST", path: "/console/api/users/sessions/query", perm: "user.sessions", sensitive: true, action: "user.sessions.query", h: (*rc).queryUserSessions},
		{method: "POST", path: "/console/api/users/convs/query", perm: "msg.meta", sensitive: true, action: actionUserConvs, h: (*rc).queryUserConvs},
		{method: "GET", path: "/console/api/users/{id}", perm: "user.read", h: (*rc).getUser},
		// 用户所在群（CS-063）：只读、不写审计，和详情、好友列表一样路径里带 userId。
		{method: "GET", path: "/console/api/users/{id}/groups", perm: "group.read", h: (*rc).listUserGroups},
		{method: "POST", path: "/console/api/users/{id}/kick", perm: "user.kick", action: "user.kick", h: (*rc).kickUser},
		{method: "PUT", path: "/console/api/users/{id}/official", perm: "user.official", action: "user.official.set", h: (*rc).setOfficial},
		// 邀请码（CS-200，PRD-chat F-ACC-09）。明文只在生成响应里出现一次，审计不记明文。
		{method: "POST", path: "/console/api/invites", perm: "account.invite", action: actionInviteCreate, h: (*rc).createInvites},
		{method: "GET", path: "/console/api/invites", perm: "account.invite", h: (*rc).listInvites},
		{method: "POST", path: "/console/api/invites/{id}/disable", perm: "account.invite", action: actionInviteDisable, h: (*rc).disableInvite},
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
		// 第二批（CS-040 ～ CS-043）
		{method: "POST", path: "/console/api/users/{id}/ban", perm: "user.ban", stepUp: true, action: "user.ban", h: (*rc).banUser},
		{method: "POST", path: "/console/api/users/{id}/unban", perm: "user.ban", stepUp: true, action: "user.unban", h: (*rc).unbanUser},
		{method: "POST", path: "/console/api/mutes", perm: "mute.write", action: "mute.set", h: (*rc).setMute},
		{method: "POST", path: "/console/api/mutes/release", perm: "mute.write", action: "mute.release", h: (*rc).releaseMute},
		{method: "POST", path: "/console/api/messages/delete", perm: "msg.delete", stepUp: true, action: "msg.delete", h: (*rc).deleteMessages},
		// 这两个路由的权限按请求内容再判断（grantPerm）：单聊 msg.read.c2c、隔离原文 msg.quarantine.read。
		{method: "POST", path: "/console/api/messages/grants", perm: "msg.read.group", sensitive: true, action: "msg.read.grant", h: (*rc).createMsgGrant},
		{method: "POST", path: "/console/api/messages/body", perm: "msg.read.group", sensitive: true, action: "msg.read.page", h: (*rc).readMessageBody},
		// 系统通知（CS-044、CS-045）
		{method: "GET", path: "/console/api/push/templates", perm: "push.user", h: (*rc).listPushTemplates},
		{method: "POST", path: "/console/api/push/targets/validate", perm: "push.user", h: (*rc).validatePushTargets},
		{method: "POST", path: "/console/api/push/preview", perm: "push.user", h: (*rc).previewPush},
		{method: "POST", path: "/console/api/push/user", perm: "push.user", action: actionPushUser, h: (*rc).pushToUsers},
		{method: "GET", path: "/console/api/push/all/drafts", perm: "push.all.request", h: (*rc).listMyDrafts},
		{method: "POST", path: "/console/api/push/all/drafts", perm: "push.all.request", action: actionPushRequest, h: (*rc).createPushDraft},
		{method: "GET", path: "/console/api/push/all/drafts/pending", perm: "push.all.approve", h: (*rc).listPendingDrafts},
		{method: "POST", path: "/console/api/push/all/drafts/{id}/approve", perm: "push.all.approve", stepUp: true, action: actionPushApprove, h: (*rc).approvePushDraft},
		{method: "GET", path: "/console/api/push/records", perm: "push.records.read", h: (*rc).listPushRecords},
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
