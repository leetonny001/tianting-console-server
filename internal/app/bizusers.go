package app

import (
	"encoding/json"
	"net/http"
	"net/url"

	"tianting/console/internal/apierr"
	"tianting/console/internal/audit"
)

// statsFields、statsOnlineFields 是首页数据概览（tianting-admin DataOverview 的 Stats）读的字段（console-chat 第 22 条）：
// 在线连接数（总数、按平台、partial、scope：B6 之前只覆盖接收请求的节点，页面靠这两个标注）、今日新增用户、今日消息数、群总数、
// 今日起点、数据时间。byPlatform 的键是平台名，只保留值是数字的项。
var (
	statsFields       = []string{"online", "newUsersToday", "messagesToday", "groupsTotal", "dayStart", "serverTime"}
	statsOnlineFields = []string{"total", "byPlatform", "partial", "scope"}
)

// getStats 代理 GET /admin/stats（G-ADM-17），按白名单输出。
func (c *rc) getStats() {
	var raw map[string]json.RawMessage
	if err := c.im(http.MethodGet, "/admin/stats", nil, nil, &raw); err != nil {
		c.failErr("stats", err)
		return
	}
	out := pickFields(raw, statsFields)
	if _, listed := out["online"]; listed && string(raw["online"]) != "null" { // 白名单里有才处理里面一层
		var online map[string]json.RawMessage
		if err := json.Unmarshal(raw["online"], &online); err != nil {
			c.failErr("stats online", err)
			return
		}
		o := pickFields(online, statsOnlineFields)
		if _, listed := o["byPlatform"]; listed && string(online["byPlatform"]) != "null" {
			var by map[string]json.RawMessage
			if err := json.Unmarshal(online["byPlatform"], &by); err != nil {
				c.failErr("stats byPlatform", err)
				return
			}
			counts := make(map[string]float64, len(by))
			for k, n := range by {
				var f float64
				if json.Unmarshal(n, &f) == nil {
					counts[k] = f
				}
			}
			o["byPlatform"] = counts
		}
		out["online"] = o
	}
	c.ok(out)
}

// CS-021：用户。

func (c *rc) listUsers() {
	q, ok := c.listParams("official", "cursor")
	if !ok {
		return
	}
	if q.Get("q") == "" && q.Get("official") != "true" {
		c.fail(apierr.New(apierr.BadRequest, "enter a keyword or filter by official accounts"))
		return
	}
	var raw struct {
		Users      []map[string]json.RawMessage `json:"users"`
		NextCursor json.RawMessage              `json:"nextCursor"`
	}
	if err := c.im(http.MethodGet, "/admin/users", q, nil, &raw); err != nil {
		c.failErr("list users", err)
		return
	}
	users := make([]map[string]any, 0, len(raw.Users))
	for _, u := range raw.Users {
		row, err := pickUser(u, userListFields, userListBanFields)
		if err != nil {
			c.failErr("list users ban", err)
			return
		}
		users = append(users, row)
	}
	out := map[string]any{"users": users}
	if raw.NextCursor != nil {
		out["nextCursor"] = raw.NextCursor
	}
	c.ok(out)
}

func (c *rc) userPath() (string, string, bool) {
	id := c.r.PathValue("id")
	if !validID(id) {
		c.fail(apierr.New(apierr.InvalidID, "invalid userId"))
		return "", "", false
	}
	return id, "/admin/users/" + pathID(id), true
}

// userDetailFields 是用户详情从 im-server 资料里放出去的字段（console-chat 问题 20：console 是白名单结构，不透传）。
// 依据是后台页面 tianting-admin 的 UserRow（src/api/types.ts）和 UserDetail 页：昵称、头像、资料创建时间、官方账号、在线、
// 封禁（第二批，null = 没有封禁）、禁言（没有这个键 = 没有禁言，null = 永久）。account、accountUnavailable 是 console 自己加的（CS-200）。
// 键在不在、值是不是 null 都有含义，所以按原始 JSON 逐个挑，不经过 Go 结构体。
var userDetailFields = []string{"userId", "nickname", "avatar", "createdAt", "official", "online", "ban", "mutedUntil"}

// userBanFields 是封禁对象里放出去的字段（UserRow.ban：到期、理由、操作人、时间）。
var userBanFields = []string{"until", "reason", "by", "at"}

// userListFields、userListBanFields 是用户列表每一行放出去的字段（console-chat 问题 20 的列表部分）：
// 依据是 tianting-admin 的 Users 页实际读的 UserRow 字段（用户、昵称、资料创建时间、在线、官方、封禁到期、禁言）。
// 列表不显示头像、封禁理由和操作人，这些只在详情里有。外层只有 users 和翻页用的 nextCursor（useCursorList）。
var (
	userListFields    = []string{"userId", "nickname", "createdAt", "online", "official", "ban", "mutedUntil"}
	userListBanFields = []string{"until"}
)

// pickUser 按白名单挑一个用户对象；ban 不是 null 时里面也按白名单挑。ban 不是对象时报错：不能当成"没有封禁"显示。
func pickUser(raw map[string]json.RawMessage, fields, banFields []string) (map[string]any, error) {
	out := pickFields(raw, fields)
	if _, listed := out["ban"]; !listed {
		return out, nil
	}
	if ban := raw["ban"]; string(ban) != "null" {
		var b map[string]json.RawMessage
		if err := json.Unmarshal(ban, &b); err != nil {
			return nil, err
		}
		out["ban"] = pickFields(b, banFields)
	}
	return out, nil
}

// pickFields 只保留 keys 里的键，值原样（含 null）。
func pickFields(in map[string]json.RawMessage, keys []string) map[string]any {
	out := make(map[string]any, len(keys))
	for _, k := range keys {
		if v, ok := in[k]; ok {
			out[k] = v
		}
	}
	return out
}

// getUser 是用户详情：im-server 的资料（白名单）加上账号信息（CS-200）。
func (c *rc) getUser() {
	id, path, ok := c.userPath()
	if !ok {
		return
	}
	var raw map[string]json.RawMessage
	if err := c.im(http.MethodGet, path, nil, nil, &raw); err != nil {
		c.failErr("get user", err)
		return
	}
	out, err := pickUser(raw, userDetailFields, userBanFields)
	if err != nil {
		c.failErr("get user ban", err)
		return
	}
	c.mergeAccountInfo(id, out)
	c.ok(out)
}

type reasonBody struct {
	Reason string `json:"reason"`
	Ticket string `json:"ticket"`
}

func (c *rc) kickUser() {
	id, path, ok := c.userPath()
	if !ok {
		return
	}
	var req reasonBody
	if !c.readJSON(&req) {
		return
	}
	reason, ok := c.reasonTicket(req.Reason, req.Ticket)
	if !ok {
		return
	}
	c.ticket = req.Ticket
	c.audited("user.kick", audit.NewTarget("user", id), nil, reason, func() (any, error) {
		return struct{}{}, c.im("POST", path+"/force-logout", nil, struct{}{}, nil)
	})
}

// sessionsDaily、sessionsPerMinute：在线设备查看的上限（F-ADM-14）。
const (
	sessionsDaily     = 50
	sessionsPerMinute = 30
)

// queryUserSessions 用 POST：userId 和理由不进 URL、不进访问日志（AC-ADM-14-5）。
func (c *rc) queryUserSessions() {
	var req struct {
		UserID string `json:"userId"`
		reasonBody
	}
	if !c.readJSON(&req) {
		return
	}
	if !validID(req.UserID) {
		c.fail(apierr.New(apierr.InvalidID, "invalid userId"))
		return
	}
	reason, ok := c.reasonTicket(req.Reason, req.Ticket)
	if !ok {
		return
	}
	if !c.minuteRate("user.sessions", sessionsPerMinute) || !c.dailyQuota("user.sessions", req.UserID, sessionsDaily) {
		return
	}
	c.ticket = req.Ticket
	c.audited("user.sessions.query", audit.NewTarget("user", req.UserID), nil, reason, func() (any, error) {
		var out struct {
			Sessions []map[string]any `json:"sessions"`
			Partial  bool             `json:"partial"`
			Scope    string           `json:"scope"`
		}
		if err := c.im("POST", "/admin/users/sessions/query", nil, map[string]any{"userId": req.UserID}, &out); err != nil {
			return nil, err
		}
		c.resultParams = map[string]any{"count": len(out.Sessions), "partial": out.Partial}
		return out, nil
	})
}

// friend 是好友列表的一项。独立类型：im-server 将来加字段也不会透传，备注永远出不去。
type friend struct {
	UserID    string `json:"userId"`
	Source    string `json:"source"`
	CreatedAt int64  `json:"createdAt"`
}

func (c *rc) listFriends() {
	_, path, ok := c.userPath()
	if !ok {
		return
	}
	q := url.Values{"limit": {"100"}}
	if v := c.r.URL.Query().Get("cursor"); v != "" {
		q.Set("cursor", v)
	}
	var out struct {
		Friends    []friend `json:"friends"`
		NextCursor string   `json:"nextCursor"`
	}
	if err := c.im(http.MethodGet, path+"/friends", q, nil, &out); err != nil {
		c.failErr("list friends", notAvailable(err))
		return
	}
	if out.Friends == nil {
		out.Friends = []friend{}
	}
	c.ok(out)
}

func (c *rc) setOfficial() {
	id, path, ok := c.userPath()
	if !ok {
		return
	}
	var req struct {
		Official *bool `json:"official"`
		reasonBody
	}
	if !c.readJSON(&req) {
		return
	}
	if req.Official == nil {
		c.fail(apierr.New(apierr.BadRequest, "official is required"))
		return
	}
	reason, ok := c.reasonTicket(req.Reason, req.Ticket)
	if !ok {
		return
	}
	action := "user.official.unset"
	if *req.Official {
		action = "user.official.set"
	}
	c.ticket = req.Ticket
	c.audited(action, audit.NewTarget("user", id), nil, reason, func() (any, error) {
		var out map[string]any
		err := c.im("PUT", path+"/official", nil, map[string]any{"official": *req.Official}, &out)
		return out, notAvailable(err)
	})
}
