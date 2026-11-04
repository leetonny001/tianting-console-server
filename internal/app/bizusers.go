package app

import (
	"net/http"
	"net/url"

	"tianting/console/internal/apierr"
	"tianting/console/internal/audit"
)

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
	c.imRead("/admin/users", q)
}

func (c *rc) userPath() (string, string, bool) {
	id := c.r.PathValue("id")
	if !validID(id) {
		c.fail(apierr.New(apierr.InvalidID, "invalid userId"))
		return "", "", false
	}
	return id, "/admin/users/" + pathID(id), true
}

func (c *rc) getUser() {
	if _, path, ok := c.userPath(); ok {
		c.imRead(path, nil)
	}
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
