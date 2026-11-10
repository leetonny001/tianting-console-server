package app

import (
	"encoding/json"
	"strings"
	"unicode/utf8"

	"tianting/console/internal/apierr"
	"tianting/console/internal/audit"
)

// CS-024、CS-025：群。

const maxMemberBody = 512 << 10 // 2000 个 userId

// groupListFields 是群列表每一行放出去的字段：tianting-admin Groups 页（GroupRow）读的群 ID、群名、类型、群主、成员数、
// 新成员看历史、创建时间、解散时间（没有 = 正常）。
var groupListFields = []string{"groupId", "name", "type", "owner", "memberCount", "historyVisible", "createdAt", "dissolvedAt"}

// groupMemberFields 是群成员每一行放出去的字段：GroupDetail 页的成员表（MemberRow）读的 userId、角色、入群时间、
// 群内禁言（没有这个键 = 没有禁言，null = 永久，MutedBadge 和"解除 / 群内禁言"按钮按它）。
var groupMemberFields = []string{"userId", "role", "joinedAt", "mutedUntil"}

func (c *rc) listGroups() {
	if q, ok := c.listParams("includeDissolved", "cursor"); ok {
		c.imList("/admin/groups", q, "groups", groupListFields)
	}
}

func (c *rc) groupPath() (string, string, bool) {
	id := c.r.PathValue("id")
	if !validID(id) {
		c.fail(apierr.New(apierr.InvalidID, "invalid groupId"))
		return "", "", false
	}
	return id, "/admin/groups/" + pathID(id), true
}

// getGroup：成员走分页接口，详情不带 2000 人的列表。
func (c *rc) getGroup() {
	_, path, ok := c.groupPath()
	if !ok {
		return
	}
	var out map[string]any
	if err := c.im("GET", path, nil, nil, &out); err != nil {
		c.failErr("get group", err)
		return
	}
	delete(out, "members")
	c.ok(out)
}

func (c *rc) createGroup() {
	var req struct {
		GroupID        string   `json:"groupId"`
		Name           string   `json:"name"`
		Members        []string `json:"members"`
		HistoryVisible bool     `json:"historyVisible"`
		Owner          *string  `json:"owner"`
	}
	if !c.readJSONLimit(&req, maxMemberBody) {
		return
	}
	if !validID(req.GroupID) || strings.HasPrefix(req.GroupID, "ug-") {
		c.fail(apierr.New(apierr.InvalidID, "invalid groupId"))
		return
	}
	members := dedupeIDs(req.Members)
	if !c.checkIDs(members) {
		return
	}
	if len(members) > maxGroupMembers {
		c.fail(apierr.New(apierr.MemberLimit, "a group can have at most 2000 members"))
		return
	}
	body := map[string]any{"groupId": req.GroupID, "name": req.Name, "members": members, "historyVisible": req.HistoryVisible}
	params := map[string]any{"memberCount": len(members), "historyVisible": req.HistoryVisible}
	if req.Owner != nil {
		body["owner"] = *req.Owner
		params["owner"] = *req.Owner
	}
	c.audited("group.create", audit.NewTarget("group", req.GroupID), params, "", func() (any, error) {
		return struct{}{}, c.im("POST", "/admin/groups", nil, body, nil)
	})
}

// listGroupMembers：每页 50，prefix 是 userId 前缀。
func (c *rc) listGroupMembers() {
	_, path, ok := c.groupPath()
	if !ok {
		return
	}
	q, ok := c.listParams("cursor", "prefix")
	if !ok {
		return
	}
	q.Set("limit", "50")
	c.imList(path+"/members", q, "members", groupMemberFields)
}

// addGroupMembers：超过 2000 人一个都不加。检查在 intent 之后：被拒绝的尝试也留痕。
func (c *rc) addGroupMembers() {
	id, path, ok := c.groupPath()
	if !ok {
		return
	}
	var req struct {
		UserIDs []string `json:"userIds"`
	}
	if !c.readJSONLimit(&req, maxMemberBody) {
		return
	}
	users := dedupeIDs(req.UserIDs)
	if !c.checkIDs(users) {
		return
	}
	if len(users) == 0 {
		c.fail(apierr.New(apierr.BadRequest, "userIds is required"))
		return
	}
	batches := chunks(users, imBatchSize)
	params := map[string]any{"count": len(users), "batches": len(batches)}
	c.audited("group.members.add", audit.NewTarget("group", id), params, "", func() (any, error) {
		var g struct {
			MemberCount int `json:"memberCount"`
		}
		if err := c.imDo(c.requestID+".count", "GET", path, nil, nil, &g); err != nil {
			return nil, err
		}
		if g.MemberCount+len(users) > maxGroupMembers {
			return nil, apierr.New(apierr.MemberLimit, "a group can have at most 2000 members")
		}
		return c.runBatches(len(batches), func(i int, rid string) error {
			return c.imDo(rid, "POST", path+"/members", nil, map[string]any{"members": batches[i-1]}, nil)
		})
	})
}

func (c *rc) removeGroupMembers() {
	id, path, ok := c.groupPath()
	if !ok {
		return
	}
	var req struct {
		UserIDs []string `json:"userIds"`
		reasonBody
	}
	if !c.readJSONLimit(&req, maxMemberBody) {
		return
	}
	reason, ok := c.reasonTicket(req.Reason, req.Ticket)
	if !ok {
		return
	}
	users := dedupeIDs(req.UserIDs)
	if !c.checkIDs(users) {
		return
	}
	if len(users) == 0 {
		c.fail(apierr.New(apierr.BadRequest, "userIds is required"))
		return
	}
	batches := chunks(users, imBatchSize)
	c.ticket = req.Ticket
	target := audit.NewTarget("user", users...)
	params := map[string]any{"groupId": id, "count": len(users), "batches": len(batches)}
	c.audited("group.members.remove", target, params, reason, func() (any, error) {
		return c.runBatches(len(batches), func(i int, rid string) error {
			return c.imDo(rid, "DELETE", path+"/members", nil, map[string]any{"members": batches[i-1]}, nil)
		})
	})
}

// patchGroup：审计记旧值 → 新值。
func (c *rc) patchGroup() {
	id, path, ok := c.groupPath()
	if !ok {
		return
	}
	var req struct {
		Name           *string `json:"name"`
		HistoryVisible *bool   `json:"historyVisible"`
		Notice         *string `json:"notice"`
	}
	if !c.readJSON(&req) {
		return
	}
	if req.Name == nil && req.HistoryVisible == nil && req.Notice == nil {
		c.fail(apierr.New(apierr.BadRequest, "nothing to change"))
		return
	}
	var cur map[string]any
	if err := c.im("GET", path, nil, nil, &cur); err != nil {
		c.failErr("patch group", err)
		return
	}
	short := func(v any) any {
		if s, isStr := v.(string); isStr && utf8.RuneCountInString(s) > 200 {
			return string([]rune(s)[:200]) + "…"
		}
		return v
	}
	body, params := map[string]any{}, map[string]any{}
	set := func(k string, v any) {
		body[k] = v
		params[k] = describeChange(short(cur[k]), short(v))
	}
	if req.Name != nil {
		set("name", *req.Name)
	}
	if req.HistoryVisible != nil {
		set("historyVisible", *req.HistoryVisible)
	}
	if req.Notice != nil {
		set("notice", *req.Notice)
	}
	c.audited("group.update", audit.NewTarget("group", id), params, "", func() (any, error) {
		return struct{}{}, c.im("PATCH", path, nil, body, nil)
	})
}

// setGroupOwner：userId 为 null 收回群主。
func (c *rc) setGroupOwner() {
	id, path, ok := c.groupPath()
	if !ok {
		return
	}
	var req struct {
		UserID *string `json:"userId"`
		reasonBody
	}
	if !c.readJSON(&req) {
		return
	}
	reason, ok := c.reasonTicket(req.Reason, req.Ticket)
	if !ok {
		return
	}
	action := "group.owner.unset"
	params := map[string]any{}
	var owner json.RawMessage = json.RawMessage("null")
	if req.UserID != nil {
		if !validID(*req.UserID) {
			c.fail(apierr.New(apierr.InvalidID, "invalid userId"))
			return
		}
		action = "group.owner.set"
		params["owner"] = *req.UserID
		owner, _ = json.Marshal(*req.UserID)
	}
	c.ticket = req.Ticket
	c.audited(action, audit.NewTarget("group", id), params, reason, func() (any, error) {
		return struct{}{}, c.im("PATCH", path, nil, map[string]any{"owner": owner}, nil)
	})
}

func (c *rc) dissolveGroup() {
	id, path, ok := c.groupPath()
	if !ok {
		return
	}
	var req struct {
		ConfirmGroupID string `json:"confirmGroupId"`
		reasonBody
	}
	if !c.readJSON(&req) {
		return
	}
	reason, ok := c.reasonTicket(req.Reason, req.Ticket)
	if !ok {
		return
	}
	if req.ConfirmGroupID != id {
		c.fail(&apierr.Error{Code: apierr.BadRequest, Msg: "confirmGroupId must equal the group ID", Reason: "confirmMismatch"})
		return
	}
	c.ticket = req.Ticket
	c.audited("group.dissolve", audit.NewTarget("group", id), nil, reason, func() (any, error) {
		return struct{}{}, c.im("DELETE", path, nil, nil, nil)
	})
}
