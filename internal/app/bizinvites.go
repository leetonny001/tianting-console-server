package app

import (
	"errors"
	"net/http"
	"strconv"

	"tianting/console/internal/apierr"
	"tianting/console/internal/audit"
	"tianting/console/internal/imclient"
)

// CS-200：邀请码（PRD-chat F-ACC-09）和用户详情的账号信息（规则 5）。

// 动作名不能用 account. 开头：那是"只改 console 自己的库"的动作，
// 对账不查 im-server（localOnlyAction），404 还会记成 denied。邀请码是 im-server 的写操作，要能对账。
const (
	actionInviteCreate  = "invite.create"
	actionInviteDisable = "invite.disable"

	invitesPath         = "/admin/invites"
	inviteDefaultLimit  = "50"
	auditInviteIDsLimit = 50 // 和 audit 的目标上限一致（F-CON-08 规则 2）：超过时只记数量和前 50 个
)

// invite 是列表的一项。独立类型：没有 code，im-server 多返回的字段也不会透传。
type invite struct {
	InviteID     string `json:"inviteId"`
	CodeLast4    string `json:"codeLast4"`
	MaxUses      int    `json:"maxUses"`
	UsedCount    int    `json:"usedCount"`
	ExpiresAt    int64  `json:"expiresAt"`
	Note         string `json:"note,omitempty"`
	CreatedBy    string `json:"createdBy,omitempty"`
	CreatedAt    int64  `json:"createdAt"`
	DisabledAt   int64  `json:"disabledAt,omitempty"`
	AutoDisabled bool   `json:"autoDisabled,omitempty"`
}

// createdInvite 是生成响应的一项：明文只在这里出现一次（规则 1）。
type createdInvite struct {
	invite
	Code string `json:"code"`
}

// createInvites 代理 POST /admin/invites。数量和 maxUses 的上限由 im-server 判断，4131、4000 原样透传（AC-ACC-09-7）。
func (c *rc) createInvites() {
	var req struct {
		Count     int    `json:"count,omitempty"`
		MaxUses   int    `json:"maxUses"`
		ExpiresAt int64  `json:"expiresAt"`
		Note      string `json:"note,omitempty"`
	}
	if !c.readJSON(&req) {
		return
	}
	// 审计不记明文（规则 2）。备注是自由文本，可能被人粘贴邀请码，也不记原文。
	params := map[string]any{"count": max(req.Count, 1), "maxUses": req.MaxUses, "expiresAt": req.ExpiresAt, "hasNote": req.Note != ""}
	c.audited(actionInviteCreate, audit.Target{Type: "invite"}, params, "", func() (any, error) {
		var out struct {
			Invites []createdInvite `json:"invites"`
		}
		if err := c.im(http.MethodPost, invitesPath, nil, req, &out); err != nil {
			return nil, notAvailable(err)
		}
		ids := make([]string, 0, min(len(out.Invites), auditInviteIDsLimit))
		for _, inv := range out.Invites[:min(len(out.Invites), auditInviteIDsLimit)] {
			ids = append(ids, inv.InviteID)
		}
		c.resultParams = map[string]any{"count": len(out.Invites), "inviteIds": ids}
		return out, nil
	})
}

// listInvites 代理 GET /admin/invites，只读、不写审计。按生成时间倒序；im-server 没有 nextCursor，这里按"满一页"算。
func (c *rc) listInvites() {
	q, ok := c.listParams()
	if !ok {
		return
	}
	q.Del("q")
	if q.Get("limit") == "" {
		q.Set("limit", inviteDefaultLimit)
	}
	if v := c.r.URL.Query().Get("cursor"); v != "" {
		if !validID(v) {
			c.fail(apierr.New(apierr.InvalidID, "invalid cursor"))
			return
		}
		q.Set("after", v)
	}
	var out struct {
		Invites    []invite `json:"invites"`
		NextCursor string   `json:"nextCursor,omitempty"`
	}
	if err := c.im(http.MethodGet, invitesPath, q, nil, &out); err != nil {
		c.failErr("list invites", notAvailable(err))
		return
	}
	if out.Invites == nil {
		out.Invites = []invite{}
	}
	if n := len(out.Invites); n > 0 && q.Get("limit") == strconv.Itoa(n) {
		out.NextCursor = out.Invites[n-1].InviteID
	}
	c.ok(out)
}

// disableInvite 代理 POST /admin/invites/{id}/disable。重复停用幂等。
// 这里不用 notAvailable：404 / 4040 是"邀请码不存在"，不是接口没上线。
func (c *rc) disableInvite() {
	id := c.r.PathValue("id")
	if !validID(id) {
		c.fail(apierr.New(apierr.InvalidID, "invalid inviteId"))
		return
	}
	c.audited(actionInviteDisable, audit.NewTarget("invite", id), nil, "", func() (any, error) {
		return struct{}{}, c.im(http.MethodPost, invitesPath+"/"+pathID(id)+"/disable", nil, struct{}{}, nil)
	})
}

// accountInfo 是用户详情的账号信息（规则 5）。独立类型：只有这 4 个字段，令牌、哈希、im-server 将来加的字段都出不去。
type accountInfo struct {
	HasAccount  bool  `json:"hasAccount"`
	CreatedAt   int64 `json:"createdAt,omitempty"`
	LastLoginAt int64 `json:"lastLoginAt,omitempty"`
	Sessions    int   `json:"sessions"`
}

// mergeAccountInfo 把账号信息合入详情。取不到时详情照常返回（客服还要看资料、强制下线），
// 用 accountUnavailable 标明；不能写 hasAccount=false，那是另一个意思。
// 日志只记错误码：底层错误里有带 userId 的地址。
func (c *rc) mergeAccountInfo(userID string, out map[string]any) {
	var info accountInfo
	err := c.im(http.MethodGet, "/admin/accounts/"+pathID(userID), nil, nil, &info)
	if err == nil {
		out["account"] = info
		return
	}
	code := apierr.Internal
	var e *apierr.Error
	switch {
	case errors.As(err, &e):
		code = e.Code
	case errors.Is(err, imclient.ErrResultUnknown):
		code = apierr.ResultUnknown
	}
	c.a.Log.Warn("account info unavailable", "requestId", c.requestID, "code", code)
	out["account"] = nil
	out["accountUnavailable"] = true
}
