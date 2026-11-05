package app

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"tianting/console/internal/apierr"
	"tianting/console/internal/audit"
	"tianting/console/internal/imclient"
)

// CS-040 ～ CS-043：管理后台第二批。到期时间、禁言状态都用 im-server 返回的值，这里不自己算（[IM 钟]）。

const (
	secondsPerDay  = 24 * 3600
	maxDeleteBatch = 50
	maxBodyPage    = 50
	minMuteSeconds = 60
	maxMuteSeconds = 30 * secondsPerDay
	msgReadCaller  = "console-msgread"
)

// banDurations、muteDurations 是页面上的选项（F-ADM-13 规则 1、F-ADM-40 规则 2）。"permanent" 单独处理。
var (
	banDurations  = map[string]int64{"1h": 3600, "1d": secondsPerDay, "7d": 7 * secondsPerDay, "30d": 30 * secondsPerDay}
	muteDurations = map[string]int64{"10m": 600, "1h": 3600, "1d": secondsPerDay, "7d": 7 * secondsPerDay, "30d": 30 * secondsPerDay}
)

// durationSeconds 把选项换成 im-server 的 durationSeconds：nil 表示永久。
func durationSeconds(choices map[string]int64, duration string) (*int64, bool) {
	if duration == "permanent" {
		return nil, true
	}
	v, ok := choices[duration]
	return &v, ok
}

func (c *rc) banUser() {
	id, path, ok := c.userPath()
	if !ok {
		return
	}
	var req struct {
		Duration string `json:"duration"`
		reasonBody
	}
	if !c.readJSON(&req) {
		return
	}
	secs, ok := durationSeconds(banDurations, req.Duration)
	if !ok {
		c.fail(apierr.New(apierr.BadRequest, "duration must be 1h, 1d, 7d, 30d or permanent"))
		return
	}
	reason, ok := c.reasonTicket(req.Reason, req.Ticket)
	if !ok {
		return
	}
	c.ticket = req.Ticket
	c.audited("user.ban", audit.NewTarget("user", id), map[string]any{"duration": req.Duration}, reason, func() (any, error) {
		var out map[string]any
		err := c.im("POST", path+"/ban", nil, map[string]any{"durationSeconds": secs, "reason": reason}, &out)
		return out, err
	})
}

func (c *rc) unbanUser() {
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
	c.audited("user.unban", audit.NewTarget("user", id), nil, reason, func() (any, error) {
		return struct{}{}, c.im("POST", path+"/unban", nil, map[string]any{"reason": reason}, nil)
	})
}

type muteBody struct {
	Scope   string `json:"scope"`
	UserID  string `json:"userId"`
	GroupID string `json:"groupId"`
	reasonBody
}

// muteTarget 校验范围和对象。
func (c *rc) muteTarget(req *muteBody) (audit.Target, map[string]any, bool) {
	body := map[string]any{"scope": req.Scope, "userId": req.UserID}
	switch req.Scope {
	case "user":
		if req.GroupID != "" {
			c.fail(apierr.New(apierr.BadRequest, "groupId is only for scope group"))
			return audit.Target{}, nil, false
		}
	case "group":
		if !validID(req.GroupID) {
			c.fail(apierr.New(apierr.InvalidID, "invalid groupId"))
			return audit.Target{}, nil, false
		}
		body["groupId"] = req.GroupID
	default:
		c.fail(apierr.New(apierr.BadRequest, "scope must be user or group"))
		return audit.Target{}, nil, false
	}
	if !validID(req.UserID) {
		c.fail(apierr.New(apierr.InvalidID, "invalid userId"))
		return audit.Target{}, nil, false
	}
	return audit.NewTarget("user", req.UserID), body, true
}

func (c *rc) setMute() {
	var req struct {
		muteBody
		Duration      string `json:"duration"`
		CustomSeconds *int64 `json:"customSeconds"`
	}
	if !c.readJSON(&req) {
		return
	}
	target, body, ok := c.muteTarget(&req.muteBody)
	if !ok {
		return
	}
	var secs *int64
	if req.CustomSeconds != nil {
		if req.Duration != "" || *req.CustomSeconds < minMuteSeconds || *req.CustomSeconds > maxMuteSeconds {
			c.fail(apierr.New(apierr.BadRequest, "customSeconds must be 60 to 2592000, without duration"))
			return
		}
		secs = req.CustomSeconds
	} else if secs, ok = durationSeconds(muteDurations, req.Duration); !ok {
		c.fail(apierr.New(apierr.BadRequest, "duration must be 10m, 1h, 1d, 7d, 30d, permanent, or use customSeconds"))
		return
	}
	reason, ok := c.reasonTicket(req.Reason, req.Ticket)
	if !ok {
		return
	}
	c.ticket = req.Ticket
	body["durationSeconds"], body["reason"] = secs, reason
	params := map[string]any{"scope": req.Scope}
	if req.GroupID != "" {
		params["groupId"] = req.GroupID
	}
	c.audited("mute.set", target, params, reason, func() (any, error) {
		var out map[string]any
		err := c.im("POST", "/admin/mute", nil, body, &out)
		return out, err
	})
}

func (c *rc) releaseMute() {
	var req muteBody
	if !c.readJSON(&req) {
		return
	}
	target, body, ok := c.muteTarget(&req)
	if !ok {
		return
	}
	reason, ok := c.reasonTicket(req.Reason, req.Ticket)
	if !ok {
		return
	}
	c.ticket = req.Ticket
	body["reason"] = reason
	params := map[string]any{"scope": req.Scope}
	if req.GroupID != "" {
		params["groupId"] = req.GroupID
	}
	c.audited("mute.release", target, params, reason, func() (any, error) {
		return struct{}{}, c.im("POST", "/admin/unmute", nil, body, nil)
	})
}

func (c *rc) deleteMessages() {
	var req struct {
		ConvID string   `json:"convId"`
		MsgIDs []string `json:"msgIds"`
		reasonBody
	}
	if !c.readJSON(&req) {
		return
	}
	kind, ok := parseConv(req.ConvID)
	if !ok || kind == "room" {
		c.fail(apierr.New(apierr.InvalidConvID, "invalid convId"))
		return
	}
	switch {
	case len(req.MsgIDs) == 0:
		c.fail(apierr.New(apierr.BadRequest, "msgIds is empty"))
		return
	case len(req.MsgIDs) > maxDeleteBatch:
		c.fail(apierr.New(apierr.BatchLimit, "at most %d messages per request", maxDeleteBatch))
		return
	}
	reason, ok := c.reasonTicket(req.Reason, req.Ticket)
	if !ok {
		return
	}
	ids := dedupeIDs(req.MsgIDs)
	c.ticket = req.Ticket
	c.audited("msg.delete", audit.NewTarget("conv", req.ConvID), map[string]any{"msgIds": ids}, reason, func() (any, error) {
		var out map[string]any
		err := c.im("POST", "/admin/messages/delete", nil, map[string]any{"convId": req.ConvID, "msgIds": ids, "reason": reason}, &out)
		return out, err
	})
}

// msgRead 用 console-msgread 凭证调用。主凭证 a.IM 没有正文 scope，im-server 会拒绝（AC-ADM-08-9）。
func (c *rc) msgRead(path string, body, out any) error {
	if c.a.MsgRead == nil {
		return apierr.New(apierr.Unavailable, "message body access is not configured")
	}
	return c.a.MsgRead.Do(context.WithoutCancel(c.ctx), imclient.Call{Operator: c.operator(), RequestID: c.requestID}, "POST", path, nil, body, out)
}

// grantPerm 是这次申请 / 读取要的权限：按会话类型和是否隔离原文（路由只能声明一个，具体的在这里判断）。
func (c *rc) grantPerm(kind string, quarantine bool) bool {
	perm := "msg.read.group"
	switch {
	case quarantine:
		perm = "msg.quarantine.read"
	case kind == "c2c":
		perm = "msg.read.c2c"
	}
	if c.ps.Has(c.roles, perm) {
		return true
	}
	c.a.recordDenied(c, perm)
	c.fail(apierr.New(apierr.Forbidden, "permission denied"))
	return false
}

// createMsgGrant：权限 → 工单号和理由（4000）→ 动态码缺失（4038）/ 错误（4015）→ intent → im-server（配额在那边）→ 绑定当前会话。
// 动态码每次都要，step-up 窗口不算数（F-CON-07 规则 3）。
func (c *rc) createMsgGrant() {
	var req struct {
		ConvID     string `json:"convId"`
		Ticket     string `json:"ticket"`
		Reason     string `json:"reason"`
		OTP        string `json:"otp"`
		Quarantine bool   `json:"quarantine"`
	}
	if !c.readJSON(&req) {
		return
	}
	kind, ok := parseConv(req.ConvID)
	if !ok || kind == "room" {
		c.fail(apierr.New(apierr.InvalidConvID, "invalid convId"))
		return
	}
	if !c.grantPerm(kind, req.Quarantine) {
		return
	}
	if req.Ticket == "" {
		c.fail(&apierr.Error{Code: apierr.BadRequest, Msg: "ticket is required", Reason: "ticketInvalid"})
		return
	}
	reason, ok := c.reasonTicket(req.Reason, req.Ticket)
	if !ok {
		return
	}
	if req.OTP == "" {
		c.fail(apierr.New(apierr.StepUpRequired, "enter your one-time code"))
		return
	}
	good, err := c.a.checkOTP(c.ctx, c.acct.ID, req.OTP)
	if err != nil {
		c.failErr("check otp", err)
		return
	}
	if !good {
		c.stepUpFailed()
		return
	}
	action := "msg.read.grant"
	if req.Quarantine {
		action = "msg.quarantine.grant"
	}
	c.ticket = req.Ticket
	c.audited(action, audit.NewTarget("conv", req.ConvID), map[string]any{"quarantine": req.Quarantine}, reason, func() (any, error) {
		var g struct {
			GrantID   string `json:"grantId"`
			ExpiresAt int64  `json:"expiresAt"`
		}
		body := map[string]any{"convId": req.ConvID, "operator": c.operator(), "reason": reason, "ticket": req.Ticket, "quarantine": req.Quarantine}
		if err := c.msgRead("/admin/msg-grants", body, &g); err != nil {
			return nil, err
		}
		if _, err := c.a.DB.Exec(context.WithoutCancel(c.ctx), `INSERT INTO biz.msg_grants (session_hash, conv_id, quarantine, grant_id, expires_at) VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (session_hash, conv_id, quarantine) DO UPDATE SET grant_id = EXCLUDED.grant_id, expires_at = EXCLUDED.expires_at`,
			c.sessionKey(), req.ConvID, req.Quarantine, g.GrantID, g.ExpiresAt); err != nil {
			return nil, err
		}
		prefix := grantPrefix(g.GrantID)
		c.resultParams = map[string]any{"grant": prefix}
		// 浏览器只拿到前 8 位（水印用）：授权绑定在服务端，页面不需要也不应该持有完整的 grantId。
		return map[string]any{"grantPrefix": prefix, "expiresAt": g.ExpiresAt}, nil
	})
}

func grantPrefix(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// bodyMessage 是正文页的一条消息。独立类型：只透传这些字段。
type bodyMessage struct {
	Seq       int64           `json:"seq"`
	MsgID     string          `json:"msgId"`
	From      string          `json:"from"`
	Type      string          `json:"type"`
	TS        int64           `json:"ts"`
	Body      *map[string]any `json:"body,omitempty"`
	Deleted   bool            `json:"deleted,omitempty"`
	DeletedAt int64           `json:"deletedAt,omitempty"`
	DeletedBy string          `json:"deletedBy,omitempty"`
}

// readMessageBody：没有该会话有效授权（未申请、过期、换了会话、换了浏览器会话）一律 403 / 4039。
// 每加载一页写一条 msg.read.page（seq 范围、条数，不含正文）。
func (c *rc) readMessageBody() {
	c.w.Header().Set("Cache-Control", "no-store")
	var req struct {
		ConvID     string `json:"convId"`
		BeforeSeq  *int64 `json:"beforeSeq"`
		Limit      *int   `json:"limit"`
		Quarantine bool   `json:"quarantine"`
	}
	if !c.readJSON(&req) {
		return
	}
	kind, ok := parseConv(req.ConvID)
	if !ok || kind == "room" {
		c.fail(apierr.New(apierr.InvalidConvID, "invalid convId"))
		return
	}
	limit := maxBodyPage
	if req.Limit != nil {
		if *req.Limit < 1 || *req.Limit > maxBodyPage {
			c.fail(apierr.New(apierr.BadRequest, "limit must be 1 to %d", maxBodyPage))
			return
		}
		limit = *req.Limit
	}
	if !c.grantPerm(kind, req.Quarantine) {
		return
	}
	var grantID string
	var expiresAt int64
	err := c.a.DB.QueryRow(c.ctx, `SELECT grant_id, expires_at FROM biz.msg_grants WHERE session_hash = $1 AND conv_id = $2 AND quarantine = $3`, c.sessionKey(), req.ConvID, req.Quarantine).Scan(&grantID, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		c.fail(apierr.New(apierr.MsgReadGrantNeeded, "no valid read grant for this conversation"))
		return
	}
	if err != nil {
		c.failErr("load msg grant", err)
		return
	}
	body := map[string]any{"grantId": grantID, "convId": req.ConvID, "limit": limit}
	params := map[string]any{"quarantine": req.Quarantine, "grant": grantPrefix(grantID)}
	if req.BeforeSeq != nil {
		body["beforeSeq"] = *req.BeforeSeq
		params["beforeSeq"] = *req.BeforeSeq
	}
	c.audited("msg.read.page", audit.NewTarget("conv", req.ConvID), params, "", func() (any, error) {
		var out struct {
			Messages []bodyMessage `json:"messages"`
			HasMore  bool          `json:"hasMore"`
		}
		if err := c.msgRead("/admin/convs/messages/body", body, &out); err != nil {
			var e *apierr.Error
			if errors.As(err, &e) && e.Code == apierr.MsgReadGrantNeeded {
				if _, derr := c.a.DB.Exec(context.WithoutCancel(c.ctx), `DELETE FROM biz.msg_grants WHERE session_hash = $1 AND conv_id = $2 AND quarantine = $3`, c.sessionKey(), req.ConvID, req.Quarantine); derr != nil {
					c.a.Log.Error("drop expired msg grant", "err", derr)
				}
			}
			return nil, err
		}
		if out.Messages == nil {
			out.Messages = []bodyMessage{}
		}
		rp := map[string]any{"count": len(out.Messages), "quarantine": req.Quarantine}
		if n := len(out.Messages); n > 0 {
			rp["seqFrom"], rp["seqTo"] = out.Messages[0].Seq, out.Messages[n-1].Seq
		}
		c.resultParams = rp
		return map[string]any{"messages": out.Messages, "hasMore": out.HasMore, "grantPrefix": grantPrefix(grantID), "expiresAt": expiresAt}, nil
	})
}
