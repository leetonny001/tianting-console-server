package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"tianting/console/internal/apierr"
	"tianting/console/internal/audit"
	"tianting/console/internal/imclient"
)

// CS-207（举报队列、详情、结案）、CS-208（证据授权、读取、文件代理）：PRD-chat F-MOD-04、第 11.6、14.1 节，PRD-admin 5.2、5.3 节；
// im-server 接口见 protocol/ADMIN.md"敏感词和举报"一节。
//
// 权限点：report.read、report.handle、report.evidence 只给审核（moderator）；超管默认没有，应急授权照旧。
// 队列、详情、结案用主凭证 console（scope report.read、report.handle）；证据授权、读证据、证据文件只用 console-msgread
// （正文类 scope report.evidence，AC-MOD-04-4）。
// 响应都是白名单结构（console-chat 第 20、22 条）：im-server 多返回的字段不透传；元数据里没有 note、正文和文件名（AC-MOD-04-10、04-11）。
// 审计只记 reportId、举报对象类型、结论和授权前 8 位，不记 note、正文、文件名。

const (
	actionReportView      = "report.view"
	actionReportHandle    = "report.handle"
	actionEvidenceGrant   = "report.evidence.grant"
	actionEvidenceView    = "report.evidence.view"
	actionReportFileFetch = "report.file.fetch"
)

// reportBrief 是队列里一个对象下的一条举报：页面点开看到每条（AC-MOD-04-6）。没有举报人和 note。
type reportBrief struct {
	ReportID  string `json:"reportId"`
	Reason    string `json:"reason"`
	State     string `json:"state"`
	CreatedAt int64  `json:"createdAt"`
}

// reportItem 是队列的一项：按对象聚合（F-MOD-04 规则 1，backend-chat 第 117 条）。targetKey 只给页面分页和去重。
// 单聊消息举报只有 convType，没有 convId、msgIds（单聊双方要在详情里填理由才看，F-MOD-04 规则 2）。
type reportItem struct {
	TargetKey  string        `json:"targetKey"`
	TargetType string        `json:"targetType"`
	ConvType   string        `json:"convType,omitempty"`
	ConvID     string        `json:"convId,omitempty"`
	MsgIDs     []string      `json:"msgIds,omitempty"`
	UserID     string        `json:"userId,omitempty"`
	GroupID    string        `json:"groupId,omitempty"`
	Count      int           `json:"count"`
	LatestAt   int64         `json:"latestAt"`
	Reports    []reportBrief `json:"reports"`
}

// listReports：状态、理由、对象类型、时间筛选，翻页。不写审计（打开详情才写）。
func (c *rc) listReports() {
	q, ok := c.listParams("cursor", "state", "reason", "targetType", "from", "to")
	if !ok {
		return
	}
	q.Del("q")
	var page struct {
		Items      []reportItem `json:"items"`
		NextCursor string       `json:"nextCursor"`
	}
	if err := c.im(http.MethodGet, "/admin/reports", q, nil, &page); err != nil {
		c.failErr("list reports", err)
		return
	}
	if page.Items == nil {
		page.Items = []reportItem{}
	}
	for i := range page.Items {
		if page.Items[i].ConvType == "c2c" { // im-server 不给；console 自己再兜一次，理由和配额在详情
			page.Items[i].ConvID, page.Items[i].MsgIDs = "", nil
		}
		if page.Items[i].Reports == nil {
			page.Items[i].Reports = []reportBrief{}
		}
	}
	c.ok(page)
}

// reportMsgMeta 是举报单里一条消息的元数据：类型和长度（F-MOD-04 规则 2），图片、文件另有原文件字节数。没有正文和文件名。
type reportMsgMeta struct {
	MsgID      string `json:"msgId"`
	Seq        int64  `json:"seq,omitempty"`
	From       string `json:"from,omitempty"`
	Type       string `json:"type,omitempty"`
	BodyLength *int   `json:"bodyLength,omitempty"`
	FileSize   int64  `json:"fileSize,omitempty"`
}

// reportDetail 是举报单的元数据（F-MOD-04 规则 2、4）：举报人、被举报人和他被举报的总次数、时间、理由、状态、消息类型和长度，
// 结案后的处理人、时间、结论。没有 note、正文和文件名（AC-MOD-04-10 第 3 种、AC-MOD-04-11）。
type reportDetail struct {
	ReportID          string          `json:"reportId"`
	TargetType        string          `json:"targetType"`
	ConvType          string          `json:"convType,omitempty"`
	ConvID            string          `json:"convId,omitempty"`
	MsgIDs            []string        `json:"msgIds,omitempty"`
	UserID            string          `json:"userId,omitempty"`
	GroupID           string          `json:"groupId,omitempty"`
	Reporter          string          `json:"reporter"`
	TargetUser        string          `json:"targetUser,omitempty"`
	TargetReportCount *int            `json:"targetReportCount,omitempty"`
	Reason            string          `json:"reason"`
	State             string          `json:"state"`
	CreatedAt         int64           `json:"createdAt"`
	Messages          []reportMsgMeta `json:"messages,omitempty"`
	HandledBy         string          `json:"handledBy,omitempty"`
	HandledAt         int64           `json:"handledAt,omitempty"`
	Conclusion        string          `json:"conclusion,omitempty"`
}

// reportPath 校验路径里的举报 ID。格式不对按不存在处理（和 im-server 一样 404 / 4040）。
func (c *rc) reportPath() (string, string, bool) {
	id := c.r.PathValue("id")
	if !validID(id) {
		c.fail(apierr.New(apierr.NotFound, "report not found"))
		return "", "", false
	}
	return id, "/admin/reports/" + pathID(id), true
}

// viewReport 是打开举报单：每次打开写一条 report.view（F-MOD-04 规则 2）。
// 单聊消息举报要填理由，配额每天 50 个、和单聊元数据查询合并计算（同一个单聊会话只算一次，kind 都是 msg.meta.c2c），
// 超出 429 / 4292（AC-MOD-04-10）。会话类型要从 im-server 的响应里才知道，所以理由的有无和配额在拿到响应之后判断，
// 不满足时响应里没有任何元数据。理由放请求体，不进 URL（CS-020 内容 3），所以是 POST。
func (c *rc) viewReport() {
	id, path, ok := c.reportPath()
	if !ok {
		return
	}
	var req reasonBody
	if !c.readJSON(&req) {
		return
	}
	reason := ""
	if req.Reason != "" || req.Ticket != "" {
		if reason, ok = c.reasonTicket(req.Reason, req.Ticket); !ok {
			return
		}
		c.ticket = req.Ticket
	}
	c.audited(actionReportView, audit.NewTarget("report", id), nil, reason, func() (any, error) {
		var d reportDetail
		if err := c.im(http.MethodGet, path, nil, nil, &d); err != nil {
			return nil, err
		}
		c.resultParams = map[string]any{"targetType": d.TargetType}
		if d.ConvType == "c2c" {
			c.resultParams["convType"] = "c2c"
			if reason == "" {
				return nil, &apierr.Error{Code: apierr.BadRequest, Msg: "a reason is required to view a one-to-one chat report", Reason: "reasonInvalid"}
			}
			if err := c.takeQuota("msg.meta.c2c", d.ConvID, metaDaily); err != nil {
				return nil, err
			}
		}
		return d, nil
	})
}

// resolveReport 是结案（F-MOD-04 规则 5）：结论 handled / rejected + 理由。不自动执行任何处置。
// 审计写失败：不调用 im-server，503 / 5031，举报还是 pending（AC-MOD-04-14 后半）；已结案的 im-server 409 / 4098 原样返回（AC-MOD-04-5）。
func (c *rc) resolveReport() {
	id, path, ok := c.reportPath()
	if !ok {
		return
	}
	var req struct {
		Result string `json:"result"`
		reasonBody
	}
	if !c.readJSON(&req) {
		return
	}
	if req.Result != "handled" && req.Result != "rejected" {
		c.fail(apierr.New(apierr.BadRequest, "result must be handled or rejected"))
		return
	}
	reason, ok := c.reasonTicket(req.Reason, req.Ticket)
	if !ok {
		return
	}
	c.ticket = req.Ticket
	c.audited(actionReportHandle, audit.NewTarget("report", id), map[string]any{"result": req.Result}, reason, func() (any, error) {
		return struct{}{}, c.im(http.MethodPost, path+"/resolve", nil, map[string]any{"result": req.Result, "reason": reason}, nil)
	})
}

// createEvidenceGrant：权限 → 理由（4000）→ 动态码缺失（4038）/ 错误（4015）→ intent → im-server（配额和正文授权合并，在那边）→ 绑定当前浏览器会话。
// 流程同 F-ADM-08：动态码每次都要，step-up 窗口不算数；工单号自动用举报 ID（PRD-admin 5.3 节）。
// 单聊消息举报、用户举报在 IM_C2C_BODY_ACCESS=off 时 im-server 403 / 4030 c2cBodyDisabled，原样返回（AC-MOD-04-3）。
func (c *rc) createEvidenceGrant() {
	id, _, ok := c.reportPath()
	if !ok {
		return
	}
	var req struct {
		Reason string `json:"reason"`
		OTP    string `json:"otp"`
	}
	if !c.readJSON(&req) {
		return
	}
	reason, e := CheckReason(req.Reason)
	if e != nil {
		c.fail(e)
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
	c.ticket = id
	c.audited(actionEvidenceGrant, audit.NewTarget("report", id), nil, reason, func() (any, error) {
		var g struct {
			GrantID   string `json:"grantId"`
			ExpiresAt int64  `json:"expiresAt"`
		}
		if err := c.msgRead("/admin/report-grants", map[string]any{"reportId": id, "reason": reason}, &g); err != nil {
			return nil, err
		}
		if _, err := c.a.DB.Exec(context.WithoutCancel(c.ctx), `INSERT INTO biz.report_grants (session_hash, report_id, grant_id, expires_at) VALUES ($1, $2, $3, $4)
			ON CONFLICT (session_hash, report_id) DO UPDATE SET grant_id = EXCLUDED.grant_id, expires_at = EXCLUDED.expires_at, conv_id = ''`,
			c.sessionKey(), id, g.GrantID, g.ExpiresAt); err != nil {
			return nil, err
		}
		prefix := grantPrefix(g.GrantID)
		c.resultParams = map[string]any{"grant": prefix}
		// 浏览器只拿到前 8 位（水印用），完整的 grantId 只在服务端。
		return map[string]any{"grantPrefix": prefix, "expiresAt": g.ExpiresAt}, nil
	})
}

// reportGrant 是这个浏览器会话对这条举报的证据授权。没有或已过期（按 console 的钟）时写好 403 / 4039，返回 false。
func (c *rc) reportGrant(id string) (grantID, convID string, expiresAt int64, ok bool) {
	err := c.a.DB.QueryRow(c.ctx, `SELECT grant_id, expires_at, conv_id FROM biz.report_grants WHERE session_hash = $1 AND report_id = $2`, c.sessionKey(), id).Scan(&grantID, &expiresAt, &convID)
	if errors.Is(err, pgx.ErrNoRows) {
		c.fail(apierr.New(apierr.MsgReadGrantNeeded, "no valid evidence grant for this report"))
		return "", "", 0, false
	}
	if err != nil {
		c.failErr("load report grant", err)
		return "", "", 0, false
	}
	if expiresAt <= c.now() {
		c.dropReportGrant(id)
		c.fail(apierr.New(apierr.MsgReadGrantNeeded, "the evidence grant has expired"))
		return "", "", 0, false
	}
	return grantID, convID, expiresAt, true
}

func (c *rc) dropReportGrant(id string) {
	if _, err := c.a.DB.Exec(context.WithoutCancel(c.ctx), `DELETE FROM biz.report_grants WHERE session_hash = $1 AND report_id = $2`, c.sessionKey(), id); err != nil {
		c.a.Log.Error("drop report grant", "err", err)
	}
}

// dropOnGrantGone：im-server 说授权没了（过期、换了操作人）就解除绑定，页面重新申请。
func (c *rc) dropOnGrantGone(id string, err error) {
	var e *apierr.Error
	if errors.As(err, &e) && e.Code == apierr.MsgReadGrantNeeded {
		c.dropReportGrant(id)
	}
}

// evidenceImage、evidenceFile、evidenceQuote、evidenceMentions、evidenceBody 是证据里一条消息的内容（同 WS 的 MsgBody）：
// 页面显示正文、引用、@、图片（fileId 用来经 console 取缩略图和原图）、文件名和大小（F-MOD-04 规则 3，backend-chat 第 134 条）。
type evidenceImage struct {
	FileID  string `json:"fileId"`
	Width   int    `json:"width"`
	Height  int    `json:"height"`
	Size    int64  `json:"size"`
	Mime    string `json:"mime"`
	Expired bool   `json:"expired,omitempty"`
}

type evidenceFile struct {
	FileID  string `json:"fileId"`
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	Mime    string `json:"mime"`
	Expired bool   `json:"expired,omitempty"`
}

type evidenceQuote struct {
	MsgID string `json:"msgId"`
	Seq   int64  `json:"seq,omitempty"`
	From  string `json:"from,omitempty"`
	Type  string `json:"type,omitempty"`
	State string `json:"state,omitempty"`
	Text  string `json:"text,omitempty"`
}

type evidenceMentions struct {
	UserIDs []string `json:"userIds"`
	All     bool     `json:"all,omitempty"`
}

type evidenceBody struct {
	Text     string            `json:"text,omitempty"`
	Data     json.RawMessage   `json:"data,omitempty"`
	Image    *evidenceImage    `json:"image,omitempty"`
	File     *evidenceFile     `json:"file,omitempty"`
	Quote    *evidenceQuote    `json:"quote,omitempty"`
	Mentions *evidenceMentions `json:"mentions,omitempty"`
}

// evidenceMessage 是证据里的一条被举报的消息（只有被举报的，不带上下文，F-MOD-04 规则 2）。只存了元数据的没有 body。
type evidenceMessage struct {
	MsgID      string        `json:"msgId"`
	Seq        int64         `json:"seq"`
	From       string        `json:"from"`
	Type       string        `json:"type"`
	TS         int64         `json:"ts"`
	Body       *evidenceBody `json:"body,omitempty"`
	Recalled   bool          `json:"recalled,omitempty"`
	RecalledAt int64         `json:"recalledAt,omitempty"`
	RecalledBy string        `json:"recalledBy,omitempty"`
}

// readEvidence：没有这个浏览器会话对这条举报的有效授权 403 / 4039，不调用 im-server。返回正文、隔离原文（AC-MOD-03-5、03-11）、
// note、文件名；密钥不匹配时 undecryptable 原样给页面（"证据无法解密"，AC-MOD-04-14 前半）。响应带水印用的授权前 8 位。
// 审计 report.evidence.view：授权前 8 位、条数，不记内容。
func (c *rc) readEvidence() {
	c.w.Header().Set("Cache-Control", "no-store")
	id, path, ok := c.reportPath()
	if !ok {
		return
	}
	grantID, _, expiresAt, ok := c.reportGrant(id)
	if !ok {
		return
	}
	prefix := grantPrefix(grantID)
	c.audited(actionEvidenceView, audit.NewTarget("report", id), map[string]any{"grant": prefix}, "", func() (any, error) {
		var out struct {
			Messages      []evidenceMessage `json:"messages"`
			Note          *string           `json:"note,omitempty"`
			Undecryptable bool              `json:"undecryptable,omitempty"`
		}
		if err := c.msgRead(path+"/evidence", map[string]any{"grantId": grantID}, &out); err != nil {
			c.dropOnGrantGone(id, err)
			return nil, err
		}
		if out.Messages == nil {
			out.Messages = []evidenceMessage{}
		}
		c.resultParams = map[string]any{"count": len(out.Messages), "grant": prefix}
		if out.Undecryptable {
			c.resultParams["undecryptable"] = true
		}
		resp := map[string]any{"messages": out.Messages, "grantPrefix": prefix, "expiresAt": expiresAt}
		if out.Note != nil {
			resp["note"] = *out.Note
		}
		if out.Undecryptable {
			resp["undecryptable"] = true
		}
		return resp, nil
	})
}

// fetchEvidenceFile：经 console 取被举报的图片、文件（缩略图和原图都可以，R-CS-12；AC-MOD-04-12、04-13、04-16）。
// 不复用 /console/api/files/{fileId}/fetch（那是隔离授权，console-chat 第 26 条）：这里用这个浏览器会话绑定的举报授权的 grantId。
// im-server 要 convId：第一次取文件时用主凭证查一次举报单（requestId 带 .conv 后缀，对账不会把它当成这次取文件），记在绑定上。
// 响应头：图片校验类型后 inline，其他只有 attachment（auditedStream，console-chat 第 25 条）；后台 CSP 不变。
func (c *rc) fetchEvidenceFile() {
	c.w.Header().Set("Cache-Control", "no-store")
	id, path, ok := c.reportPath()
	if !ok {
		return
	}
	fileID := c.r.PathValue("fileId")
	var req struct {
		MsgID   string `json:"msgId"`
		Variant string `json:"variant"`
	}
	if !c.readJSON(&req) {
		return
	}
	if !validID(fileID) || !validID(req.MsgID) {
		c.fail(apierr.New(apierr.BadRequest, "invalid fileId or msgId"))
		return
	}
	variant := req.Variant
	if variant == "" {
		variant = "original"
	}
	if variant != "original" && variant != "thumb" {
		c.fail(apierr.New(apierr.BadRequest, "variant must be original or thumb"))
		return
	}
	grantID, convID, _, ok := c.reportGrant(id)
	if !ok {
		return
	}
	params := map[string]any{"fileId": fileID, "msgId": req.MsgID, "variant": variant, "grant": grantPrefix(grantID)}
	c.auditedStream(actionReportFileFetch, audit.NewTarget("report", id), params, true, func() (*http.Response, error) {
		if convID == "" {
			var d struct {
				ConvID string `json:"convId"`
			}
			if err := c.imDo(c.requestID+".conv", http.MethodGet, path, nil, nil, &d); err != nil {
				return nil, err
			}
			if d.ConvID == "" { // 用户举报、群举报：证据里没有消息，也就没有文件
				return nil, apierr.New(apierr.NotFound, "no message evidence in this report")
			}
			convID = d.ConvID
			if _, err := c.a.DB.Exec(context.WithoutCancel(c.ctx), `UPDATE biz.report_grants SET conv_id = $3 WHERE session_hash = $1 AND report_id = $2 AND grant_id = $4`,
				c.sessionKey(), id, convID, grantID); err != nil {
				return nil, err
			}
		}
		if c.a.MsgRead == nil {
			return nil, apierr.New(apierr.Unavailable, "message body access is not configured")
		}
		resp, err := c.a.MsgRead.Stream(c.ctx, imclient.Call{Operator: c.operator(), RequestID: c.requestID}, http.MethodPost, "/admin/files/"+pathID(fileID)+"/fetch", nil,
			map[string]any{"grantId": grantID, "convId": convID, "msgId": req.MsgID, "variant": variant})
		// 这里的 4039 也可能是"这条举报的证据没有引用这个文件"（backend-chat 第 109 条），不解除绑定：
		// 授权真的没了时读证据会拿到 4039 并解除，console 自己的到期判断也会解除。
		return resp, err
	})
}
