package app

import (
	"net/http"

	"tianting/console/internal/apierr"
	"tianting/console/internal/audit"
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
