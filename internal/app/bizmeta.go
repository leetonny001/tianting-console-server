package app

import (
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"tianting/console/internal/apierr"
	"tianting/console/internal/audit"
)

// CS-026：会话消息元数据。

const (
	metaWindow  = 15 * time.Minute
	metaDaily   = 50
	metaPerPage = 50
)

// messageMeta 是一条元数据。独立类型：im-server 的响应反序列化到这里，未知字段丢弃，正文出不去（AC-ADM-30-7）。
type messageMeta struct {
	Seq        int64  `json:"seq"`
	MsgID      string `json:"msgId"`
	From       string `json:"from"`
	Type       string `json:"type"`
	BodyLength int    `json:"bodyLength"`
	// 图片、文件消息的原文件字节数（im-server 的 fileSize，PRD-chat v1.4 第 14.1 节，P-37 ③）；其他消息、已删除的没有。
	FileSize *int64 `json:"fileSize,omitempty"`
	TS       int64  `json:"ts"`
	// 第二批：删除标记、删除时间、删除人（im-server 的值，CS-042）。
	Deleted   bool   `json:"deleted,omitempty"`
	DeletedAt int64  `json:"deletedAt,omitempty"`
	DeletedBy string `json:"deletedBy,omitempty"`
	// C4：撤回标记、时间、撤回人 userId（im-server 的值，F-RCL-04 规则 3，CS-204）。撤回的没有 fileSize（im-server 不返回）。
	Recalled   bool   `json:"recalled,omitempty"`
	RecalledAt int64  `json:"recalledAt,omitempty"`
	RecalledBy string `json:"recalledBy,omitempty"`
}

type metaPage struct {
	Messages []messageMeta `json:"messages"`
	HasMore  bool          `json:"hasMore"`
}

// parseConv 校验会话 ID（和 im-server 的 ParseConvID 相同）：c2c 两个用户按字典序。
func parseConv(s string) (kind string, ok bool) {
	parts := strings.Split(s, ":")
	switch {
	case len(parts) == 3 && parts[0] == "c2c":
		return "c2c", validID(parts[1]) && validID(parts[2]) && parts[1] <= parts[2]
	case len(parts) == 2 && (parts[0] == "group" || parts[0] == "room"):
		return parts[0], validID(parts[1])
	}
	return "", false
}

// metaActive 判断这个浏览器会话是不是已经进入过这个会话、还在窗口内。
func (c *rc) metaActive(conv string) (bool, error) {
	var until int64
	err := c.a.DB.QueryRow(c.ctx, `SELECT until FROM biz.meta_sessions WHERE session_hash = $1 AND conv_id = $2`, c.sessionKey(), conv).Scan(&until)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil && until > c.now(), err
}

func (c *rc) metaEnter(conv string) error {
	_, err := c.a.DB.Exec(c.ctx, `INSERT INTO biz.meta_sessions (session_hash, conv_id, until) VALUES ($1, $2, $3)
		ON CONFLICT (session_hash, conv_id) DO UPDATE SET until = EXCLUDED.until`, c.sessionKey(), conv, c.now()+metaWindow.Milliseconds())
	return err
}

// queryMeta：翻页（带 beforeSeq）且窗口有效时不再要理由、不再写审计；其他情况都是"进入"。
// 不能只看有没有 beforeSeq：否则一直带 beforeSeq 就能绕过理由和审计。
func (c *rc) queryMeta() {
	var req struct {
		ConvID    string `json:"convId"`
		BeforeSeq *int64 `json:"beforeSeq"`
		From      string `json:"from"`
		SinceTS   *int64 `json:"sinceTs"`
		UntilTS   *int64 `json:"untilTs"`
		reasonBody
	}
	if !c.readJSON(&req) {
		return
	}
	kind, ok := parseConv(req.ConvID)
	if !ok {
		c.fail(apierr.New(apierr.InvalidConvID, "invalid convId"))
		return
	}
	if req.From != "" && !validID(req.From) {
		c.fail(apierr.New(apierr.InvalidID, "invalid from"))
		return
	}
	body := map[string]any{"convId": req.ConvID, "limit": metaPerPage}
	if req.BeforeSeq != nil {
		body["beforeSeq"] = *req.BeforeSeq
	}
	if req.From != "" {
		body["from"] = req.From
	}
	if req.SinceTS != nil {
		body["sinceTs"] = *req.SinceTS
	}
	if req.UntilTS != nil {
		body["untilTs"] = *req.UntilTS
	}
	fetch := func() (any, error) {
		var page metaPage
		if err := c.im("POST", "/admin/convs/messages/query", nil, body, &page); err != nil {
			return nil, err
		}
		if page.Messages == nil {
			page.Messages = []messageMeta{}
		}
		return page, nil
	}
	if req.BeforeSeq != nil {
		active, err := c.metaActive(req.ConvID)
		if err != nil {
			c.failErr("meta query", err)
			return
		}
		if active {
			page, err := fetch()
			if err != nil {
				c.failErr("meta query", err)
				return
			}
			c.ok(page)
			return
		}
	}
	reason := ""
	if kind == "c2c" {
		if reason, ok = c.reasonTicket(req.Reason, req.Ticket); !ok {
			return
		}
		if !c.dailyQuota("msg.meta.c2c", req.ConvID, metaDaily) {
			return
		}
		c.ticket = req.Ticket
	}
	params := map[string]any{}
	if req.From != "" {
		params["from"] = req.From
	}
	c.audited("msg.meta.query", audit.NewTarget("conv", req.ConvID), params, reason, func() (any, error) {
		page, err := fetch()
		if err != nil {
			return nil, err
		}
		if err := c.metaEnter(req.ConvID); err != nil {
			c.a.Log.Error("meta session", "err", err) // 只影响下一页要不要再填理由
		}
		return page, nil
	})
}

// CS-063：用户所在群和用户会话列表（F-ADM-10 规则 2、F-ADM-30 规则 1 ③）。

const actionUserConvs = "msg.user_convs.query"

// listUserGroups：分页，不含已解散的群（im-server 保证），不写审计。
func (c *rc) listUserGroups() {
	id := c.r.PathValue("id")
	if !validID(id) {
		c.fail(apierr.New(apierr.InvalidID, "invalid userId"))
		return
	}
	q, ok := c.listParams("cursor")
	if !ok {
		return
	}
	q.Del("q")
	c.imRead("/admin/users/"+pathID(id)+"/groups", q)
}

// userConv 是用户会话列表的一项：只有会话 ID、类型、最后活跃时间。im-server 的响应反序列化到这里，
// 其他字段（对方、群名、最后一条消息的发送者和类型）都丢弃，这个接口出不去正文和摘要。
type userConv struct {
	ConvID    string `json:"convId"`
	Type      string `json:"type"`
	UpdatedAt int64  `json:"updatedAt"`
}

type userConvPage struct {
	Convs      []userConv `json:"convs"`
	NextCursor string     `json:"nextCursor"`
}

// userConvsActive：这个账号打开过这个用户的会话列表、还在 15 分钟内。按账号 + 用户算，换一个浏览器会话不用重新填。
func (c *rc) userConvsActive(userID string) (bool, error) {
	var until int64
	err := c.a.DB.QueryRow(c.ctx, `SELECT until FROM biz.user_convs_windows WHERE account_id = $1::uuid AND user_id = $2`, c.acct.ID, userID).Scan(&until)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil && until > c.now(), err
}

func (c *rc) userConvsEnter(userID string) error {
	_, err := c.a.DB.Exec(c.ctx, `INSERT INTO biz.user_convs_windows (account_id, user_id, until) VALUES ($1::uuid, $2, $3)
		ON CONFLICT (account_id, user_id) DO UPDATE SET until = EXCLUDED.until`, c.acct.ID, userID, c.now()+metaWindow.Milliseconds())
	return err
}

// queryUserConvs：不带 cursor 是打开，必填理由、写一条审计，窗口从这时开始；翻页（带 cursor）在窗口内不要理由、不写审计，也不延长窗口。
// 窗口外的翻页和打开一样。理由校验在调用 im-server 之前：校验不过 im-server 收不到请求。
func (c *rc) queryUserConvs() {
	var req struct {
		UserID string `json:"userId"`
		Cursor string `json:"cursor"`
		reasonBody
	}
	if !c.readJSON(&req) {
		return
	}
	if !validID(req.UserID) {
		c.fail(apierr.New(apierr.InvalidID, "invalid userId"))
		return
	}
	body := map[string]any{"userId": req.UserID}
	if req.Cursor != "" {
		body["cursor"] = req.Cursor
	}
	fetch := func() (userConvPage, error) {
		var page userConvPage
		if err := c.im("POST", "/admin/users/convs/query", nil, body, &page); err != nil {
			return page, err
		}
		if page.Convs == nil {
			page.Convs = []userConv{}
		}
		return page, nil
	}
	if req.Cursor != "" {
		active, err := c.userConvsActive(req.UserID)
		if err != nil {
			c.failErr(actionUserConvs, err)
			return
		}
		if active {
			page, err := fetch()
			if err != nil {
				c.failErr(actionUserConvs, err)
				return
			}
			c.ok(page)
			return
		}
	}
	reason, ok := c.reasonTicket(req.Reason, req.Ticket)
	if !ok {
		return
	}
	c.ticket = req.Ticket
	c.audited(actionUserConvs, audit.NewTarget("user", req.UserID), nil, reason, func() (any, error) {
		page, err := fetch()
		if err != nil {
			return nil, err
		}
		c.resultParams = map[string]any{"count": len(page.Convs)}
		if err := c.userConvsEnter(req.UserID); err != nil {
			c.a.Log.Error("user convs window", "err", err) // 只影响下一页要不要再填理由
		}
		return page, nil
	})
}
