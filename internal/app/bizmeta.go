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
	TS         int64  `json:"ts"`
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
