package app

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"

	"tianting/console/internal/apierr"
	"tianting/console/internal/audit"
	"tianting/console/internal/imclient"
)

// CS-202：审核员经 console 代理取被撤回或被后台删除的消息里的图片、文件（PRD-chat 第 11.6、14.1 节，F-RCL-04，AC-RCL-04-9，R-CS-24）。
// C4 只开放隔离路径：权限点 msg.quarantine.read，这个浏览器会话对这个会话有有效的隔离授权；report.evidence 的路径随 C6。
// im-server 侧是 POST /admin/files/{fileId}/fetch（console-msgread 调用，msg.quarantine + 同一调用方、操作人的有效隔离授权）。
// 响应字节流式透传：不落盘、不缓存；固定 Content-Disposition: attachment（不带文件名）、nosniff、no-store，不内联，后台 CSP 不放宽。
// 审计记 fileId、msgId、variant、授权前 8 位，不记文件名。

const actionFileFetch = "msg.file.fetch"

func (c *rc) fetchFile() {
	c.w.Header().Set("Cache-Control", "no-store")
	fileID := c.r.PathValue("fileId")
	var req struct {
		ConvID  string `json:"convId"`
		MsgID   string `json:"msgId"`
		Variant string `json:"variant"`
	}
	if !c.readJSON(&req) {
		return
	}
	kind, ok := parseConv(req.ConvID)
	if !ok || kind == "room" {
		c.fail(apierr.New(apierr.InvalidConvID, "invalid convId"))
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
	// 权限点 msg.quarantine.read 由路由声明（单聊、群相同，和申请隔离授权一致）；单聊再受 im-server 的 IM_C2C_BODY_ACCESS。
	// 授权绑定在这个浏览器会话上（和正文读取相同）。im-server 的 fetch 不带 grantId、按调用方 + 操作人查授权（backend-chat 第 66 条），
	// 所以过期也要在这里判断：否则同一个人另一个会话的授权能让这个会话取文件（console 问题 14）。
	var grantID string
	var expiresAt int64
	err := c.a.DB.QueryRow(c.ctx, `SELECT grant_id, expires_at FROM biz.msg_grants WHERE session_hash = $1 AND conv_id = $2 AND quarantine = true`, c.sessionKey(), req.ConvID).Scan(&grantID, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		c.fail(apierr.New(apierr.MsgReadGrantNeeded, "no valid quarantine grant for this conversation"))
		return
	}
	if err != nil {
		c.failErr("load msg grant", err)
		return
	}
	if expiresAt <= c.now() {
		c.dropQuarantineGrant(req.ConvID)
		c.fail(apierr.New(apierr.MsgReadGrantNeeded, "the quarantine grant has expired"))
		return
	}
	params := map[string]any{"fileId": fileID, "msgId": req.MsgID, "variant": variant, "grant": grantPrefix(grantID)}
	c.auditedStream(actionFileFetch, audit.NewTarget("conv", req.ConvID), params, func() (*http.Response, error) {
		if c.a.MsgRead == nil {
			return nil, apierr.New(apierr.Unavailable, "message body access is not configured")
		}
		resp, err := c.a.MsgRead.Stream(c.ctx, imclient.Call{Operator: c.operator(), RequestID: c.requestID}, "POST", "/admin/files/"+pathID(fileID)+"/fetch", nil,
			map[string]any{"convId": req.ConvID, "msgId": req.MsgID, "variant": variant})
		var e *apierr.Error
		if errors.As(err, &e) && e.Code == apierr.MsgReadGrantNeeded {
			c.dropQuarantineGrant(req.ConvID) // im-server 说授权没了（过期、撤销）：解除绑定，页面重新申请
		}
		return resp, err
	})
}

func (c *rc) dropQuarantineGrant(conv string) {
	if _, err := c.a.DB.Exec(context.WithoutCancel(c.ctx), `DELETE FROM biz.msg_grants WHERE session_hash = $1 AND conv_id = $2 AND quarantine = true`, c.sessionKey(), conv); err != nil {
		c.a.Log.Error("drop expired msg grant", "err", err)
	}
}

// fileContentType 用 im-server 给的类型（上传时校验过）；解析不了就是 application/octet-stream。
// 浏览器不会按它渲染：固定 attachment + nosniff。
func fileContentType(v string) string {
	mt, _, err := mime.ParseMediaType(v)
	if err != nil || mt == "" {
		return "application/octet-stream"
	}
	return mt
}

// auditedStream 是流式响应的两阶段审计：intent 写失败不调用 im-server（503 / 5031）；
// im-server 拒绝时和 audited 相同；成功时先写响应头、再边读边写，读完写 result（字节数）。
// 传到一半断了（im-server 或浏览器）result 记 failure，params.incomplete=true；状态码已经发出去，改不了。
func (c *rc) auditedStream(action string, target audit.Target, params map[string]any, fn func() (*http.Response, error)) {
	r := c.base(audit.PhaseIntent, action)
	r.Target, r.Params = target, params
	if err := c.a.Audit.Write(c.ctx, r); err != nil {
		c.a.Log.Error("audit intent write failed; request rejected", "action", action, "requestId", c.requestID, "err", err)
		c.fail(apierr.New(apierr.AuditUnavailable, "audit service unavailable, the operation was not performed"))
		return
	}
	res := c.base(audit.PhaseResult, action)
	res.Target = target
	writeResult := func() {
		if werr := c.a.Audit.Write(context.WithoutCancel(c.ctx), res); werr != nil {
			c.a.resultFailures.Inc()
			c.a.Log.Error("audit result write failed", "action", action, "requestId", c.requestID, "err", werr)
		}
	}
	resp, err := fn()
	if err != nil {
		var e *apierr.Error
		switch {
		case errors.Is(err, imclient.ErrResultUnknown):
			res.Result, res.Code = audit.Unknown, apierr.ResultUnknown
			err = apierr.New(apierr.ResultUnknown, "im-server did not answer in time")
		case errors.As(err, &e):
			res.Result, res.Code = audit.Failure, e.Code
		default:
			res.Result, res.Code = audit.Failure, apierr.Internal
		}
		writeResult()
		c.failErr(action, err)
		return
	}
	defer resp.Body.Close()
	h := c.w.Header()
	h.Set("Content-Type", fileContentType(resp.Header.Get("Content-Type")))
	h.Set("Content-Disposition", "attachment") // 固定附件、不带文件名：文件名按正文对待（R-CS-14），页面从正文接口拿
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	if n := resp.ContentLength; n >= 0 {
		h.Set("Content-Length", strconv.FormatInt(n, 10))
	}
	c.w.WriteHeader(http.StatusOK)
	n, cerr := io.Copy(c.w, resp.Body)
	res.Params = map[string]any{"bytes": n}
	if cerr != nil || (resp.ContentLength >= 0 && n != resp.ContentLength) {
		res.Result, res.Code = audit.Failure, apierr.Internal
		res.Params["incomplete"] = true
		c.a.Log.Warn("file fetch interrupted", "requestId", c.requestID, "bytes", n) // 不记文件名、fileId 以外的内容
	} else {
		res.Result = audit.Success
	}
	writeResult()
}
