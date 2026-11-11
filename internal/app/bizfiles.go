package app

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"tianting/console/internal/apierr"
	"tianting/console/internal/audit"
	"tianting/console/internal/imclient"
)

// CS-202：审核员经 console 代理取被撤回或被后台删除的消息里的图片、文件（PRD-chat v1.6 第 11.6、14.1 节，F-RCL-04，AC-RCL-04-9，R-CS-24）。
// C4 只开放隔离路径：权限点 msg.quarantine.read，这个浏览器会话对这个会话有有效的隔离授权；report.evidence 的路径随 C6。
// im-server 侧是 POST /admin/files/{fileId}/fetch（console-msgread 调用，msg.quarantine + 同一调用方、操作人的有效隔离授权）；
// 请求体带这个浏览器会话绑定的 grantId（PRD-chat v1.6，PENDING P-44 ④），im-server 只认这一个授权。grantId 只放请求体，不进 URL 和日志。
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
	// 授权绑定在这个浏览器会话上（和正文读取相同）。im-server 按请求体里的 grantId 校验调用方、操作人、会话、隔离和到期（v1.6，P-44 ④）；
	// console 这里仍先比一次到期时间，过期就不调用 im-server（console 问题 14）。
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
	c.auditedStream(actionFileFetch, audit.NewTarget("conv", req.ConvID), params, false, func() (*http.Response, error) {
		if c.a.MsgRead == nil {
			return nil, apierr.New(apierr.Unavailable, "message body access is not configured")
		}
		resp, err := c.a.MsgRead.Stream(c.ctx, imclient.Call{Operator: c.operator(), RequestID: c.requestID}, "POST", "/admin/files/"+pathID(fileID)+"/fetch", nil,
			map[string]any{"grantId": grantID, "convId": req.ConvID, "msgId": req.MsgID, "variant": variant})
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

// inlineImageTypes 是举报证据里可以内联显示的图片类型（F-MOD-04 规则 3，console-chat 第 25 条）和它们的文件头。
// 不含 SVG（可以带脚本）。im-server 记录的类型在这里、文件头也对得上才内联，Content-Type 固定成这个值。
var inlineImageTypes = map[string]func([]byte) bool{
	"image/jpeg": func(b []byte) bool { return bytes.HasPrefix(b, []byte{0xFF, 0xD8, 0xFF}) },
	"image/png":  func(b []byte) bool { return bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")) },
	"image/gif": func(b []byte) bool {
		return bytes.HasPrefix(b, []byte("GIF87a")) || bytes.HasPrefix(b, []byte("GIF89a"))
	},
	"image/webp": func(b []byte) bool { return len(b) >= 12 && string(b[:4]) == "RIFF" && string(b[8:12]) == "WEBP" },
}

// sniffLen 是判断文件头要读的字节数（WebP 要 12 个）。
const sniffLen = 12

// auditedStream 是流式响应的两阶段审计：intent 写失败不调用 im-server（503 / 5031）；
// im-server 拒绝时和 audited 相同；成功时先写响应头、再边读边写，读完写 result（字节数）。
// 传到一半断了（im-server 或浏览器）result 记 failure，params.incomplete=true；状态码已经发出去，改不了。
// inlineImages=false（隔离路径，CS-202）：一律 attachment。true（举报证据，CS-208）：im-server 记录的类型在白名单里、
// 文件头也对得上的图片 inline（页面同源显示）；声称是图片但对不上的按 application/octet-stream 附件；其他类型 attachment。
// 两种都带 nosniff、no-store，不带文件名，后台 CSP 不变。
func (c *rc) auditedStream(action string, target audit.Target, params map[string]any, inlineImages bool, fn func() (*http.Response, error)) {
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
	contentType, disposition := fileContentType(resp.Header.Get("Content-Type")), "attachment"
	var src io.Reader = resp.Body
	inline := false
	if inlineImages {
		br := bufio.NewReaderSize(resp.Body, 512)
		head, _ := br.Peek(sniffLen) // 文件不到 12 个字节时 head 更短，校验不过
		src = br
		if check, ok := inlineImageTypes[contentType]; ok && check(head) {
			disposition, inline = "inline", true
		} else if strings.HasPrefix(contentType, "image/") {
			contentType = "application/octet-stream"
		}
	}
	h.Set("Content-Type", contentType)
	h.Set("Content-Disposition", disposition) // 不带文件名：文件名按正文对待（R-CS-14），页面从正文、证据接口拿
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	if n := resp.ContentLength; n >= 0 {
		h.Set("Content-Length", strconv.FormatInt(n, 10))
	}
	c.w.WriteHeader(http.StatusOK)
	n, cerr := io.Copy(c.w, src)
	res.Params = map[string]any{"bytes": n}
	if inlineImages {
		res.Params["inline"] = inline
	}
	if cerr != nil || (resp.ContentLength >= 0 && n != resp.ContentLength) {
		res.Result, res.Code = audit.Failure, apierr.Internal
		res.Params["incomplete"] = true
		c.a.Log.Warn("file fetch interrupted", "requestId", c.requestID, "bytes", n) // 不记文件名、fileId 以外的内容
	} else {
		res.Result = audit.Success
	}
	writeResult()
}
