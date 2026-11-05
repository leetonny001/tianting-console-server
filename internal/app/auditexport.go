package app

import (
	"context"
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"tianting/console/internal/apierr"
	"tianting/console/internal/audit"
	"tianting/console/internal/perm"
)

// CS-061、CS-132：审计导出 CSV（F-CON-09 规则 7、PRD-ops F-OPS-15 规则 3）。
// 边查边写：不生成临时文件，内存里最多一页。每页单独查，慢客户端不会一直占着数据库连接。

const (
	auditExportPath  = "/console/api/audit/export"
	auditExportMax   = 10_000
	auditExportPage  = 500
	auditExportWrite = 30 * time.Second // 每页的写超时：客户端不收数据时不要一直挂着
)

func auditExportAction(ps perm.Space) string {
	if ps.Name == perm.Ops.Name {
		return "ops.audit.export"
	}
	return "audit.export"
}

var auditCSVHeader = []string{"seq", "time", "space", "phase", "requestId", "username", "actor", "roles", "ip", "ua", "action", "target", "params", "reason", "ticket", "result", "code", "hash"}

// csvCell 防公式注入：表格软件会把开头是这些字符的单元格当公式执行（账号名、理由、UA 都可能是别人填的）。
// 前面加一个单引号让它变成文本。导出的内容因此可能和库里差一个引号，核对哈希链要用 audit verify，不用 CSV。
func csvCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '\t', '\r', '\n':
		return "'" + s
	}
	// 有的软件会先去掉开头的空白再判断。
	t := []rune(strings.TrimLeft(s, " \u00a0\u3000"))
	if len(t) > 0 {
		switch t[0] {
		case '=', '+', '-', '@', '\t', '\r', '\n', '＝', '＋', '－', '＠':
			return "'" + s
		}
	}
	return s
}

func auditCSVRow(s audit.Stored) []string {
	cells := []string{
		s.Space, s.Phase, s.RequestID, s.Username, s.Actor, s.Roles, s.IP, s.UA, s.Action, s.Target, s.Params, s.Reason, s.Ticket, s.Result,
	}
	for i := range cells {
		cells[i] = csvCell(cells[i])
	}
	row := make([]string, 0, len(auditCSVHeader))
	row = append(row, strconv.FormatInt(s.Seq, 10), time.UnixMilli(s.TS).In(shanghai).Format(time.RFC3339))
	row = append(row, cells...)
	return append(row, strconv.Itoa(s.Code), csvCell(s.Hash))
}

func (c *rc) auditExport() {
	action := c.route.action
	var req struct {
		From      *int64 `json:"from"`
		To        *int64 `json:"to"`
		Space     string `json:"space"`
		Actor     string `json:"actor"`
		Action    string `json:"action"`
		Target    string `json:"target"`
		Result    string `json:"result"`
		RequestID string `json:"requestId"`
	}
	if !c.readJSON(&req) {
		return
	}
	num := func(v *int64) string {
		if v == nil {
			return ""
		}
		return strconv.FormatInt(*v, 10)
	}
	fields := map[string]string{"from": num(req.From), "to": num(req.To), "space": req.Space, "actor": req.Actor, "action": req.Action, "target": req.Target, "result": req.Result, "requestId": req.RequestID}
	f, ok := c.parseAuditFilter(func(k string) string { return fields[k] }, action)
	if !ok {
		return
	}
	// 上界在写这次导出的审计之前定下来：导出不包含自己，翻页时也不会数到后来的记录。
	var maxSeq int64
	if err := c.a.DB.QueryRow(c.ctx, `SELECT COALESCE(max(seq), 0) FROM audit.records`).Scan(&maxSeq); err != nil {
		c.failErr(action, err)
		return
	}
	f.add("seq <= ?", maxSeq)

	intent := c.base(audit.PhaseIntent, action)
	intent.Params = map[string]any{"filters": f.filters}
	if err := c.a.Audit.Write(c.ctx, intent); err != nil {
		c.a.Log.Error("audit intent write failed; export rejected", "requestId", c.requestID, "err", err)
		c.fail(apierr.New(apierr.AuditUnavailable, "audit service unavailable, the operation was not performed"))
		return
	}
	finish := func(result string, code, count int, complete bool) {
		res := c.base(audit.PhaseResult, action)
		res.Result, res.Code = result, code
		res.Params = map[string]any{"filters": f.filters, "count": count, "complete": complete}
		if err := c.a.Audit.Write(context.WithoutCancel(c.ctx), res); err != nil {
			c.a.resultFailures.Inc()
			c.a.Log.Error("audit result write failed", "action", action, "requestId", c.requestID, "err", err)
		}
	}

	// 超过上限直接拒绝，不截断：截断的导出看起来和完整的一样。
	var total int
	if err := c.a.DB.QueryRow(c.ctx, `SELECT count(*) FROM (SELECT 1 FROM audit.records WHERE `+f.sql()+` LIMIT `+strconv.Itoa(auditExportMax+1)+`) x`, f.args...).Scan(&total); err != nil {
		finish(audit.Failure, apierr.Internal, 0, false)
		c.failErr(action, err)
		return
	}
	if total > auditExportMax {
		finish(audit.Failure, apierr.BatchLimit, 0, false)
		c.fail(&apierr.Error{Code: apierr.BatchLimit, Msg: "at most 10000 records per export", Reason: "auditExportTooMany"})
		return
	}

	h := c.w.Header()
	h.Set("Content-Type", "text/csv; charset=utf-8")
	h.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="audit-%s-%s.csv"`, c.space.Name, c.a.Clock.Now().In(shanghai).Format("20060102-150405")))
	c.w.WriteHeader(http.StatusOK)
	flusher := http.NewResponseController(c.w)
	// BOM：Excel 没有它会把中文当成本地编码。
	_, err := c.w.Write([]byte("\xef\xbb\xbf"))
	w := csv.NewWriter(c.w)
	if err == nil {
		err = w.Write(auditCSVHeader)
	}
	written := 0
	cursor := maxSeq + 1
	for err == nil {
		args := append(append([]any{}, f.args...), cursor, auditExportPage)
		n := len(f.args)
		rows, qerr := c.a.DB.Query(c.ctx, `SELECT `+audit.StoredColumns+` FROM audit.records WHERE `+f.sql()+` AND seq < $`+strconv.Itoa(n+1)+` ORDER BY seq DESC LIMIT $`+strconv.Itoa(n+2), args...)
		if qerr != nil {
			err = qerr
			break
		}
		list, qerr := collectStored(rows)
		if qerr != nil {
			err = qerr
			break
		}
		_ = flusher.SetWriteDeadline(time.Now().Add(auditExportWrite))
		for _, s := range list {
			if err = w.Write(auditCSVRow(s)); err != nil {
				break
			}
			written++
			cursor = s.Seq
		}
		w.Flush()
		if err == nil {
			err = w.Error()
		}
		if err == nil {
			err = flusher.Flush()
		}
		if len(list) < auditExportPage {
			break
		}
	}
	if err != nil {
		finish(audit.Failure, apierr.Internal, written, false)
		c.a.Log.Error("audit export interrupted", "requestId", c.requestID, "written", written, "err", err)
		panic(http.ErrAbortHandler) // 状态码已经发出去了：断开连接，让客户端知道文件不完整
	}
	finish(audit.Success, 0, written, true)
}
