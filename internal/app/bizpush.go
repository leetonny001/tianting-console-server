package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"tianting/console/internal/apierr"
	"tianting/console/internal/audit"
	"tianting/console/internal/ids"
	"tianting/console/internal/imclient"
	"tianting/console/internal/pushtpl"
)

// CS-044、CS-045：系统通知（PRD-admin F-ADM-50，协议见 PRD-live 第 4 节）。
//
// 通知正文只进 biz.push_records、biz.push_drafts：审计只记长度和 SHA-256，日志和 URL 都不带。

const (
	pushMaxUsers     = 1000
	pushMaxDataBytes = 4096 // 和 im-server 一样按序列化后的字节数算
	pushBodyLimit    = 1 << 20
	pushDraftTTL     = 24 * time.Hour
	pushAllInterval  = 5 * time.Minute
	pushConfirmText  = "全员发送"
	pushRecordsPage  = 20
	// pushRecordsTargetPreview：发送记录列表里每条最多带这么多个 userId，全部名单很大。
	pushRecordsTargetPreview = 50

	jobPushTargets = "push.targets"

	actionPushUser    = "push.user"
	actionPushRequest = "push.all.request"
	actionPushApprove = "push.all.approve"
	actionPushReplay  = "push.replay"

	pushKindUser = "user"
	pushKindAll  = "all"

	pushSending   = "sending"
	pushSuccess   = "success"
	pushFailed    = "failed"
	pushUnknown   = "unknown"
	pushReplayDue = "replay_due" // 对账认定要重放，下一步由 replayPushes 执行（PRD-live 4.7 节）
)

func pushBad(reason, msg string) *apierr.Error {
	return &apierr.Error{Code: apierr.BadRequest, Msg: msg, Reason: reason}
}

// pushContent 校验 type 和 data，返回紧凑序列化后的 data：这份字节就是存库、算哈希、发给 im-server 的内容。
func (c *rc) pushContent(typ string, raw json.RawMessage) ([]byte, bool) {
	tpl := c.a.Cfg.PushTemplates.Get(typ)
	if tpl == nil {
		c.fail(pushBad("templateUnknown", "type is not one of the configured templates"))
		return nil, false
	}
	var buf bytes.Buffer
	if len(raw) == 0 || json.Compact(&buf, raw) != nil || !utf8.Valid(buf.Bytes()) {
		c.fail(pushBad("dataInvalid", "data must be valid JSON"))
		return nil, false
	}
	if buf.Len() > pushMaxDataBytes {
		c.fail(pushBad("dataTooLarge", "data must be at most 4096 bytes"))
		return nil, false
	}
	if err := tpl.Validate(buf.Bytes()); err != nil {
		e := pushBad("dataInvalid", "data does not match the template")
		var fe *pushtpl.FieldError
		if errors.As(err, &fe) {
			e.Details = map[string]any{"path": fe.Path, "rule": fe.Rule}
		}
		c.fail(e)
		return nil, false
	}
	return buf.Bytes(), true
}

func pushAuditParams(kind, pushID, typ string, data []byte, targets int) map[string]any {
	p := map[string]any{"kind": kind, "pushId": pushID, "type": typ, "dataLength": len(data), "dataSha256": sha256Hex(data)}
	if kind == pushKindUser {
		p["targetCount"] = targets
	}
	return p
}

// imPushBody 是 POST /admin/push 的请求体。不转义 HTML：字节数要和 4KB 的校验一致。
func imPushBody(kind string, userIDs []string, typ, pushID string, data []byte) (imclient.RawBody, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(struct {
		Target  string          `json:"target"`
		UserIDs []string        `json:"userIds,omitempty"`
		Type    string          `json:"type"`
		Data    json.RawMessage `json:"data"`
		PushID  string          `json:"pushId"`
	}{kind, userIDs, typ, data, pushID})
	return bytes.TrimRight(buf.Bytes(), "\n"), err
}

type imPushReply struct {
	Created  bool `json:"created"`
	Accepted *int `json:"accepted"`
}

// listTemplates 给前端渲染表单。
func (c *rc) listPushTemplates() {
	type item struct {
		Type   string          `json:"type"`
		Title  string          `json:"title"`
		Schema json.RawMessage `json:"schema"`
	}
	out := []item{}
	for _, t := range c.a.Cfg.PushTemplates.List() {
		out = append(out, item{t.Type, t.Title, t.Schema})
	}
	c.ok(map[string]any{"templates": out, "maxUsers": pushMaxUsers, "maxDataBytes": pushMaxDataBytes})
}

// validatePushTargets：CSV 只有一列 userId。发 importToken，发送时用它。
func (c *rc) validatePushTargets() {
	file, _, ok := c.readUpload()
	if !ok {
		return
	}
	r, e := newCSV(file)
	if e != nil {
		c.fail(e)
		return
	}
	header, err := r.Read()
	if err != nil || len(header) != 1 || header[0] != "userId" {
		c.fail(apierr.New(apierr.BadRequest, "the header must be userId"))
		return
	}
	errs := &errRows{}
	seen := map[string]bool{}
	list := []string{}
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		line, _ := r.FieldPos(0)
		if err != nil || len(rec) != 1 {
			errs.add(line, apierr.BadRequest, "invalid CSV row")
			continue
		}
		if !validID(rec[0]) {
			errs.add(line, apierr.InvalidID, "invalid userId")
			continue
		}
		if !seen[rec[0]] {
			seen[rec[0]] = true
			list = append(list, rec[0])
		}
		if len(list) > pushMaxUsers {
			c.fail(&apierr.Error{Code: apierr.BatchLimit, Msg: "at most 1000 userIds per push", Reason: "pushTooManyUsers"})
			return
		}
	}
	preview := list
	if len(preview) > importPreview {
		preview = preview[:importPreview]
	}
	rows, err := json.Marshal(list)
	if err != nil {
		c.failErr("validate push targets", err)
		return
	}
	c.validateResult(jobPushTargets, file, len(list), errs, preview, string(rows))
}

// pushTargets 取出目标用户：userIds 或 importToken，二选一。job 非空时发送时要标成已用。
func (c *rc) pushTargets(userIDs []string, token string) ([]string, *importJob, bool) {
	var job *importJob
	switch {
	case token != "" && len(userIDs) > 0:
		c.fail(apierr.New(apierr.BadRequest, "use either userIds or importToken"))
		return nil, nil, false
	case token != "":
		var ok bool
		if job, ok = c.loadJob(jobPushTargets, token); !ok {
			return nil, nil, false
		}
		if err := json.Unmarshal([]byte(job.rows), &userIDs); err != nil {
			c.failErr("push targets", err)
			return nil, nil, false
		}
	}
	list := dedupeIDs(userIDs)
	switch {
	case len(list) == 0:
		c.fail(apierr.New(apierr.BadRequest, "userIds is required"))
		return nil, nil, false
	case len(list) > pushMaxUsers:
		c.fail(&apierr.Error{Code: apierr.BatchLimit, Msg: "at most 1000 userIds per push", Reason: "pushTooManyUsers"})
		return nil, nil, false
	case !c.checkIDs(list):
		return nil, nil, false
	}
	return list, job, true
}

func prettyJSON(data []byte) string {
	var buf bytes.Buffer
	if json.Indent(&buf, data, "", "  ") != nil {
		return string(data)
	}
	return buf.String()
}

// previewPush：发送前必须预览（F-ADM-50 规则 6）。不发送、不写审计。
func (c *rc) previewPush() {
	var req struct {
		Target      string          `json:"target"`
		UserIDs     []string        `json:"userIds"`
		ImportToken string          `json:"importToken"`
		Type        string          `json:"type"`
		Data        json.RawMessage `json:"data"`
	}
	if !c.readJSONLimit(&req, pushBodyLimit) {
		return
	}
	count := 0
	switch req.Target {
	case pushKindAll:
		if !c.ps.Has(c.roles, "push.all.request") {
			c.a.recordDenied(c, actionPushRequest)
			c.fail(apierr.New(apierr.Forbidden, "permission denied"))
			return
		}
	case pushKindUser:
		list, _, ok := c.pushTargets(req.UserIDs, req.ImportToken)
		if !ok {
			return
		}
		count = len(list)
	default:
		c.fail(apierr.New(apierr.BadRequest, "target must be user or all"))
		return
	}
	data, ok := c.pushContent(req.Type, req.Data)
	if !ok {
		return
	}
	c.ok(map[string]any{"target": req.Target, "targetCount": count, "type": req.Type, "dataLength": len(data), "data": prettyJSON(data)})
}

// pushRow 是 biz.push_records 新的一行。
type pushRow struct {
	id, kind, typ, pushID, requestID, reason, ticket string
	data                                             []byte
	targets                                          []string
	createdBy, createdByName                         string
	approvedBy, approvedByName, draftID              *string
	sentAt                                           int64
}

func insertPushRecord(ctx context.Context, tx pgx.Tx, r pushRow) error {
	targets := r.targets
	if targets == nil {
		targets = []string{}
	}
	raw, err := json.Marshal(targets)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO biz.push_records (id, kind, type, data, data_sha256, targets, target_count, reason, ticket, created_by, created_by_name, approved_by, approved_by_name, draft_id, sent_at, request_id, im_push_id, status)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10::uuid, $11, $12::uuid, $13, $14::uuid, $15, $16, $17, $18)`,
		r.id, r.kind, r.typ, string(r.data), sha256Hex(r.data), string(raw), len(targets), r.reason, r.ticket, r.createdBy, r.createdByName,
		r.approvedBy, r.approvedByName, r.draftID, r.sentAt, r.requestID, r.pushID, pushSending)
	return err
}

// sendPush 发给 im-server 并更新记录。
func (c *rc) sendPush(r pushRow) (any, error) {
	body, err := imPushBody(r.kind, r.targets, r.typ, r.pushID, r.data)
	if err != nil {
		return nil, err
	}
	var out imPushReply
	err = c.imDo(r.requestID, "POST", "/admin/push", nil, body, &out)
	ctx := context.WithoutCancel(c.ctx)
	if uerr := c.a.finishPush(ctx, r.id, out, err); uerr != nil {
		c.a.Log.Error("update push record failed", "recordId", r.id, "requestId", r.requestID, "err", uerr)
	}
	if err != nil {
		return nil, err
	}
	c.resultParams = map[string]any{"pushId": r.pushID, "created": out.Created}
	resp := map[string]any{"recordId": r.id, "pushId": r.pushID, "created": out.Created}
	if out.Accepted != nil {
		resp["accepted"] = *out.Accepted
	}
	return resp, nil
}

// finishPush 写下第一次调用的结果。结果未知的留给对账。
func (a *App) finishPush(ctx context.Context, id string, out imPushReply, callErr error) error {
	var e *apierr.Error
	var err error
	switch {
	case callErr == nil:
		_, err = a.DB.Exec(ctx, `UPDATE biz.push_records SET status = $2, im_created = $3, accepted = $4 WHERE id = $1::uuid`, id, pushSuccess, out.Created, out.Accepted)
	case errors.As(callErr, &e) && !errors.Is(callErr, imclient.ErrResultUnknown):
		_, err = a.DB.Exec(ctx, `UPDATE biz.push_records SET status = $2, error_code = $3 WHERE id = $1::uuid`, id, pushFailed, e.Code)
	default:
		_, err = a.DB.Exec(ctx, `UPDATE biz.push_records SET status = $2 WHERE id = $1::uuid`, id, pushUnknown)
	}
	return err
}

// pushToUsers：POST /console/api/push/user。
func (c *rc) pushToUsers() {
	var req struct {
		UserIDs     []string        `json:"userIds"`
		ImportToken string          `json:"importToken"`
		Type        string          `json:"type"`
		Data        json.RawMessage `json:"data"`
		reasonBody
	}
	if !c.readJSONLimit(&req, pushBodyLimit) {
		return
	}
	targets, job, ok := c.pushTargets(req.UserIDs, req.ImportToken)
	if !ok {
		return
	}
	data, ok := c.pushContent(req.Type, req.Data)
	if !ok {
		return
	}
	reason, ok := c.reasonTicket(req.Reason, req.Ticket)
	if !ok {
		return
	}
	c.ticket = req.Ticket
	pushID := ids.New(c.a.Clock.Now())
	row := pushRow{
		id: ids.New(c.a.Clock.Now()), kind: pushKindUser, typ: req.Type, pushID: pushID, requestID: c.requestID, reason: reason, ticket: req.Ticket,
		data: data, targets: targets, createdBy: c.acct.ID, createdByName: c.acct.Username, sentAt: c.now(),
	}
	c.audited(actionPushUser, audit.NewTarget("push", pushID), pushAuditParams(pushKindUser, pushID, req.Type, data, len(targets)), reason, func() (any, error) {
		if job != nil {
			if err := c.useJob(job); err != nil {
				return nil, err
			}
		}
		// 先落库再调用：进程在中间崩溃时，对账靠这一行才能重放。
		err := pgx.BeginFunc(context.WithoutCancel(c.ctx), c.a.DB, func(tx pgx.Tx) error {
			return insertPushRecord(context.WithoutCancel(c.ctx), tx, row)
		})
		if err != nil {
			return nil, err
		}
		return c.sendPush(row)
	})
}

// createPushDraft：全员草稿，运营发起，另一个账号批准（F-ADM-50 规则 5）。
func (c *rc) createPushDraft() {
	var req struct {
		Type   string          `json:"type"`
		Data   json.RawMessage `json:"data"`
		Reason string          `json:"reason"`
	}
	if !c.readJSONLimit(&req, pushBodyLimit) {
		return
	}
	data, ok := c.pushContent(req.Type, req.Data)
	if !ok {
		return
	}
	reason, ok := c.reasonTicket(req.Reason, "")
	if !ok {
		return
	}
	id := ids.New(c.a.Clock.Now())
	now := c.now()
	params := map[string]any{"draftId": id, "type": req.Type, "dataLength": len(data), "dataSha256": sha256Hex(data)}
	c.audited(actionPushRequest, audit.NewTarget("pushDraft", id), params, reason, func() (any, error) {
		_, err := c.a.DB.Exec(context.WithoutCancel(c.ctx), `INSERT INTO biz.push_drafts (id, type, data, data_sha256, reason, created_by, created_by_name, created_at, expires_at)
			VALUES ($1::uuid, $2, $3, $4, $5, $6::uuid, $7, $8, $9)`,
			id, req.Type, string(data), sha256Hex(data), reason, c.acct.ID, c.acct.Username, now, now+pushDraftTTL.Milliseconds())
		if err != nil {
			return nil, err
		}
		return map[string]any{"draftId": id, "expiresAt": now + pushDraftTTL.Milliseconds()}, nil
	})
}

type pushDraftItem struct {
	ID            string  `json:"id"`
	Type          string  `json:"type"`
	Data          string  `json:"data"`
	DataPretty    string  `json:"dataPretty"`
	DataSha256    string  `json:"dataSha256"`
	Reason        string  `json:"reason"`
	CreatedBy     string  `json:"createdBy"`
	CreatedByName string  `json:"createdByName"`
	CreatedAt     int64   `json:"createdAt"`
	ExpiresAt     int64   `json:"expiresAt"`
	Status        string  `json:"status"` // pending、expired、approved
	ApprovedBy    *string `json:"approvedByName,omitempty"`
	ApprovedAt    *int64  `json:"approvedAt,omitempty"`
	SendStatus    *string `json:"sendStatus,omitempty"`
}

func (c *rc) pushPage() int {
	limit := pushRecordsPage
	if v := c.r.URL.Query().Get("limit"); v == "50" || v == "100" {
		limit, _ = strconv.Atoi(v)
	}
	return limit
}

func (c *rc) listDrafts(onlyPending bool) {
	now := c.now()
	cond := "$2::bigint IS NOT NULL" // $2 也要用上：pgx 不接受没有用到的参数
	if onlyPending {
		cond = "d.status = 'pending' AND d.expires_at > $2"
	}
	rows, err := c.a.DB.Query(c.ctx, `SELECT d.id::text, d.type, d.data, d.data_sha256, d.reason, d.created_by::text, d.created_by_name, d.created_at, d.expires_at, d.status,
		d.approved_by_name, d.approved_at, r.status FROM biz.push_drafts d LEFT JOIN biz.push_records r ON r.draft_id = d.id
		WHERE `+cond+` ORDER BY d.created_at DESC, d.id DESC LIMIT $1`, c.pushPage(), now) // #nosec G202 -- cond 只有上面两种写死的条件
	if err != nil {
		c.failErr("list drafts", err)
		return
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (pushDraftItem, error) {
		var d pushDraftItem
		err := r.Scan(&d.ID, &d.Type, &d.Data, &d.DataSha256, &d.Reason, &d.CreatedBy, &d.CreatedByName, &d.CreatedAt, &d.ExpiresAt, &d.Status, &d.ApprovedBy, &d.ApprovedAt, &d.SendStatus)
		d.DataPretty = prettyJSON([]byte(d.Data))
		if d.Status == "pending" && d.ExpiresAt <= now { // 24 小时未批准自动作废：读取时判断
			d.Status = "expired"
		}
		return d, err
	})
	if err != nil {
		c.failErr("list drafts", err)
		return
	}
	if list == nil {
		list = []pushDraftItem{}
	}
	c.ok(map[string]any{"drafts": list})
}

func (c *rc) listMyDrafts()      { c.listDrafts(false) }
func (c *rc) listPendingDrafts() { c.listDrafts(true) }

// approvePushDraft：step-up + 确认文字，批准后立即发送。
func (c *rc) approvePushDraft() {
	id := c.r.PathValue("id")
	var req struct {
		ConfirmText string `json:"confirmText"`
	}
	if !c.readJSON(&req) {
		return
	}
	var d struct {
		typ, data, reason, createdBy, createdByName string
	}
	err := c.a.DB.QueryRow(c.ctx, `SELECT type, data, reason, created_by::text, created_by_name FROM biz.push_drafts WHERE id::text = $1`, id).
		Scan(&d.typ, &d.data, &d.reason, &d.createdBy, &d.createdByName)
	if errors.Is(err, pgx.ErrNoRows) {
		c.fail(apierr.New(apierr.NotFound, "draft not found"))
		return
	}
	if err != nil {
		c.failErr("load draft", err)
		return
	}
	// 发起人不能批准自己的草稿，同时有超管角色也不行（AC-ADM-50-7）。
	if d.createdBy == c.acct.ID {
		c.a.recordDenied(c, actionPushApprove)
		c.fail(&apierr.Error{Code: apierr.Forbidden, Msg: "you cannot approve your own draft", Reason: "ownDraft"})
		return
	}
	if req.ConfirmText != pushConfirmText {
		c.fail(pushBad("confirmMismatch", "confirmText does not match"))
		return
	}
	data := []byte(d.data)
	pushID := ids.New(c.a.Clock.Now())
	params := pushAuditParams(pushKindAll, pushID, d.typ, data, 0)
	params["draftId"] = id
	c.audited(actionPushApprove, audit.NewTarget("push", pushID), params, d.reason, func() (any, error) {
		now := c.now()
		approver, approverName := c.acct.ID, c.acct.Username
		row := pushRow{
			id: ids.New(c.a.Clock.Now()), kind: pushKindAll, typ: d.typ, pushID: pushID, requestID: c.requestID, reason: d.reason, data: data,
			createdBy: d.createdBy, createdByName: d.createdByName, approvedBy: &approver, approvedByName: &approverName, draftID: &id, sentAt: now,
		}
		ctx := context.WithoutCancel(c.ctx)
		err := pgx.BeginFunc(ctx, c.a.DB, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('push.all'))`); err != nil {
				return err
			}
			var status string
			var expires int64
			if err := tx.QueryRow(ctx, `SELECT status, expires_at FROM biz.push_drafts WHERE id::text = $1 FOR UPDATE`, id).Scan(&status, &expires); err != nil {
				return err
			}
			if status != "pending" {
				return pushBad("draftClosed", "the draft has already been approved")
			}
			if now >= expires {
				return pushBad("draftExpired", "the draft has expired")
			}
			// 重放不改 sent_at，所以这里自然不算重放（F-ADM-50 规则 5）。failed 的没发出去，不占间隔。
			var last *int64
			if err := tx.QueryRow(ctx, `SELECT max(sent_at) FROM biz.push_records WHERE kind = 'all' AND status <> 'failed'`).Scan(&last); err != nil {
				return err
			}
			if last != nil && now-*last < pushAllInterval.Milliseconds() {
				return &apierr.Error{Code: apierr.RateLimited, Msg: "at least 5 minutes between broadcast pushes", Reason: "pushAllInterval"}
			}
			if _, err := tx.Exec(ctx, `UPDATE biz.push_drafts SET status = 'approved', approved_by = $2::uuid, approved_by_name = $3, approved_at = $4 WHERE id::text = $1`, id, approver, approverName, now); err != nil {
				return err
			}
			return insertPushRecord(ctx, tx, row)
		})
		if err != nil {
			return nil, err
		}
		return c.sendPush(row)
	})
}

type pushRecordItem struct {
	ID             string   `json:"id"`
	Kind           string   `json:"kind"`
	Type           string   `json:"type"`
	Data           string   `json:"data"`
	DataPretty     string   `json:"dataPretty"`
	DataSha256     string   `json:"dataSha256"`
	UserIDs        []string `json:"userIds"`
	TargetCount    int      `json:"targetCount"`
	Reason         string   `json:"reason"`
	Ticket         string   `json:"ticket,omitempty"`
	CreatedByName  string   `json:"createdByName"`
	ApprovedByName *string  `json:"approvedByName,omitempty"`
	SentAt         int64    `json:"sentAt"`
	PushID         string   `json:"pushId"`
	RequestID      string   `json:"requestId"`
	Status         string   `json:"status"`
	ErrorCode      int      `json:"errorCode,omitempty"`
	Created        *bool    `json:"created,omitempty"`
	Accepted       *int     `json:"accepted,omitempty"`
	ReplayedAt     *int64   `json:"replayedAt,omitempty"`
	ReplayCreated  *bool    `json:"replayCreated,omitempty"`
	ReplayExpired  bool     `json:"replayExpired,omitempty"`
}

// listPushRecords：审计员和超管看全文（F-ADM-50 规则 7）。看全文本身也留痕。
func (c *rc) listPushRecords() {
	before := int64(1<<62 - 1)
	if v := c.r.URL.Query().Get("before"); v != "" {
		n, ok := parseInt(v)
		if !ok {
			c.fail(apierr.New(apierr.BadRequest, "before must be a timestamp"))
			return
		}
		before = n
	}
	limit := c.pushPage()
	if err := c.event("push.records.read", audit.Target{Type: "pushRecords"}, map[string]any{"before": before, "limit": limit}, audit.Success, 0); err != nil {
		c.fail(apierr.New(apierr.AuditUnavailable, "audit service unavailable, try again later"))
		return
	}
	rows, err := c.a.DB.Query(c.ctx, `SELECT id::text, kind, type, data, data_sha256, targets, target_count, reason, ticket, created_by_name, approved_by_name, sent_at, im_push_id, request_id, status, error_code, im_created, accepted, replay_at, replay_created, replay_expired
		FROM biz.push_records WHERE sent_at < $1 ORDER BY sent_at DESC, id DESC LIMIT $2`, before, limit)
	if err != nil {
		c.failErr("list push records", err)
		return
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (pushRecordItem, error) {
		var it pushRecordItem
		var targets string
		err := r.Scan(&it.ID, &it.Kind, &it.Type, &it.Data, &it.DataSha256, &targets, &it.TargetCount, &it.Reason, &it.Ticket, &it.CreatedByName, &it.ApprovedByName, &it.SentAt, &it.PushID, &it.RequestID, &it.Status, &it.ErrorCode, &it.Created, &it.Accepted, &it.ReplayedAt, &it.ReplayCreated, &it.ReplayExpired)
		if err != nil {
			return it, err
		}
		it.DataPretty = prettyJSON([]byte(it.Data))
		if err := json.Unmarshal([]byte(targets), &it.UserIDs); err != nil {
			return it, err
		}
		if len(it.UserIDs) > pushRecordsTargetPreview {
			it.UserIDs = it.UserIDs[:pushRecordsTargetPreview]
		}
		return it, nil
	})
	if err != nil {
		c.failErr("list push records", err)
		return
	}
	if list == nil {
		list = []pushRecordItem{}
	}
	var next *int64
	if len(list) == limit {
		next = &list[len(list)-1].SentAt
	}
	c.ok(map[string]any{"records": list, "nextBefore": next})
}
