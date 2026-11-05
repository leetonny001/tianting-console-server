package app

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"tianting/console/internal/apierr"
	"tianting/console/internal/audit"
)

const (
	auditPath        = "/console/api/audit"
	auditRequestPath = "/console/api/audit/requests/{requestId}"
	auditIMPath      = "/console/api/audit/im"
	actionAuditQuery = "audit.query"

	auditMaxSpan  = 31 * 24 * time.Hour
	auditMaxLimit = 200
)

// auditItem 是接口返回的一条审计。
type auditItem struct {
	Seq           int64           `json:"seq"`
	ID            string          `json:"id"`
	TS            int64           `json:"ts"`
	Space         string          `json:"space"`
	Phase         string          `json:"phase"`
	RequestID     string          `json:"requestId"`
	AccountID     string          `json:"accountId"`
	Username      string          `json:"username"`
	Roles         json.RawMessage `json:"roles"`
	Actor         string          `json:"actor"`
	IP            string          `json:"ip"`
	UA            string          `json:"ua"`
	Action        string          `json:"action"`
	Target        json.RawMessage `json:"target"`
	Params        json.RawMessage `json:"params"`
	Reason        string          `json:"reason"`
	Ticket        string          `json:"ticket"`
	Result        string          `json:"result"`
	Code          int             `json:"code"`
	PrevHash      string          `json:"prevHash"`
	Hash          string          `json:"hash"`
	ResultMissing bool            `json:"resultMissing,omitempty"` // intent 还没有 result：页面显示"结果未知"
}

// rawJSON：库里的文本正常都是合法 JSON；被人改坏时当字符串返回，不能让审计页打不开。
func rawJSON(s string) json.RawMessage {
	if json.Valid([]byte(s)) {
		return json.RawMessage(s)
	}
	quoted, _ := json.Marshal(s)
	return quoted
}

func toItem(s audit.Stored) auditItem {
	return auditItem{
		Seq: s.Seq, ID: s.ID, TS: s.TS, Space: s.Space, Phase: s.Phase, RequestID: s.RequestID, AccountID: s.AccountID, Username: s.Username,
		Roles: rawJSON(s.Roles), Actor: s.Actor, IP: s.IP, UA: s.UA, Action: s.Action, Target: rawJSON(s.Target), Params: rawJSON(s.Params),
		Reason: s.Reason, Ticket: s.Ticket, Result: s.Result, Code: s.Code, PrevHash: s.PrevHash, Hash: s.Hash,
	}
}

func parseJSONStrings(s string) []string {
	var out []string
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

func parseTarget(s string) audit.Target {
	var t audit.Target
	_ = json.Unmarshal([]byte(s), &t)
	return t
}

// auditSpaces 决定这次能看哪些空间（F-CON-09 规则 1）：管理空间审计员只能看 admin，运维空间审计员可以选全部。
func (c *rc) auditSpaces(want string) ([]string, bool) {
	if want == "" || want == c.space.Name {
		return []string{c.space.Name}, true
	}
	if !c.ps.AuditAll {
		return nil, false
	}
	switch want {
	case "all":
		return []string{"admin", "ops"}, true
	case "admin", "ops":
		return []string{want}, true
	}
	return nil, false
}

// auditDenied：越权查询另一个空间也要留痕。
func (c *rc) auditDenied(action string) {
	c.a.recordDenied(c, action)
	c.fail(apierr.New(apierr.Forbidden, "permission denied"))
}

// auditEvent 写查询本身的审计。写失败不返回数据（F-CON-08 规则 4）。
func (c *rc) auditEvent(params map[string]any) bool {
	if err := c.event(actionAuditQuery, audit.Target{}, params, audit.Success, 0); err != nil {
		c.fail(apierr.New(apierr.AuditUnavailable, "audit service unavailable, try again later"))
		return false
	}
	return true
}

func parseInt(s string) (int64, bool) {
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}

// auditFilter 是查询和导出共用的筛选条件（F-CON-09 规则 2）。
type auditFilter struct {
	where   []string
	args    []any
	filters map[string]any
}

func (f *auditFilter) add(cond string, v any) {
	f.args = append(f.args, v)
	f.where = append(f.where, strings.ReplaceAll(cond, "?", "$"+strconv.Itoa(len(f.args))))
}

func (f *auditFilter) sql() string { return strings.Join(f.where, " AND ") }

// parseAuditFilter 校验筛选条件。失败时已经写好响应，越权的空间按 action 留痕。
func (c *rc) parseAuditFilter(get func(string) string, action string) (*auditFilter, bool) {
	from, ok1 := parseInt(get("from"))
	to, ok2 := parseInt(get("to"))
	if !ok1 || !ok2 || from > to || to-from > auditMaxSpan.Milliseconds() {
		c.fail(apierr.New(apierr.BadRequest, "from and to (ms) are required, from <= to, and the range must be at most 31 days"))
		return nil, false
	}
	switch get("result") {
	case "", audit.Success, audit.Failure, audit.Denied, audit.Unknown:
	default:
		c.fail(apierr.New(apierr.BadRequest, "invalid result"))
		return nil, false
	}
	spaces, ok := c.auditSpaces(get("space"))
	if !ok {
		c.auditDenied(action)
		return nil, false
	}
	f := &auditFilter{where: []string{"ts >= $1", "ts <= $2", "space = ANY($3)"}, args: []any{from, to, spaces}, filters: map[string]any{"from": from, "to": to, "space": get("space")}}
	for param, cond := range map[string]string{"actor": "actor = ?", "action": "action = ?", "result": "result = ?", "requestId": "request_id = ?"} {
		if v := get(param); v != "" {
			f.add(cond, v)
			f.filters[param] = truncate(v, 128)
		}
	}
	if v := get("target"); v != "" {
		t := map[string]any{"ids": []string{v}}
		if typ, id, found := strings.Cut(v, ":"); found {
			t = map[string]any{"type": typ, "ids": []string{id}}
		}
		raw, _ := json.Marshal(t)
		f.add("target::jsonb @> ?::jsonb", string(raw))
		f.filters["target"] = truncate(v, 128)
	}
	return f, true
}

func (c *rc) auditQuery() {
	q := c.r.URL.Query()
	limit := 50
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > auditMaxLimit {
			c.fail(apierr.New(apierr.BadRequest, "limit must be 1..200"))
			return
		}
		limit = n
	}
	var cursor int64
	if v := q.Get("cursor"); v != "" {
		n, ok := parseInt(v)
		if !ok || n <= 0 {
			c.fail(apierr.New(apierr.BadRequest, "invalid cursor"))
			return
		}
		cursor = n
	}
	f, ok := c.parseAuditFilter(q.Get, actionAuditQuery)
	if !ok {
		return
	}
	if cursor > 0 {
		f.add("seq < ?", cursor)
		f.filters["cursor"] = cursor
	}
	where, args, filters := f.sql(), f.args, f.filters
	if !c.auditEvent(filters) {
		return
	}
	args = append(args, limit+1)
	rows, err := c.a.DB.Query(c.ctx, `SELECT `+audit.StoredColumns+` FROM audit.records WHERE `+where+` ORDER BY seq DESC LIMIT $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		c.failErr("audit query", err)
		return
	}
	list, err := collectStored(rows)
	if err != nil {
		c.failErr("audit query", err)
		return
	}
	var next int64
	if len(list) > limit {
		list = list[:limit]
		next = list[limit-1].Seq
	}
	items, err := c.withResultMissing(list)
	if err != nil {
		c.failErr("audit query", err)
		return
	}
	c.ok(map[string]any{"records": items, "nextCursor": next})
}

func collectStored(rows pgx.Rows) ([]audit.Stored, error) {
	defer rows.Close()
	var out []audit.Stored
	for rows.Next() {
		var s audit.Stored
		if err := s.Scan(rows); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// withResultMissing 标出还没有 result 的 intent（F-CON-08 规则 4 的"结果未知"）。
func (c *rc) withResultMissing(list []audit.Stored) ([]auditItem, error) {
	items := make([]auditItem, 0, len(list))
	var intents []string
	for _, s := range list {
		items = append(items, toItem(s))
		if s.Phase == audit.PhaseIntent {
			intents = append(intents, s.RequestID)
		}
	}
	if len(intents) == 0 {
		return items, nil
	}
	rows, err := c.a.DB.Query(c.ctx, `SELECT DISTINCT request_id FROM audit.records WHERE phase = 'result' AND request_id = ANY($1)`, intents)
	if err != nil {
		return nil, err
	}
	done, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	settled := make(map[string]bool, len(done))
	for _, id := range done {
		settled[id] = true
	}
	for i := range items {
		items[i].ResultMissing = items[i].Phase == audit.PhaseIntent && !settled[items[i].RequestID]
	}
	return items, nil
}

// auditRequest 是详情：同一 requestId 的 intent / result 合并显示（F-CON-09 规则 3）。
func (c *rc) auditRequest() {
	id := c.r.PathValue("requestId")
	spaces, ok := c.auditSpaces(c.r.URL.Query().Get("space"))
	if !ok {
		c.auditDenied(actionAuditQuery)
		return
	}
	if !c.auditEvent(map[string]any{"requestId": truncate(id, 128), "space": c.r.URL.Query().Get("space")}) {
		return
	}
	rows, err := c.a.DB.Query(c.ctx, `SELECT `+audit.StoredColumns+` FROM audit.records WHERE request_id = $1 AND space = ANY($2) ORDER BY seq`, id, spaces)
	if err != nil {
		c.failErr("audit request", err)
		return
	}
	list, err := collectStored(rows)
	if err != nil {
		c.failErr("audit request", err)
		return
	}
	if len(list) == 0 {
		c.fail(apierr.New(apierr.NotFound, "no audit records for this request"))
		return
	}
	var intent *auditItem
	results, events := []auditItem{}, []auditItem{}
	status := ""
	for _, s := range list {
		item := toItem(s)
		switch s.Phase {
		case audit.PhaseIntent:
			intent = &item
		case audit.PhaseResult:
			results = append(results, item)
			status = s.Result // 对账补写的结论在后面，以最后一条为准
		default:
			events = append(events, item)
		}
	}
	if intent != nil && status == "" {
		status = audit.Unknown
	}
	c.ok(map[string]any{"requestId": id, "status": status, "intent": intent, "results": results, "events": events})
}

// auditIM 跳转查看 im-server 侧同一 requestId 的记录。只能查本空间能看到的请求：
// 不然管理空间审计员可以拿运维空间的 requestId 从这里绕过空间隔离。
func (c *rc) auditIM() {
	id := c.r.URL.Query().Get("requestId")
	if id == "" {
		c.fail(apierr.New(apierr.BadRequest, "requestId is required"))
		return
	}
	spaces, ok := c.auditSpaces(c.r.URL.Query().Get("space"))
	if !ok {
		c.auditDenied(actionAuditQuery)
		return
	}
	if !c.auditEvent(map[string]any{"requestId": truncate(id, 128), "im": true}) {
		return
	}
	var ts *int64
	if err := c.a.DB.QueryRow(c.ctx, `SELECT min(ts) FROM audit.records WHERE request_id = $1 AND space = ANY($2)`, id, spaces).Scan(&ts); err != nil {
		c.failErr("audit im", err)
		return
	}
	if ts == nil {
		c.fail(apierr.New(apierr.NotFound, "no audit records for this request"))
		return
	}
	if c.a.IM == nil {
		c.fail(apierr.New(apierr.Unavailable, "im-server is not configured"))
		return
	}
	from := *ts - time.Minute.Milliseconds()
	to := min(c.now()+time.Minute.Milliseconds(), from+auditMaxSpan.Milliseconds())
	entries, err := c.a.imAuditRaw(c.ctx, c.ps.Name+":"+c.acct.ID, c.requestID, id, from, to)
	if err != nil {
		c.failErr("audit im", err)
		return
	}
	c.ok(map[string]any{"entries": entries})
}
