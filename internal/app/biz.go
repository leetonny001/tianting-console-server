package app

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"tianting/console/internal/apierr"
	"tianting/console/internal/imclient"
	"tianting/console/internal/secret"
)

// 业务公共层（CS-020）。

const (
	// imBatchSize 是 im-server 单次的上限（ADMIN.md）。
	imBatchSize     = 500
	maxGroupMembers = 2000
)

var (
	idRe     = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	shanghai = time.FixedZone("Asia/Shanghai", 8*3600) // 没有夏令时；不依赖系统的时区数据库
)

func validID(s string) bool { return idRe.MatchString(s) }

// CheckReason 校验理由：去首尾空白后 4～200 个码点，不能由同一字符重复组成。返回去空白后的理由。
func CheckReason(raw string) (string, *apierr.Error) {
	bad := &apierr.Error{Code: apierr.BadRequest, Msg: "reason must be 4 to 200 characters and not a single repeated character", Reason: "reasonInvalid"}
	if !validReason(raw) {
		return "", bad
	}
	return strings.TrimSpace(raw), nil
}

// reasonTicket 校验理由和可选的工单号。失败时已经写好响应。
func (c *rc) reasonTicket(rawReason, ticket string) (string, bool) {
	reason, e := CheckReason(rawReason)
	if e != nil {
		c.fail(e)
		return "", false
	}
	if ticket != "" && !c.a.Cfg.TicketPattern.MatchString(ticket) {
		c.fail(&apierr.Error{Code: apierr.BadRequest, Msg: "invalid ticket", Reason: "ticketInvalid"})
		return "", false
	}
	return reason, true
}

// dailyQuota 是每日上限（Asia/Shanghai）：按不同对象计数，已查过的不重复计数。超出 429 / 4292。
func (c *rc) dailyQuota(kind, key string, limit int) bool {
	day := c.a.Clock.Now().In(shanghai).Format("2006-01-02")
	exceeded := false
	err := pgx.BeginFunc(c.ctx, c.a.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(c.ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "quota:"+c.acct.ID+":"+kind+":"+day); err != nil {
			return err
		}
		var seen bool
		if err := tx.QueryRow(c.ctx, `SELECT EXISTS (SELECT 1 FROM biz.daily_quota WHERE account_id = $1::uuid AND kind = $2 AND day = $3 AND key = $4)`, c.acct.ID, kind, day, key).Scan(&seen); err != nil || seen {
			return err
		}
		var n int
		if err := tx.QueryRow(c.ctx, `SELECT count(*) FROM biz.daily_quota WHERE account_id = $1::uuid AND kind = $2 AND day = $3`, c.acct.ID, kind, day).Scan(&n); err != nil {
			return err
		}
		if n >= limit {
			exceeded = true
			return nil
		}
		_, err := tx.Exec(c.ctx, `INSERT INTO biz.daily_quota (account_id, kind, day, key) VALUES ($1::uuid, $2, $3, $4)`, c.acct.ID, kind, day, key)
		return err
	})
	if err != nil {
		c.failErr("daily quota", err)
		return false
	}
	if exceeded {
		c.fail(apierr.New(apierr.QuotaExceeded, "daily limit reached"))
		return false
	}
	return true
}

// minuteRate 是每账号每分钟的限流。超出 429 / 4290。
func (c *rc) minuteRate(kind string, limit int) bool {
	var n int
	err := c.a.DB.QueryRow(c.ctx, `INSERT INTO biz.minute_rate (account_id, kind, minute, count) VALUES ($1::uuid, $2, $3, 1)
		ON CONFLICT (account_id, kind, minute) DO UPDATE SET count = biz.minute_rate.count + 1 RETURNING count`, c.acct.ID, kind, c.now()/60_000).Scan(&n)
	if err != nil {
		c.failErr("minute rate", err)
		return false
	}
	if n > limit {
		c.fail(apierr.New(apierr.RateLimited, "too many requests, try again later"))
		return false
	}
	return true
}

// listParams 校验列表参数：limit ∈ {20, 50, 100}；关键字去空白后 1～64 个字符。返回转给 im-server 的查询串。
func (c *rc) listParams(keys ...string) (url.Values, bool) {
	q := c.r.URL.Query()
	out := url.Values{}
	if v := q.Get("limit"); v != "" {
		if v != "20" && v != "50" && v != "100" {
			c.fail(apierr.New(apierr.BadRequest, "limit must be 20, 50 or 100"))
			return nil, false
		}
		out.Set("limit", v)
	}
	if q.Has("q") {
		kw := strings.TrimSpace(q.Get("q"))
		if n := utf8.RuneCountInString(kw); n < 1 || n > 64 {
			c.fail(apierr.New(apierr.BadRequest, "keyword must be 1 to 64 characters"))
			return nil, false
		}
		out.Set("q", kw)
	}
	for _, k := range keys {
		if v := q.Get(k); v != "" {
			out.Set(k, v)
		}
	}
	return out, true
}

func (c *rc) operator() string { return c.ps.Name + ":" + c.acct.ID }

// imDo 调用 im-server，requestID 是这一次的 X-Request-Id。不继承请求的取消：浏览器断开时写操作不能算成失败。
func (c *rc) imDo(requestID, method, path string, query url.Values, body, out any) error {
	if c.a.IM == nil {
		return apierr.New(apierr.Unavailable, "im-server is not configured")
	}
	return c.a.IM.Do(context.WithoutCancel(c.ctx), imclient.Call{Operator: c.operator(), RequestID: requestID}, method, path, query, body, out)
}

// im 是一次性调用：X-Request-Id 就是这次请求的 requestId，对账按它查。
func (c *rc) im(method, path string, query url.Values, body, out any) error {
	return c.imDo(c.requestID, method, path, query, body, out)
}

// imRead 是不写审计的只读查询：直接回 im-server 的响应。
func (c *rc) imRead(path string, query url.Values) {
	var out map[string]any
	if err := c.im("GET", path, query, nil, &out); err != nil {
		c.failErr("im read", err)
		return
	}
	c.ok(out)
}

func pathID(s string) string { return url.PathEscape(s) }

// chunks 把 list 按 size 切批。
func chunks[T any](list []T, size int) [][]T {
	var out [][]T
	for len(list) > size {
		out = append(out, list[:size])
		list = list[size:]
	}
	if len(list) > 0 {
		out = append(out, list)
	}
	return out
}

func batchCount(n int) int { return (n + imBatchSize - 1) / imBatchSize }

// batchRequestID 是拆批调用的 X-Request-Id：{requestId}.{批号}，批号从 1 开始。对账靠 intent 的 params.batches 逐批查。
func batchRequestID(requestID string, batch int) string { return requestID + "." + strconv.Itoa(batch) }

// batchResponse 是拆批操作的响应。部分失败也是 200：页面要显示"已成功 1 批 / 共 3 批"。
type batchResponse struct {
	SucceededBatches int    `json:"succeededBatches"`
	TotalBatches     int    `json:"totalBatches"`
	FailedCode       int    `json:"failedCode,omitempty"`
	FailedMsg        string `json:"failedMsg,omitempty"`
}

// partialError：操作部分完成。审计按失败记，响应照常 200 带 Resp。超时不走这里：还是 504。
type partialError struct {
	Resp any
	Err  error
}

func (p *partialError) Error() string { return p.Err.Error() }
func (p *partialError) Unwrap() error { return p.Err }

// runBatches 依次调用每一批，失败就停，后面的批不调用（AC-ADM-11-4）。
func (c *rc) runBatches(total int, call func(batch int, requestID string) error) (any, error) {
	resp := batchResponse{TotalBatches: total}
	for i := 1; i <= total; i++ {
		err := call(i, batchRequestID(c.requestID, i))
		if err == nil {
			resp.SucceededBatches = i
			continue
		}
		c.resultParams = map[string]any{"succeededBatches": resp.SucceededBatches, "totalBatches": total}
		if errors.Is(err, imclient.ErrResultUnknown) {
			return nil, err // 这一批不知道结果：504 / 5040，由对账补写
		}
		var e *apierr.Error
		if !errors.As(err, &e) {
			return nil, err
		}
		c.resultParams["failedCode"] = e.Code
		resp.FailedCode, resp.FailedMsg = e.Code, e.Msg
		return nil, &partialError{Resp: resp, Err: e}
	}
	c.resultParams = map[string]any{"succeededBatches": total, "totalBatches": total}
	return resp, nil
}

func dedupeIDs(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, id := range in {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// checkIDs 校验一组 userId，失败 400 / 4004。
func (c *rc) checkIDs(ids []string) bool {
	for _, id := range ids {
		if !validID(id) {
			c.fail(apierr.New(apierr.InvalidID, "invalid userId"))
			return false
		}
	}
	return true
}

// sessionKey 是元数据会话表的键：不存原始的会话 ID。
func (c *rc) sessionKey() string { return secret.SessionHash(c.sid) }

func describeChange(oldV, newV any) string { return fmt.Sprintf("%v → %v", oldV, newV) }
