// Package audit 是审计写入（PRD-admin F-CON-08）：全局一条哈希链，多实例并发写严格串行。
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"tianting/console/internal/ids"
)

// 阶段和结果。
const (
	PhaseIntent = "intent"
	PhaseResult = "result"
	PhaseEvent  = "event"

	Success = "success"
	Failure = "failure"
	Denied  = "denied"
	Unknown = "unknown"
)

// maxTargets：目标超过 50 个时只记数量和前 50 个（规则 2）。
const maxTargets = 50

// Record 是一条审计记录。不放密码、动态码、恢复码、激活码、会话 ID、CSRF 令牌、密钥、消息正文、好友备注（规则 3）。
type Record struct {
	Seq       int64
	ID        string
	TS        int64
	Space     string
	Phase     string
	RequestID string
	AccountID string
	Username  string
	Roles     []string
	Actor     string // 命令行操作：cli:{操作系统用户}@{主机名}
	IP        string
	UA        string
	Action    string
	Target    Target
	Params    map[string]any
	Reason    string
	Ticket    string
	Result    string
	Code      int
	PrevHash  string
	Hash      string
}

// Target 是操作对象。
type Target struct {
	Type  string   `json:"type,omitempty"`
	IDs   []string `json:"ids,omitempty"`
	Count int      `json:"count,omitempty"`
}

// NewTarget 创建目标，自动截断到前 50 个。
func NewTarget(typ string, ids ...string) Target {
	t := Target{Type: typ, IDs: ids, Count: len(ids)}
	if len(ids) > maxTargets {
		t.IDs = ids[:maxTargets]
	}
	return t
}

// ErrInjected 是测试模式注入的写失败。
var ErrInjected = errors.New("injected audit write failure")

// Writer 写审计。Fault 是测试模式的故障注入：返回 true 时这个阶段写失败。
type Writer struct {
	DB    *pgxpool.Pool
	Now   func() time.Time
	Fault func(phase string) bool
	// OnCommit 在写入提交后调用，用来在满 1000 条时立即唤醒锚定任务。不能阻塞。
	OnCommit func(seq int64)
}

// Canonical 返回规范化 JSON：键排序、无空白、不转义 HTML。
func Canonical(v any) (string, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return string(bytes.TrimRight(b.Bytes(), "\n")), nil
}

// HashInput 是参与哈希的字段：roles、target、params 是已经规范化的文本。
type HashInput struct {
	Seq       int64  `json:"seq"`
	ID        string `json:"id"`
	TS        int64  `json:"ts"`
	Space     string `json:"space"`
	Phase     string `json:"phase"`
	RequestID string `json:"requestId"`
	AccountID string `json:"accountId"`
	Username  string `json:"username"`
	Roles     string `json:"roles"`
	Actor     string `json:"actor"`
	IP        string `json:"ip"`
	UA        string `json:"ua"`
	Action    string `json:"action"`
	Target    string `json:"target"`
	Params    string `json:"params"`
	Reason    string `json:"reason"`
	Ticket    string `json:"ticket"`
	Result    string `json:"result"`
	Code      int    `json:"code"`
	PrevHash  string `json:"prevHash"`
}

// ComputeHash 计算一条记录的哈希。先转成 map 再编码，键序由 encoding/json 排好。
func ComputeHash(in HashInput) (string, error) {
	raw, err := json.Marshal(in)
	if err != nil {
		return "", err
	}
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return "", err
	}
	c, err := Canonical(m)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(in.PrevHash + c))
	return hex.EncodeToString(sum[:]), nil
}

// Write 写一条记录：同一事务里锁链头、取 seq 和 prevHash、插入、更新链头。
func (w *Writer) Write(ctx context.Context, r Record) error {
	if w.Fault != nil && w.Fault(r.Phase) {
		return ErrInjected
	}
	now := w.Now()
	if r.ID == "" {
		r.ID = ids.New(now)
	}
	if r.TS == 0 {
		r.TS = now.UnixMilli()
	}
	if r.Roles == nil {
		r.Roles = []string{}
	}
	if r.Params == nil {
		r.Params = map[string]any{}
	}
	roles, err := Canonical(r.Roles)
	if err != nil {
		return err
	}
	target, err := Canonical(r.Target)
	if err != nil {
		return err
	}
	params, err := Canonical(r.Params)
	if err != nil {
		return err
	}
	var committed int64
	write := func(tx pgx.Tx) error {
		var seq, lastTS int64
		var prev string
		if err := tx.QueryRow(ctx, `SELECT seq, hash, ts FROM audit.chain_head WHERE id = 1 FOR UPDATE`).Scan(&seq, &prev, &lastTS); err != nil {
			return err
		}
		seq++
		committed = seq
		// ts 随 seq 单调不减：这样一个月分区里的 seq 一定连续，归档后链才接得上。
		ts := max(r.TS, lastTS)
		hash, err := ComputeHash(HashInput{
			Seq: seq, ID: r.ID, TS: ts, Space: r.Space, Phase: r.Phase, RequestID: r.RequestID, AccountID: r.AccountID, Username: r.Username,
			Roles: roles, Actor: r.Actor, IP: r.IP, UA: r.UA, Action: r.Action, Target: target, Params: params, Reason: r.Reason, Ticket: r.Ticket,
			Result: r.Result, Code: r.Code, PrevHash: prev,
		})
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO audit.records (seq, id, ts, space, phase, request_id, account_id, username, roles, actor, ip, ua, action, target, params, reason, ticket, result, code, prev_hash, hash)
			VALUES ($1, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)`,
			seq, r.ID, ts, r.Space, r.Phase, r.RequestID, r.AccountID, r.Username, roles, r.Actor, r.IP, r.UA, r.Action, target, params, r.Reason, r.Ticket, r.Result, r.Code, prev, hash); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE audit.chain_head SET seq = $1, hash = $2, ts = $3 WHERE id = 1`, seq, hash, ts)
		return err
	}
	err = pgx.BeginFunc(ctx, w.DB, write)
	// 正好在建这个月的分区时写入：语句已经路由到默认分区，等锁期间范围被划走了。重试一次就会路由到新分区。
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23514" {
		err = pgx.BeginFunc(ctx, w.DB, write)
	}
	if err == nil && w.OnCommit != nil {
		w.OnCommit(committed)
	}
	return err
}
