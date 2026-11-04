package audit

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"tianting/console/internal/anchor"
)

// 校验发现的问题类型（F-CON-08 规则 8）。
const (
	IssueHashMismatch   = "hashMismatch"
	IssueGap            = "gap"
	IssueAnchorMismatch = "anchorMismatch"
	IssueTruncated      = "truncated"
)

// Issue 是第一个异常。
type Issue struct {
	Type   string
	Seq    int64
	Detail string
}

func (i Issue) String() string {
	if i.Detail == "" {
		return fmt.Sprintf("%s seq=%d", i.Type, i.Seq)
	}
	return fmt.Sprintf("%s seq=%d (%s)", i.Type, i.Seq, i.Detail)
}

// VerifyResult 是一次校验的结果。Issue 为 nil 表示通过。
type VerifyResult struct {
	Issue        *Issue
	Records      int64
	Anchors      int
	FirstSeq     int64
	LastSeq      int64
	AnchorSource string // external：比对外部存储；database：没有读取凭证，只比对库里的 audit.anchors
	Warnings     []string
}

// StoredColumns 是校验、归档和查询共用的列，顺序和 Stored.Scan 一致。
const StoredColumns = `seq, id::text, ts, space, phase, request_id, account_id, username, roles, actor, ip, ua, action, target, params, reason, ticket, result, code, prev_hash, hash`

// Stored 是库里的一条记录：roles、target、params 是原样的规范化文本。也是归档 JSONL 的一行。
type Stored struct {
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
	Hash      string `json:"hash"`
}

// Scan 读一行 StoredColumns。
func (s *Stored) Scan(row pgx.Rows) error {
	return row.Scan(&s.Seq, &s.ID, &s.TS, &s.Space, &s.Phase, &s.RequestID, &s.AccountID, &s.Username, &s.Roles, &s.Actor, &s.IP, &s.UA, &s.Action, &s.Target, &s.Params, &s.Reason, &s.Ticket, &s.Result, &s.Code, &s.PrevHash, &s.Hash)
}

// Recompute 按记录内容重算哈希。
func (s *Stored) Recompute() (string, error) {
	return ComputeHash(HashInput{
		Seq: s.Seq, ID: s.ID, TS: s.TS, Space: s.Space, Phase: s.Phase, RequestID: s.RequestID, AccountID: s.AccountID, Username: s.Username,
		Roles: s.Roles, Actor: s.Actor, IP: s.IP, UA: s.UA, Action: s.Action, Target: s.Target, Params: s.Params, Reason: s.Reason, Ticket: s.Ticket,
		Result: s.Result, Code: s.Code, PrevHash: s.PrevHash,
	})
}

// walker 逐条校验：seq 连续、prevHash 相连、哈希正确、和锚定一致。校验和归档用同一份逻辑。
type walker struct {
	expected int64
	prev     string
	linked   bool // prev 是否可信（--from-seq 的前一条可能不存在）
	anchors  map[int64][]string
}

func (w *walker) check(s *Stored) (*Issue, error) {
	if s.Seq != w.expected {
		return &Issue{Type: IssueGap, Seq: w.expected, Detail: fmt.Sprintf("next record is seq %d", s.Seq)}, nil
	}
	if w.linked && s.PrevHash != w.prev {
		return &Issue{Type: IssueHashMismatch, Seq: s.Seq, Detail: "prevHash does not match the previous record"}, nil
	}
	got, err := s.Recompute()
	if err != nil {
		return nil, err
	}
	if got != s.Hash {
		return &Issue{Type: IssueHashMismatch, Seq: s.Seq}, nil
	}
	for _, h := range w.anchors[s.Seq] {
		if h != s.Hash {
			return &Issue{Type: IssueAnchorMismatch, Seq: s.Seq}, nil
		}
	}
	w.expected, w.prev, w.linked = s.Seq+1, s.Hash, true
	return nil, nil
}

// archiveRange 是一个已归档的分区。
type archiveRange struct {
	name        string
	first, last int64
	hash        string
}

func loadArchives(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}) ([]archiveRange, error) {
	rows, err := q.Query(ctx, `SELECT partition_name, seq_first, seq_last, last_hash FROM audit.archives ORDER BY seq_first`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (archiveRange, error) {
		var a archiveRange
		err := r.Scan(&a.name, &a.first, &a.last, &a.hash)
		return a, err
	})
}

// checkArchives：归档段必须从 1 开始首尾相接，每段的末条要有外部锚定（归档时写的）。
// 没有这一步，有库权限的人可以伪造一条 audit.archives，再删掉前面的记录。
func checkArchives(list []archiveRange, anchors map[int64][]string) *Issue {
	next := int64(1)
	for _, a := range list {
		if a.first != next {
			return &Issue{Type: IssueGap, Seq: next, Detail: "archive " + a.name + " does not continue the chain"}
		}
		hashes := anchors[a.last]
		if len(hashes) == 0 {
			return &Issue{Type: IssueAnchorMismatch, Seq: a.last, Detail: "archive " + a.name + " has no anchor"}
		}
		for _, h := range hashes {
			if h != a.hash {
				return &Issue{Type: IssueAnchorMismatch, Seq: a.last, Detail: "archive " + a.name}
			}
		}
		next = a.last + 1
	}
	return nil
}

// Verify 校验审计链（F-CON-08 规则 8）。reader 为 nil 时只比对库里的 audit.anchors，结果的 AnchorSource 是 database。
//
// 顺序有讲究：先读外部锚定、再开快照。锚定的 seq 在写外部之前已经提交，所以快照里一定有它，
// 不会因为校验期间新写了锚定而误报 truncated。
func Verify(ctx context.Context, db *pgxpool.Pool, fromSeq int64, reader anchor.Reader) (VerifyResult, error) {
	res := VerifyResult{AnchorSource: "database"}
	external := map[int64][]string{}
	latestExternal := int64(0)
	if reader != nil {
		res.AnchorSource = "external"
		points, err := reader.List(ctx)
		if err != nil {
			return res, fmt.Errorf("read external anchors: %w", err)
		}
		for _, p := range points {
			external[p.Seq] = append(external[p.Seq], p.Hash)
			latestExternal = max(latestExternal, p.Seq)
		}
	}
	err := pgx.BeginTxFunc(ctx, db, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT seq, hash FROM audit.anchors ORDER BY seq`)
		if err != nil {
			return err
		}
		dbAnchors, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (anchor.Point, error) {
			var p anchor.Point
			err := r.Scan(&p.Seq, &p.Hash)
			return p, err
		})
		if err != nil {
			return err
		}
		anchors := external
		if reader == nil {
			for _, p := range dbAnchors {
				anchors[p.Seq] = append(anchors[p.Seq], p.Hash)
				latestExternal = max(latestExternal, p.Seq)
			}
		} else {
			// 库里有、外部没有的锚定不可能是正常写入产生的（先写外部再写库）。比最新外部锚定还新的是校验开始后写的，不算。
			for _, p := range dbAnchors {
				if p.Seq <= latestExternal && len(external[p.Seq]) == 0 {
					res.Issue = &Issue{Type: IssueAnchorMismatch, Seq: p.Seq, Detail: "database anchor is missing from the external store"}
					return nil
				}
			}
		}
		for _, list := range anchors {
			res.Anchors += len(list)
		}

		archives, err := loadArchives(ctx, tx)
		if err != nil {
			return err
		}
		if res.Issue = checkArchives(archives, anchors); res.Issue != nil {
			return nil
		}
		w := &walker{expected: 1, linked: true, anchors: anchors}
		if n := len(archives); n > 0 {
			w.expected, w.prev = archives[n-1].last+1, archives[n-1].hash
		}
		if fromSeq > w.expected {
			w.expected, w.linked = fromSeq, false
			err := tx.QueryRow(ctx, `SELECT hash FROM audit.records WHERE seq = $1`, fromSeq-1).Scan(&w.prev)
			switch {
			case err == nil:
				w.linked = true
			case !errors.Is(err, pgx.ErrNoRows):
				return err
			}
		}
		res.FirstSeq = w.expected

		rows, err = tx.Query(ctx, `SELECT `+StoredColumns+` FROM audit.records WHERE seq >= $1 ORDER BY seq, ts`, w.expected)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s Stored
			if err := s.Scan(rows); err != nil {
				return err
			}
			issue, err := w.check(&s)
			if err != nil {
				return err
			}
			if issue != nil {
				res.Issue = issue
				return nil
			}
			res.Records++
			res.LastSeq = s.Seq
		}
		if err := rows.Err(); err != nil {
			return err
		}
		maxSeq := w.expected - 1
		if res.Records == 0 && fromSeq > 1 {
			// 从 --from-seq 往后没有记录：还要看整条链到哪儿。
			var m *int64
			if err := tx.QueryRow(ctx, `SELECT max(seq) FROM audit.records`).Scan(&m); err != nil {
				return err
			}
			maxSeq = 0
			if m != nil {
				maxSeq = *m
			}
			if n := len(archives); n > 0 {
				maxSeq = max(maxSeq, archives[n-1].last)
			}
		}
		if maxSeq < latestExternal {
			res.Issue = &Issue{Type: IssueTruncated, Seq: maxSeq + 1, Detail: fmt.Sprintf("latest anchor is seq %d, chain ends at seq %d", latestExternal, maxSeq)}
			return nil
		}
		// 最近一次锚定之后被截断是已接受的风险（PRD 第 13.2 节），不算失败。但链头还记着，提示一下。
		var head int64
		if err := tx.QueryRow(ctx, `SELECT seq FROM audit.chain_head WHERE id = 1`).Scan(&head); err != nil {
			return err
		}
		if head > maxSeq {
			res.Warnings = append(res.Warnings, fmt.Sprintf("chain head is seq %d but the last record is seq %d: records after the latest anchor may have been removed", head, maxSeq))
		}
		return nil
	})
	return res, err
}
