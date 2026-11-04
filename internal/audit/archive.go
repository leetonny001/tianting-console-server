package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"filippo.io/age"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"tianting/console/internal/anchor"
	"tianting/console/internal/objstore"
)

// Archiver 把满 1 年的月分区加密归档后删除（F-CON-09 规则 6、CS-015）。DB 用 console_archiver 连接。
type Archiver struct {
	DB        *pgxpool.Pool
	Store     *objstore.Store
	Recipient age.Recipient
	Identity  age.Identity // 只有测试环境有：顺带核对能解密。生产环境私钥线下保存，只核对密文哈希
	Sink      anchor.Sink
	Reader    anchor.Reader
	Years     int
	Now       func() time.Time
	// Record 写审计（用运行账号）。写失败时不删分区。
	Record func(ctx context.Context, done Archived) error
}

// Archived 是归档好的一个分区。
type Archived struct {
	Partition   string
	First, Last int64
	Count       int64
	Key         string
	SHA256      string
	RetainUntil time.Time
}

// PartitionName 是月分区的表名。
func PartitionName(t time.Time) string { return "records_" + t.UTC().Format("200601") }

type monthPartition struct {
	name     string
	from, to time.Time
}

// eligible 是整个月都早于 1 年前的分区，从旧到新。默认分区里的旧数据先搬进月分区。
func (ar *Archiver) eligible(ctx context.Context) ([]monthPartition, error) {
	cutoff := ar.Now().UTC().AddDate(-1, 0, 0)
	var minTS, maxTS *int64
	if err := ar.DB.QueryRow(ctx, `SELECT min(ts), max(ts) FROM audit.records WHERE tableoid = 'audit.records_default'::regclass AND ts < $1`, cutoff.UnixMilli()).Scan(&minTS, &maxTS); err != nil {
		return nil, err
	}
	if minTS != nil {
		for m := monthStart(time.UnixMilli(*minTS)); !m.After(time.UnixMilli(*maxTS)); m = m.AddDate(0, 1, 0) {
			if _, err := ar.DB.Exec(ctx, `SELECT audit.ensure_partition($1, $2)`, m.Year(), int(m.Month())); err != nil {
				return nil, err
			}
		}
	}
	rows, err := ar.DB.Query(ctx, `SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid WHERE i.inhparent = 'audit.records'::regclass AND c.relname ~ '^records_[0-9]{6}$' ORDER BY c.relname`)
	if err != nil {
		return nil, err
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	var out []monthPartition
	for _, name := range names {
		from, err := time.Parse("200601", name[len("records_"):])
		if err != nil {
			return nil, fmt.Errorf("unexpected partition name %q", name)
		}
		to := from.AddDate(0, 1, 0)
		if !to.After(cutoff) {
			out = append(out, monthPartition{name: name, from: from, to: to})
		}
	}
	return out, nil
}

func monthStart(t time.Time) time.Time {
	u := t.UTC()
	return time.Date(u.Year(), u.Month(), 1, 0, 0, 0, 0, time.UTC)
}

// Run 归档全部到期的分区。空分区跳过（没有东西要保存，留着无害）。
func (ar *Archiver) Run(ctx context.Context) ([]Archived, error) {
	parts, err := ar.eligible(ctx)
	if err != nil {
		return nil, err
	}
	var done []Archived
	for _, p := range parts {
		d, err := ar.one(ctx, p)
		if err != nil {
			return done, fmt.Errorf("archive %s: %w", p.name, err)
		}
		if d != nil {
			done = append(done, *d)
		}
	}
	return done, nil
}

// anchors 读全部锚定：外部优先。
func (ar *Archiver) anchors(ctx context.Context) (map[int64][]string, error) {
	out := map[int64][]string{}
	if ar.Reader != nil {
		points, err := ar.Reader.List(ctx)
		if err != nil {
			return nil, fmt.Errorf("read external anchors: %w", err)
		}
		for _, p := range points {
			out[p.Seq] = append(out[p.Seq], p.Hash)
		}
		return out, nil
	}
	rows, err := ar.DB.Query(ctx, `SELECT seq, hash FROM audit.anchors`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var seq int64
		var hash string
		if err := rows.Scan(&seq, &hash); err != nil {
			return nil, err
		}
		out[seq] = append(out[seq], hash)
	}
	return out, rows.Err()
}

func (ar *Archiver) one(ctx context.Context, p monthPartition) (*Archived, error) {
	anchors, err := ar.anchors(ctx)
	if err != nil {
		return nil, err
	}
	archives, err := loadArchives(ctx, ar.DB)
	if err != nil {
		return nil, err
	}
	if issue := checkArchives(archives, anchors); issue != nil {
		return nil, fmt.Errorf("archive chain is broken: %s", issue)
	}
	w := &walker{expected: 1, linked: true, anchors: anchors}
	if n := len(archives); n > 0 {
		w.expected, w.prev = archives[n-1].last+1, archives[n-1].hash
	}

	// 明文不落盘：边读边加密，写进 0600 的临时文件。
	tmp, err := os.CreateTemp("", "audit-archive-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	enc, err := age.Encrypt(tmp, ar.Recipient)
	if err != nil {
		return nil, err
	}
	d := Archived{Partition: p.name}
	lastHash := ""
	lineEnc := json.NewEncoder(enc)
	lineEnc.SetEscapeHTML(false)
	rows, err := ar.DB.Query(ctx, `SELECT `+StoredColumns+` FROM audit.records WHERE ts >= $1 AND ts < $2 ORDER BY seq`, p.from.UnixMilli(), p.to.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var s Stored
		if err := s.Scan(rows); err != nil {
			return nil, err
		}
		issue, err := w.check(&s)
		if err != nil {
			return nil, err
		}
		if issue != nil {
			return nil, fmt.Errorf("chain check failed, partition kept: %s", issue)
		}
		if err := lineEnc.Encode(&s); err != nil {
			return nil, err
		}
		if d.Count == 0 {
			d.First = s.Seq
		}
		d.Count++
		d.Last, lastHash = s.Seq, s.Hash
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	if d.Count == 0 {
		return nil, nil
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, tmp); err != nil {
		return nil, err
	}
	d.SHA256 = hex.EncodeToString(hasher.Sum(nil))
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	now := ar.Now()
	d.Key = fmt.Sprintf("archive/%s-%020d-%020d.jsonl.age", p.name, d.First, d.Last)
	d.RetainUntil = time.Now().AddDate(ar.Years, 0, 0)
	if err := ar.Store.Put(ctx, d.Key, tmp, d.RetainUntil); err != nil {
		return nil, err
	}
	if err := ar.confirm(ctx, d); err != nil {
		return nil, err
	}
	// 归档段的末条写一个外部锚定：之后 verify 从这里接续，靠它证明 audit.archives 没被改过。
	point := anchor.Point{Seq: d.Last, Hash: lastHash, TS: now.UnixMilli()}
	if ar.Sink != nil {
		if err := ar.Sink.Put(ctx, point); err != nil {
			return nil, fmt.Errorf("anchor archive end: %w", err)
		}
	}
	if ar.Record != nil {
		if err := ar.Record(ctx, d); err != nil {
			return nil, fmt.Errorf("audit write failed, partition kept: %w", err)
		}
	}
	err = pgx.BeginFunc(ctx, ar.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO audit.anchors (seq, hash, ts) VALUES ($1, $2, $3) ON CONFLICT (seq) DO NOTHING`, point.Seq, point.Hash, point.TS); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO audit.archives (partition_name, seq_first, seq_last, last_hash, record_count, object_key, ciphertext_sha256, archived_at, retain_until)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, p.name, d.First, d.Last, lastHash, d.Count, d.Key, d.SHA256, now.UnixMilli(), d.RetainUntil.UnixMilli()); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `SELECT audit.drop_archived_partition($1)`, p.name)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// confirm 读回对象核对密文哈希。测试环境有私钥时再解密核对条数和末条哈希（CS-015 内容 2）。
func (ar *Archiver) confirm(ctx context.Context, d Archived) error {
	rc, err := ar.Store.Get(ctx, d.Key)
	if err != nil {
		return fmt.Errorf("read back archive: %w", err)
	}
	defer rc.Close()
	hasher := sha256.New()
	var src io.Reader = io.TeeReader(rc, hasher)
	if ar.Identity != nil {
		plain, err := age.Decrypt(src, ar.Identity)
		if err != nil {
			return fmt.Errorf("decrypt archive: %w", err)
		}
		dec := json.NewDecoder(plain)
		var n int64
		var last Stored
		for {
			var s Stored
			err := dec.Decode(&s)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return fmt.Errorf("decode archive: %w", err)
			}
			n++
			last = s
		}
		if n != d.Count || last.Seq != d.Last {
			return fmt.Errorf("archive content does not match: %d records, last seq %d", n, last.Seq)
		}
	}
	if _, err := io.Copy(hasher, rc); err != nil {
		return err
	}
	if got := hex.EncodeToString(hasher.Sum(nil)); got != d.SHA256 {
		return errors.New("archive ciphertext hash does not match")
	}
	return nil
}
