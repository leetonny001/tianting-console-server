// Package dbx 是数据库迁移和连接。迁移规则和 im-server 相同：嵌入二进制、带校验和、已执行的文件不能改。
package dbx

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"tianting/console/migrations"
)

// Migration 是一个迁移文件。
type Migration struct {
	Version  int
	Name     string
	SQL      string
	Checksum string
}

// Row 是一条迁移的状态。
type Row struct {
	Version    int
	Name       string
	AppliedAt  time.Time // 零值表示未执行
	ChecksumOK bool
	Pending    bool
}

var fileRe = regexp.MustCompile(`^(\d{4})_([a-z0-9_]+)\.sql$`)

const migrationLock = 7264001 // pg_advisory_lock 的键：多实例同时 migrate up 时排队

// Load 读取嵌入的迁移。
func Load() ([]Migration, error) { return load(migrations.FS) }

func load(fsys fs.FS) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	var out []Migration
	for _, e := range entries {
		m := fileRe.FindStringSubmatch(e.Name())
		if m == nil {
			if e.Name() == "embed.go" {
				continue
			}
			return nil, fmt.Errorf("bad migration file name %q", e.Name())
		}
		raw, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			return nil, err
		}
		v, _ := strconv.Atoi(m[1])
		sum := sha256.Sum256(raw)
		out = append(out, Migration{Version: v, Name: m[2], SQL: string(raw), Checksum: hex.EncodeToString(sum[:])})
	}
	slices.SortFunc(out, func(a, b Migration) int { return a.Version - b.Version })
	for i, m := range out {
		if m.Version != i+1 {
			return nil, fmt.Errorf("migrations must be numbered without gaps: %04d", m.Version)
		}
	}
	return out, nil
}

const migrationsTable = `CREATE TABLE IF NOT EXISTS public.schema_migrations (
	version    integer PRIMARY KEY,
	name       text NOT NULL,
	checksum   text NOT NULL,
	applied_at timestamptz NOT NULL DEFAULT now()
)`

// Up 执行未执行的迁移，每个迁移一个事务。用 console_owner 连接。
func Up(ctx context.Context, url string) ([]int, error) {
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		return nil, err
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLock); err != nil {
		return nil, err
	}
	defer func() { _, _ = conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, migrationLock) }()
	if _, err := conn.Exec(ctx, migrationsTable); err != nil {
		return nil, err
	}
	ms, err := Load()
	if err != nil {
		return nil, err
	}
	rows, err := report(ctx, conn, ms)
	if err != nil {
		return nil, err
	}
	var done []int
	for i, r := range rows {
		if r.Pending {
			m := ms[i]
			if err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
				// 多条语句走简单协议（Exec 不带参数）。
				if _, err := tx.Exec(ctx, m.SQL); err != nil {
					return err
				}
				_, err := tx.Exec(ctx, `INSERT INTO public.schema_migrations (version, name, checksum) VALUES ($1, $2, $3)`, m.Version, m.Name, m.Checksum)
				return err
			}); err != nil {
				return done, fmt.Errorf("migration %04d_%s: %w", m.Version, m.Name, err)
			}
			done = append(done, m.Version)
			continue
		}
		if !r.ChecksumOK {
			return done, fmt.Errorf("migration %04d_%s was modified after being applied; add a new migration instead", r.Version, r.Name)
		}
	}
	return done, nil
}

// Status 只读地返回每个迁移的状态。
func Status(ctx context.Context, url string) ([]Row, error) {
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		return nil, err
	}
	defer conn.Close(ctx)
	ms, err := Load()
	if err != nil {
		return nil, err
	}
	return report(ctx, conn, ms)
}

func report(ctx context.Context, conn *pgx.Conn, ms []Migration) ([]Row, error) {
	applied := map[int]Row{}
	sums := map[int]string{}
	rows, err := conn.Query(ctx, `SELECT version, name, checksum, applied_at FROM public.schema_migrations`)
	var pgErr *pgconn.PgError
	switch {
	case errors.As(err, &pgErr) && pgErr.Code == "42P01": // 表还不存在：全部未执行
	case err != nil:
		return nil, err
	default:
		defer rows.Close()
		for rows.Next() {
			var r Row
			var sum string
			if err := rows.Scan(&r.Version, &r.Name, &sum, &r.AppliedAt); err != nil {
				return nil, err
			}
			applied[r.Version], sums[r.Version] = r, sum
		}
		if err := rows.Err(); err != nil {
			if !errors.As(err, &pgErr) || pgErr.Code != "42P01" {
				return nil, err
			}
		}
	}
	out := make([]Row, 0, len(ms))
	for _, m := range ms {
		r, ok := applied[m.Version]
		if !ok {
			out = append(out, Row{Version: m.Version, Name: m.Name, Pending: true, ChecksumOK: true})
			continue
		}
		r.ChecksumOK = sums[m.Version] == m.Checksum
		out = append(out, r)
	}
	return out, nil
}
