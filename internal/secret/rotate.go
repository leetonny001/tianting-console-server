package secret

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MissingKIDs 返回库里有记录在用、配置里却没有的 kid（AC-CON-11-2：启动时拒绝，并指出来）。
func MissingKIDs(ctx context.Context, db *pgxpool.Pool, k Keyring) ([]string, error) {
	rows, err := db.Query(ctx, `SELECT DISTINCT kid FROM auth.totp ORDER BY kid`)
	if err != nil {
		return nil, err
	}
	used, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(used, func(id string) bool { _, ok := k.Keys[id]; return ok }), nil
}

// MissingKIDProblem 把缺少的 kid 写成启动错误。
func MissingKIDProblem(kids []string) string {
	return fmt.Sprintf("CON_DATA_KEYS is missing %s, still used by stored records; restore it or run `console-server keys rotate` first", strings.Join(kids, ", "))
}

// Rotate 用当前密钥重新加密全部旧记录（console-server keys rotate）。可以中断后重跑。返回处理的条数。
func Rotate(ctx context.Context, db *pgxpool.Pool, k Keyring) (int, error) {
	if _, ok := k.Keys[k.Active]; !ok {
		return 0, fmt.Errorf("no active data key")
	}
	done := 0
	for {
		n := 0
		err := pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT account_id, kid, nonce, ciphertext FROM auth.totp WHERE kid <> $1 ORDER BY account_id LIMIT 100 FOR UPDATE`, k.Active)
			if err != nil {
				return err
			}
			type rec struct {
				id        int64
				kid       string
				nonce, ct []byte
			}
			var batch []rec
			for rows.Next() {
				var r rec
				if err := rows.Scan(&r.id, &r.kid, &r.nonce, &r.ct); err != nil {
					return err
				}
				batch = append(batch, r)
			}
			if err := rows.Err(); err != nil {
				return err
			}
			for _, r := range batch {
				plain, err := k.Decrypt(r.id, r.kid, r.nonce, r.ct)
				if err != nil {
					return fmt.Errorf("account %d: %w", r.id, err)
				}
				kid, nonce, ct, err := k.Encrypt(r.id, plain)
				if err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, `UPDATE auth.totp SET kid = $2, nonce = $3, ciphertext = $4 WHERE account_id = $1`, r.id, kid, nonce, ct); err != nil {
					return err
				}
			}
			n = len(batch)
			return nil
		})
		if err != nil {
			return done, err
		}
		done += n
		if n == 0 {
			return done, nil
		}
	}
}
