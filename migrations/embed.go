// Package migrations 把 SQL 迁移打包进二进制。
package migrations

import "embed"

// FS 是全部迁移文件。
//
//go:embed *.sql
var FS embed.FS
