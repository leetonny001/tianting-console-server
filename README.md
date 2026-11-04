# tianting-console-server

管理后台和运维后台的服务端（Go + Postgres）。一个二进制，每个账号空间一个监听地址。规格见 tianting-server 的 `docs/prd/PRD-admin-v1.0.md` 第 4 节和 `docs/tasks/console.md`。

## 本地开发

需要 Postgres 17（本机只监听 localhost）：

```bash
$(brew --prefix postgresql@17)/bin/pg_ctl -D $(brew --prefix)/var/postgresql@17 -l $(brew --prefix)/var/postgresql@17/server.log start
```

```bash
CON_OWNER_DATABASE_URL='postgres://127.0.0.1:5432/tianting_console_dev?sslmode=disable' go run ./cmd/console-server migrate up
```

```bash
CON_DATABASE_URL='postgres://127.0.0.1:5432/tianting_console_dev?sslmode=disable' go run ./cmd/console-server
```

## 测试

```bash
go test -race ./...
```

`e2e/` 每个用例建一个独立的库，用完删除。Postgres 不可用时跳过（CI 设 `CON_TEST_REQUIRE_DB=1` 时失败）。同级目录有 tianting-server 时会对真实 im-server 跑签名调用（`TIANTING_SERVER_DIR` 可以指定位置）。

协议文件（错误码、签名向量）从 tianting-server 同步：`scripts/sync-protocol.sh`。
