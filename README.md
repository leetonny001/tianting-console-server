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

## 审计

- `console-server audit verify [--from-seq N]`：校验哈希链和外部锚定，第一个异常输出 `FAILED {gap|hashMismatch|anchorMismatch|truncated} seq=N` 并非 0 退出。每天由 `deploy/console-audit-verify.timer` 运行，失败时站内通知超管和审计员。
- `console-server audit archive`：把满 1 年的月分区用 age 加密写进归档桶、核对后删除。每月由 `deploy/console-audit-archive.timer` 运行。
- **凭证分开**：服务进程（`console-server.env`）只有锚定桶的写入凭证；读取凭证和归档凭证只放 `audit-tasks.env`，只给上面两个命令。校验比对的是外部存储，因为能改审计表的人同样能改库里的 `audit.anchors`。
- 对账：每 10 分钟补写缺失的结论。只改 console 自己数据库的动作（`account.*`、`auth.*`、`audit.*`）im-server 查不到，补写 `result=unknown`、`params.reconciled="localOnly"`，不会声称"没有执行"。
- `tools/minio-test.sh` 用真实的 MinIO（Object Lock）跑一遍读写权限，需要 docker，CI 里运行。

## 运维模块

接口清单是 `api/ops-routes.yaml`，启动时和注册的路由比对，不一致就启动失败；权限矩阵测试用它做数据源。节点凭证、Prometheus、Alertmanager、备份桶、Grafana 的配置见 `deploy/console-server.env.example`。

- 总览和节点列表只读 Postgres 里的探测结果（每 5 秒一次，多实例不重复），不在用户请求时扇出到节点。
- Grafana 用一次性票据换主机专属 Cookie，Cookie 绑定原运维会话；只有页面导航续期，数据查询不续期。
- 在开发机上测试时，Prometheus、Alertmanager、备份桶和 Grafana 是假服务；节点是真实的 im-server。
