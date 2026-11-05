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
- 导出：`POST /console/api/audit/export`（请求体是筛选条件，规则同查询）。需要重新验证，单次不超过 1 万条，超过时整个拒绝（400 / 4131），不截断；边查边写，不落盘；写 `ops.audit.export`（管理空间 `audit.export`）。开头是公式字符的单元格前面加单引号，所以校验哈希链要用 `audit verify`，不用 CSV。
- 对账：每 10 分钟补写缺失的结论。只改 console 自己数据库的动作（`account.*`、`auth.*`、`audit.*`）im-server 查不到，补写 `result=unknown`、`params.reconciled="localOnly"`，不会声称"没有执行"。
- `tools/minio-test.sh` 用真实的 MinIO（Object Lock）跑一遍读写权限，需要 docker，CI 里运行。

## 运维模块

接口清单是 `api/ops-routes.yaml`，启动时和注册的路由比对，不一致就启动失败；权限矩阵测试用它做数据源。节点凭证、Prometheus、Alertmanager、备份桶、Grafana 的配置见 `deploy/console-server.env.example`。

- 总览和节点列表只读 Postgres 里的探测结果（每 5 秒一次，多实例不重复），不在用户请求时扇出到节点。
- Grafana 用一次性票据换主机专属 Cookie，Cookie 绑定原运维会话；只有页面导航续期，数据查询不续期。
- 告警静默（CS-130）是唯一写 Alertmanager 的接口：只能等值匹配 `alertname`、`node_id`，15 分钟～24 小时，要重新验证、工单号和理由。`GET /alerts` 和总览的告警卡片带当前生效的静默。
- 授予 `ops_engineer`（新建账号或改角色）先进入待批准，由另一个 `ops_superadmin` 调 `POST /console/api/accounts/{id}/roles/approve` 生效，发起人自己批准 403 / 4030。批准后该账号要重新登录。所以运维空间要有两个超管才能开排障账号。
- 同一账号 1 小时（滑动窗口）内查询 20 个不同的 userId，通知全部 `ops_auditor`，内容只有账号名和数量；通知后 1 小时内不再发。
- 在开发机上测试时，Prometheus、Alertmanager、备份桶和 Grafana 是假服务；节点是真实的 im-server。真实 Alertmanager 的验收在 `tools/ops-accept` 的 `silence` 步骤（测试环境运行）。
