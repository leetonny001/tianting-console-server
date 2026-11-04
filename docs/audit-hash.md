# 审计哈希（PRD-admin F-CON-08 规则 6）

`hash = hex(SHA-256(prevHash ‖ canonical_json(记录除 hash 外的全部字段)))`。第一条的 `prevHash` 是空字符串。

规范化 JSON（`internal/audit/audit.go`）：

- 键按字节序排序，没有空白，UTF-8，不转义 `<`、`>`、`&`；
- 字段：`seq`、`id`、`ts`、`space`、`phase`、`requestId`、`accountId`、`username`、`roles`、`actor`、`ip`、`ua`、`action`、`target`、`params`、`reason`、`ticket`、`result`、`code`、`prevHash`；
- `roles`、`target`、`params` 在库里就是规范化后的 JSON 文本，作为字符串参与哈希（不再解析）。

固定向量：`internal/audit/hash_test.go`。改动规则必须同时改向量，并且不能影响已经写入的记录（校验命令按这个规则重算）。

`ts` 随 `seq` 单调不减（写入时取 `max(当前时间, 链头 ts)`），所以一个月分区里的 `seq` 是连续的一段，归档后 `audit verify` 能从归档的最后一条接续。
