-- CS-012：审计记录（PRD-admin F-CON-08）。按时间范围分区（毫秒），CS-015 按月建分区和归档；先有一个默认分区。
-- params、target 存规范化后的 JSON 文本：哈希按原文计算，jsonb 会改写数字和键序。
CREATE TABLE audit.records (
	seq        bigint NOT NULL,
	id         uuid   NOT NULL,
	ts         bigint NOT NULL,
	space      text   NOT NULL,
	phase      text   NOT NULL CHECK (phase IN ('intent', 'result', 'event')),
	request_id text   NOT NULL,
	account_id text   NOT NULL DEFAULT '',
	username   text   NOT NULL DEFAULT '',
	roles      text   NOT NULL DEFAULT '[]',
	actor      text   NOT NULL DEFAULT '',
	ip         text   NOT NULL DEFAULT '',
	ua         text   NOT NULL DEFAULT '',
	action     text   NOT NULL,
	target     text   NOT NULL DEFAULT '{}',
	params     text   NOT NULL DEFAULT '{}',
	reason     text   NOT NULL DEFAULT '',
	ticket     text   NOT NULL DEFAULT '',
	result     text   NOT NULL DEFAULT '',
	code       integer NOT NULL DEFAULT 0,
	prev_hash  text   NOT NULL,
	hash       text   NOT NULL,
	PRIMARY KEY (seq, ts)
) PARTITION BY RANGE (ts);
CREATE TABLE audit.records_default PARTITION OF audit.records DEFAULT;
CREATE INDEX records_request ON audit.records (request_id);
CREATE INDEX records_space_ts ON audit.records (space, ts);

CREATE TABLE audit.chain_head (
	id   integer PRIMARY KEY CHECK (id = 1),
	seq  bigint NOT NULL,
	hash text   NOT NULL
);
INSERT INTO audit.chain_head (id, seq, hash) VALUES (1, 0, '');

-- 只追加：运行账号对 records 只有 INSERT + SELECT；链头只有 SELECT + UPDATE（规则 10）。
REVOKE ALL ON audit.records, audit.records_default, audit.chain_head FROM console_app;
GRANT SELECT, INSERT ON audit.records TO console_app;
GRANT SELECT, UPDATE ON audit.chain_head TO console_app;
GRANT SELECT ON audit.records, audit.chain_head TO console_archiver;
