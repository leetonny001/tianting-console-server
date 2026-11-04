-- CS-112、CS-117：运维模块（PRD-ops）。多个 console-server 实例共享探测结果；进程不存状态。

CREATE TABLE biz.ops_node_status (
	node_id      text   PRIMARY KEY,
	snapshot     text   NOT NULL DEFAULT '',   -- 最后一次成功探测的 /internal/v1/node 响应
	last_seen_at bigint NOT NULL DEFAULT 0,    -- 最后一次成功的时间
	last_probe_at bigint NOT NULL DEFAULT 0,
	failure      text   NOT NULL DEFAULT ''    -- 最后一次探测的失败类型：''、unreachable、identity
);

-- 单行：谁在什么时候探测过（多实例不重复探测），以及版本不一致从什么时候开始。
CREATE TABLE biz.ops_probe (
	id                     integer PRIMARY KEY CHECK (id = 1),
	at                     bigint NOT NULL,
	version_mismatch_since bigint NOT NULL DEFAULT 0
);
INSERT INTO biz.ops_probe (id, at) VALUES (1, 0);

-- Grafana 一次性票据：30 秒有效，消费时原子删除。
CREATE TABLE biz.grafana_tickets (
	ticket_hash  text   PRIMARY KEY,
	session_hash text   NOT NULL,
	expires_at   bigint NOT NULL
);

-- Grafana 主机专属 Cookie → 原运维会话。原会话失效时这边立刻失效。
CREATE TABLE biz.grafana_sessions (
	cookie_hash  text   PRIMARY KEY,
	session_hash text   NOT NULL,
	created_at   bigint NOT NULL
);
