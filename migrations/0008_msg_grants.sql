-- CS-041：正文查看授权绑定到当前浏览器会话 + 会话 ID（F-ADM-08 规则 3）。
-- 是否过期以 im-server 的结果为准（4039）；expires_at 是 im-server 返回的，只用来清理这张表。
CREATE TABLE biz.msg_grants (
	session_hash text    NOT NULL,
	conv_id      text    NOT NULL,
	quarantine   boolean NOT NULL,
	grant_id     text    NOT NULL,
	expires_at   bigint  NOT NULL,
	PRIMARY KEY (session_hash, conv_id, quarantine)
);
CREATE INDEX msg_grants_expires ON biz.msg_grants (expires_at);
