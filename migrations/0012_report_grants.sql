-- CS-208：举报证据授权绑定到当前浏览器会话 + 举报 ID（F-MOD-04 规则 3，同 F-ADM-08 规则 3）。
-- 是否过期以 im-server 的结果为准（4039）；expires_at 是 im-server 返回的，console 先比一次、也用来清理这张表。
-- conv_id 是举报对象所在的会话：取证据文件时 im-server 要它，第一次取文件时向 im-server 查一次再记下（空串表示还没查过）。
CREATE TABLE biz.report_grants (
	session_hash text   NOT NULL,
	report_id    text   NOT NULL,
	grant_id     text   NOT NULL,
	expires_at   bigint NOT NULL,
	conv_id      text   NOT NULL DEFAULT '',
	PRIMARY KEY (session_hash, report_id)
);
CREATE INDEX report_grants_expires ON biz.report_grants (expires_at);
