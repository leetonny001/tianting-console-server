-- CS-020 ～ CS-026：业务公共层（PRD-admin 第 6 节）。默认权限见 0001：console_app 读写 biz。

-- 每日上限：按"不同对象"计数，已查过的对象不重复计数。day 是 Asia/Shanghai 的日期。
CREATE TABLE biz.daily_quota (
	account_id uuid NOT NULL,
	kind       text NOT NULL,
	day        text NOT NULL,
	key        text NOT NULL,
	PRIMARY KEY (account_id, kind, day, key)
);

-- 分钟级限流。
CREATE TABLE biz.minute_rate (
	account_id uuid   NOT NULL,
	kind       text   NOT NULL,
	minute     bigint NOT NULL,
	count      integer NOT NULL,
	PRIMARY KEY (account_id, kind, minute)
);

-- 导入任务。用户导入把校验过的行存在 rows（资料不敏感）；好友导入 rows 为空：备注不落库，提交时前端重新上传同一文件，按哈希核对。
CREATE TABLE biz.import_jobs (
	id           uuid   PRIMARY KEY,
	account_id   uuid   NOT NULL,
	kind         text   NOT NULL,
	file_sha256  text   NOT NULL,
	total        integer NOT NULL,
	preview      text   NOT NULL,
	rows         text   NOT NULL DEFAULT '',
	created_at   bigint NOT NULL,
	expires_at   bigint NOT NULL,
	used_at      bigint
);

-- 单聊元数据：进入一个会话后 15 分钟内翻页不再要理由（[C 钟]）。session_hash 是会话 ID 的哈希。
CREATE TABLE biz.meta_sessions (
	session_hash text   NOT NULL,
	conv_id      text   NOT NULL,
	until        bigint NOT NULL,
	PRIMARY KEY (session_hash, conv_id)
);
