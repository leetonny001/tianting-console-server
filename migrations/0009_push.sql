-- CS-044、CS-045：系统通知（PRD-admin F-ADM-50、PRD-live 4.7 节）。默认权限见 0001：console_app 读写 biz。
-- data 用 text 存原文：jsonb 会改写数字和键顺序。审计只记长度和 SHA-256。

CREATE TABLE biz.push_drafts (
	id               uuid   PRIMARY KEY,
	type             text   NOT NULL,
	data             text   NOT NULL,
	data_sha256      text   NOT NULL,
	reason           text   NOT NULL,
	created_by       uuid   NOT NULL,
	created_by_name  text   NOT NULL,
	created_at       bigint NOT NULL,
	expires_at       bigint NOT NULL, -- 24 小时；是否作废读取时按 [C 钟] 判断
	status           text   NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved')),
	approved_by      uuid,
	approved_by_name text,
	approved_at      bigint,
	CHECK (approved_by IS NULL OR approved_by <> created_by) -- 发起人不能批准自己的草稿，库也兜一层
);
CREATE INDEX push_drafts_created ON biz.push_drafts (created_at DESC);
CREATE INDEX push_drafts_pending ON biz.push_drafts (expires_at) WHERE status = 'pending';

CREATE TABLE biz.push_records (
	id                uuid   PRIMARY KEY,
	kind              text   NOT NULL CHECK (kind IN ('user', 'all')),
	type              text   NOT NULL,
	data              text   NOT NULL,
	data_sha256       text   NOT NULL,
	targets           text   NOT NULL DEFAULT '[]', -- kind=user 的 userId 列表（JSON）；kind=all 为空列表
	target_count      integer NOT NULL DEFAULT 0,
	reason            text   NOT NULL,
	ticket            text   NOT NULL DEFAULT '',
	created_by        uuid   NOT NULL,
	created_by_name   text   NOT NULL,
	approved_by       uuid,
	approved_by_name  text,
	draft_id          uuid,
	sent_at           bigint NOT NULL, -- 首次发送时间。重放不改它：5 分钟间隔和 1 小时时限都按它算
	request_id        text   NOT NULL UNIQUE, -- 首次调用的 X-Request-Id，对账按它查
	im_push_id        text   NOT NULL UNIQUE,
	status            text   NOT NULL CHECK (status IN ('sending', 'success', 'failed', 'unknown', 'replay_due')),
	error_code        integer NOT NULL DEFAULT 0,
	im_created        boolean,
	accepted          integer,
	replay_request_id text   UNIQUE, -- 非空表示已经领走了唯一一次重放，进程崩溃也不会重放第二次
	replay_at         bigint,
	replay_created    boolean,
	replay_expired    boolean NOT NULL DEFAULT false
);
-- 查"最近一次全员发送"。failed 的没有发出去，不占间隔。
CREATE INDEX push_records_all_sent ON biz.push_records (sent_at DESC) WHERE kind = 'all' AND status <> 'failed';
CREATE INDEX push_records_sent ON biz.push_records (sent_at DESC);
CREATE INDEX push_records_replay ON biz.push_records (sent_at) WHERE status = 'replay_due';
