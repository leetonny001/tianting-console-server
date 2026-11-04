-- CS-005～CS-011、CS-016：账号、角色、会话、失败计数、通知。时间都是毫秒（[C 钟]）。
CREATE TABLE auth.accounts (
	id                 uuid PRIMARY KEY,
	space              text NOT NULL,
	username           text NOT NULL,
	display_name       text NOT NULL,
	status             text NOT NULL CHECK (status IN ('pending', 'active', 'disabled')),
	password_hash      text NOT NULL DEFAULT '',
	password_history   text[] NOT NULL DEFAULT '{}', -- 最近 5 次的哈希（含当前）
	activation_hash    text NOT NULL DEFAULT '',
	activation_expires bigint NOT NULL DEFAULT 0,
	idp_subject        text NOT NULL DEFAULT '',
	idp_issuer         text NOT NULL DEFAULT '',
	created_at         bigint NOT NULL,
	activated_at       bigint NOT NULL DEFAULT 0,
	UNIQUE (space, username)
);

ALTER TABLE auth.totp ADD CONSTRAINT totp_account FOREIGN KEY (account_id) REFERENCES auth.accounts (id);

CREATE TABLE auth.account_roles (
	account_id uuid NOT NULL REFERENCES auth.accounts (id),
	role       text NOT NULL,
	granted_by text NOT NULL,
	granted_at bigint NOT NULL,
	expires_at bigint, -- 应急授权的到期时间；判断时按 [C 钟] 当前时间，不需要定时任务
	PRIMARY KEY (account_id, role)
);

CREATE TABLE auth.recovery_codes (
	account_id uuid NOT NULL REFERENCES auth.accounts (id),
	code_hash  text NOT NULL,
	used_at    bigint,
	PRIMARY KEY (account_id, code_hash)
);

CREATE TABLE auth.sessions (
	id_hash         text PRIMARY KEY,
	account_id      uuid NOT NULL REFERENCES auth.accounts (id),
	space           text NOT NULL,
	state           text NOT NULL CHECK (state IN ('setup', 'full')),
	csrf_token_hash text NOT NULL,
	created_at      bigint NOT NULL,
	last_active_at  bigint NOT NULL,
	step_up_at      bigint NOT NULL DEFAULT 0,
	step_up_failures integer NOT NULL DEFAULT 0,
	revoked_reason  text NOT NULL DEFAULT ''
);
CREATE INDEX sessions_account ON auth.sessions (account_id, created_at);

-- 失败计数：key 是 "n|space|用户名|IP"（账号名 + IP）或 "g|space|用户名"（账号名全局），不管账号是否存在。
CREATE TABLE auth.login_failures (
	key          text PRIMARY KEY,
	space        text NOT NULL,
	username     text NOT NULL,
	count        integer NOT NULL,
	window_start bigint NOT NULL,
	locked_until bigint NOT NULL DEFAULT 0
);
CREATE INDEX login_failures_user ON auth.login_failures (space, username);

CREATE TABLE auth.ip_rate (
	ip     text   NOT NULL,
	minute bigint NOT NULL,
	count  integer NOT NULL,
	PRIMARY KEY (ip, minute)
);

CREATE TABLE auth.denied_buffer (
	account_id uuid   NOT NULL,
	minute     bigint NOT NULL,
	action     text   NOT NULL,
	total      integer NOT NULL,
	merged     integer NOT NULL DEFAULT 0,
	PRIMARY KEY (account_id, minute, action)
);

CREATE TABLE auth.notifications (
	id         uuid PRIMARY KEY,
	account_id uuid NOT NULL REFERENCES auth.accounts (id),
	space      text NOT NULL,
	kind       text NOT NULL,
	payload    jsonb NOT NULL,
	created_at bigint NOT NULL,
	read_at    bigint
);
CREATE INDEX notifications_account ON auth.notifications (account_id, created_at DESC);
