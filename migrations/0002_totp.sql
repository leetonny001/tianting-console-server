-- CS-003：TOTP 种子只存密文和 kid（PRD-admin F-CON-11）。账号表在 0004 加入后补外键。
CREATE TABLE auth.totp (
	account_id uuid PRIMARY KEY,
	kid        text   NOT NULL,
	nonce      bytea  NOT NULL,
	ciphertext bytea  NOT NULL,
	last_step  bigint NOT NULL DEFAULT 0, -- 最近成功使用的步长：防重放，覆盖登录和 step-up
	confirmed  boolean NOT NULL DEFAULT false,
	created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX totp_kid ON auth.totp (kid);
