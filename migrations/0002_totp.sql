-- CS-003：TOTP 种子只存密文和 kid（PRD-admin F-CON-11）。账号表在 CS-005 加入后补外键。
CREATE TABLE auth.totp (
	account_id bigint PRIMARY KEY,
	kid        text   NOT NULL,
	nonce      bytea  NOT NULL,
	ciphertext bytea  NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX totp_kid ON auth.totp (kid);
