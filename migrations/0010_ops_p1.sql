-- CS-131：授予 ops_engineer 要第二个超管批准；异常查询通知。

CREATE TABLE auth.role_grant_requests (
	id                uuid   PRIMARY KEY,
	account_id        uuid   NOT NULL REFERENCES auth.accounts (id),
	role              text   NOT NULL,
	requested_by      uuid   NOT NULL,
	requested_by_name text   NOT NULL,
	requested_at      bigint NOT NULL,
	status            text   NOT NULL CHECK (status IN ('pending', 'approved', 'cancelled')),
	decided_by        uuid,
	decided_by_name   text,
	decided_at        bigint
);
CREATE UNIQUE INDEX role_grant_requests_pending ON auth.role_grant_requests (account_id, role) WHERE status = 'pending';

-- 每个账号最近 1 小时查过的不同 userId。查询时顺手清理，不长期保存。
CREATE TABLE biz.ops_query_recent (
	account_id uuid   NOT NULL,
	user_id    text   NOT NULL,
	last_at    bigint NOT NULL,
	PRIMARY KEY (account_id, user_id)
);

-- 每个账号最后一次发异常查询通知的时间：1 小时内只发一次。
CREATE TABLE biz.ops_query_anomalies (
	account_id  uuid   PRIMARY KEY,
	notified_at bigint NOT NULL
);
