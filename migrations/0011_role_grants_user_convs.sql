-- CS-133：待批准可以被拒绝、会过期；替换现有角色的授予在批准时才替换（PRD-ops F-OPS-02 规则 6）。
ALTER TABLE auth.role_grant_requests DROP CONSTRAINT role_grant_requests_status_check;
ALTER TABLE auth.role_grant_requests ADD CONSTRAINT role_grant_requests_status_check
	CHECK (status IN ('pending', 'approved', 'cancelled', 'rejected', 'expired'));
-- 批准时要去掉的现有角色和一起生效的不需批准的角色。待批准期间账号的权限按未生效前的角色计算。
ALTER TABLE auth.role_grant_requests ADD COLUMN replaces_roles text[] NOT NULL DEFAULT '{}';
ALTER TABLE auth.role_grant_requests ADD COLUMN with_roles text[] NOT NULL DEFAULT '{}';
CREATE INDEX role_grant_requests_expiry ON auth.role_grant_requests (requested_at) WHERE status = 'pending';

-- CS-063：打开用户会话列表之后，同一账号查同一用户 15 分钟内翻页不再要理由（F-ADM-30 规则 1 ③）。
CREATE TABLE biz.user_convs_windows (
	account_id uuid   NOT NULL,
	user_id    text   NOT NULL,
	until      bigint NOT NULL,
	PRIMARY KEY (account_id, user_id)
);
