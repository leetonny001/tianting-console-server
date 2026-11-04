-- CS-002：schema、数据库角色和审计探针（PRD-admin F-CON-01 规则 5、9）。
-- 用 console_owner 执行。角色是集群级的，不存在时才创建，没有 LOGIN 和密码：由运维单独设置。
DO $$
DECLARE r text;
BEGIN
	FOREACH r IN ARRAY ARRAY['console_app', 'console_archiver'] LOOP
		IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
			EXECUTE format('CREATE ROLE %I NOLOGIN', r);
		END IF;
	END LOOP;
END $$;

CREATE SCHEMA auth;
CREATE SCHEMA audit;
CREATE SCHEMA biz;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA auth, audit, biz TO console_app;
GRANT USAGE ON SCHEMA audit TO console_archiver;

-- auth、biz：运行时读写。新表自动继承。
ALTER DEFAULT PRIVILEGES IN SCHEMA auth, biz GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO console_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA auth, biz GRANT USAGE, SELECT ON SEQUENCES TO console_app;
-- audit：默认只追加。链头表等例外在各自的迁移里显式授权。
ALTER DEFAULT PRIVILEGES IN SCHEMA audit GRANT SELECT, INSERT ON TABLES TO console_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA audit GRANT SELECT ON TABLES TO console_archiver;
ALTER DEFAULT PRIVILEGES IN SCHEMA audit GRANT USAGE, SELECT ON SEQUENCES TO console_app;

-- 审计探针：生产启动时用运行账号 UPDATE 这张表，必须失败，证明运行账号确实改不了审计（规则 9）。
CREATE TABLE audit.probe (
	id   integer PRIMARY KEY,
	note text NOT NULL
);
INSERT INTO audit.probe (id, note) VALUES (1, 'startup permission probe');
REVOKE UPDATE, DELETE, TRUNCATE ON audit.probe FROM console_app;
GRANT SELECT, INSERT ON audit.probe TO console_app;
