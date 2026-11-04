-- CS-013 ～ CS-015：外部锚定、查询索引、按月分区和归档（PRD-admin F-CON-08 规则 7、F-CON-09）。

-- 链头记住最后一条的 ts：写入时保证 ts 随 seq 单调不减。否则多实例时钟有偏差时，月边界上的 seq 会交错分到两个分区，
-- 归档一个分区后哈希链就接不上了。
ALTER TABLE audit.chain_head ADD COLUMN ts bigint NOT NULL DEFAULT 0;
UPDATE audit.chain_head SET ts = COALESCE((SELECT max(ts) FROM audit.records), 0);

CREATE TABLE audit.anchors (
	seq        bigint PRIMARY KEY,
	hash       text   NOT NULL,
	ts         bigint NOT NULL
);
REVOKE ALL ON audit.anchors FROM console_app, console_archiver;
GRANT SELECT, INSERT ON audit.anchors TO console_app, console_archiver;

-- 查询索引（CS-014 内容 5）。records_space_ts、records_request 在 0003。
CREATE INDEX records_account_ts ON audit.records (account_id, ts);
CREATE INDEX records_actor_ts   ON audit.records (actor, ts);
CREATE INDEX records_action_ts  ON audit.records (action, ts);
-- 对账只扫 intent。
CREATE INDEX records_intent_ts  ON audit.records (ts) WHERE phase = 'intent';

-- 已归档的分区：verify 从最后一条接续（F-CON-09 规则 6）。运行账号只读。
CREATE TABLE audit.archives (
	partition_name    text   PRIMARY KEY,
	seq_first         bigint NOT NULL,
	seq_last          bigint NOT NULL,
	last_hash         text   NOT NULL,
	record_count      bigint NOT NULL,
	object_key        text   NOT NULL,
	ciphertext_sha256 text   NOT NULL,
	archived_at       bigint NOT NULL,
	retain_until      bigint NOT NULL
);
REVOKE ALL ON audit.archives FROM console_app, console_archiver;
GRANT SELECT ON audit.archives TO console_app;
GRANT SELECT, INSERT ON audit.archives TO console_archiver;

-- 建月分区。运行账号没有 DDL 权限，只能通过这个函数做这一件事。默认分区里已有这个月的数据时先搬过去（否则 PG 不让建）。
-- 已经归档的月份不再重建。
CREATE FUNCTION audit.ensure_partition(p_year integer, p_month integer) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, audit SET timezone = 'UTC' AS $$
DECLARE
	v_name  text;
	v_start timestamptz;
	v_from  bigint;
	v_to    bigint;
BEGIN
	IF p_year NOT BETWEEN 2000 AND 9998 OR p_month NOT BETWEEN 1 AND 12 THEN
		RAISE EXCEPTION 'invalid partition month: %-%', p_year, p_month;
	END IF;
	v_name := 'records_' || to_char(p_year, 'FM0000') || to_char(p_month, 'FM00');
	PERFORM pg_advisory_xact_lock(hashtext('audit.partitions'));
	IF to_regclass('audit.' || v_name) IS NOT NULL OR EXISTS (SELECT 1 FROM audit.archives WHERE partition_name = v_name) THEN
		RETURN v_name;
	END IF;
	v_start := make_timestamptz(p_year, p_month, 1, 0, 0, 0, 'UTC');
	v_from  := (extract(epoch FROM v_start) * 1000)::bigint;
	v_to    := (extract(epoch FROM v_start + interval '1 month') * 1000)::bigint;
	LOCK TABLE audit.records_default IN ACCESS EXCLUSIVE MODE;
	EXECUTE format('CREATE TABLE audit.%I (LIKE audit.records INCLUDING DEFAULTS INCLUDING CONSTRAINTS INCLUDING INDEXES)', v_name);
	EXECUTE format('WITH moved AS (DELETE FROM audit.records_default WHERE ts >= %s AND ts < %s RETURNING *) INSERT INTO audit.%I SELECT * FROM moved', v_from, v_to, v_name);
	EXECUTE format('ALTER TABLE audit.records ATTACH PARTITION audit.%I FOR VALUES FROM (%s) TO (%s)', v_name, v_from, v_to);
	EXECUTE format('REVOKE ALL ON audit.%I FROM console_app, console_archiver', v_name);
	RETURN v_name;
END $$;
REVOKE ALL ON FUNCTION audit.ensure_partition(integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.ensure_partition(integer, integer) TO console_app, console_archiver;

-- 删除已归档的分区：只有归档账号能调用，而且 audit.archives 里必须有一致的记录（条数、首末 seq）。
CREATE FUNCTION audit.drop_archived_partition(p_name text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, audit AS $$
DECLARE
	a     audit.archives;
	v_cnt bigint;
	v_min bigint;
	v_max bigint;
BEGIN
	IF p_name !~ '^records_[0-9]{6}$' THEN
		RAISE EXCEPTION 'not a monthly audit partition: %', p_name;
	END IF;
	SELECT * INTO a FROM audit.archives WHERE partition_name = p_name;
	IF NOT FOUND THEN
		RAISE EXCEPTION 'partition % has no archive record', p_name;
	END IF;
	EXECUTE format('SELECT count(*), COALESCE(min(seq), 0), COALESCE(max(seq), 0) FROM audit.%I', p_name) INTO v_cnt, v_min, v_max;
	IF v_cnt <> a.record_count OR v_min <> a.seq_first OR v_max <> a.seq_last THEN
		RAISE EXCEPTION 'partition % does not match its archive record', p_name;
	END IF;
	EXECUTE format('DROP TABLE audit.%I', p_name);
END $$;
REVOKE ALL ON FUNCTION audit.drop_archived_partition(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.drop_archived_partition(text) TO console_archiver;

-- 预建当月和下月（CS-015 内容 1）。之后由服务每小时检查一次。
DO $$
DECLARE d timestamptz := date_trunc('month', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
BEGIN
	PERFORM audit.ensure_partition(extract(year FROM (d AT TIME ZONE 'UTC'))::int, extract(month FROM (d AT TIME ZONE 'UTC'))::int);
	d := d + interval '32 days';
	PERFORM audit.ensure_partition(extract(year FROM (d AT TIME ZONE 'UTC'))::int, extract(month FROM (d AT TIME ZONE 'UTC'))::int);
END $$;
