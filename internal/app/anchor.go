package app

import (
	"context"
	"errors"
	"time"

	"filippo.io/age"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"tianting/console/internal/anchor"
	"tianting/console/internal/audit"
	"tianting/console/internal/config"
	"tianting/console/internal/ids"
	"tianting/console/internal/notify"
	"tianting/console/internal/objstore"
	"tianting/console/internal/perm"
	"tianting/console/internal/secret"
)

// anchorEvery：每新增这么多条就锚定一次，不等整点（F-CON-08 规则 7）。
const anchorEvery = 1000

// anchorTimeout 是一次写外部存储的上限：锚定期间占着一个数据库连接。
const anchorTimeout = 15 * time.Second

func anchorStore(c config.AnchorConfig, access string, key secret.Bytes) *objstore.Store {
	return objstore.New(objstore.Config{Endpoint: c.Endpoint, Region: c.Region, Bucket: c.Bucket, Prefix: c.Prefix, AccessKey: access, SecretKey: key})
}

func openAnchorSink(cfg config.Config) (anchor.Sink, error) {
	c := cfg.Anchor
	switch {
	case c.Target == "":
		return nil, nil
	case c.S3():
		return &anchor.S3{Store: anchorStore(c, c.AccessKey, c.SecretKey), Retain: time.Duration(c.RetainDays) * 24 * time.Hour}, nil
	}
	return &anchor.HTTP{URL: c.Target, Token: string(c.Token)}, nil
}

// anchorReader 只给校验和归档用；服务进程不需要、也不应该有读取凭证。
func anchorReader(cfg config.Config) anchor.Reader {
	c := cfg.Anchor
	switch {
	case !c.CanRead():
		return nil
	case c.S3():
		return &anchor.S3{Store: anchorStore(c, c.ReadAccessKey, c.ReadSecretKey)}
	}
	return &anchor.HTTP{URL: c.Target, Token: string(c.ReadToken)}
}

// AnchorTick 检查要不要锚定：比上次多 1000 条，或者跨了整点。有新记录才写。失败时下一轮（1 分钟后）重试，
// 满足"10 分钟内重试"。多实例用 advisory lock，同一时刻只有一个在写。
func (a *App) AnchorTick(ctx context.Context) error {
	if a.Anchor == nil {
		return nil
	}
	now := a.Clock.Now().UnixMilli()
	var lastTS int64
	err := pgx.BeginFunc(ctx, a.DB, func(tx pgx.Tx) error {
		var locked bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtext('audit.anchor'))`).Scan(&locked); err != nil || !locked {
			return err
		}
		var head anchor.Point
		if err := tx.QueryRow(ctx, `SELECT seq, hash FROM audit.chain_head WHERE id = 1`).Scan(&head.Seq, &head.Hash); err != nil {
			return err
		}
		var lastSeq int64
		err := tx.QueryRow(ctx, `SELECT seq, ts FROM audit.anchors ORDER BY seq DESC LIMIT 1`).Scan(&lastSeq, &lastTS)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		hour := time.Hour.Milliseconds()
		if head.Seq == 0 || head.Seq <= lastSeq || (head.Seq-lastSeq < anchorEvery && now/hour <= lastTS/hour) {
			return nil
		}
		head.TS = now
		putCtx, cancel := context.WithTimeout(ctx, anchorTimeout)
		defer cancel()
		if err := a.Anchor.Put(putCtx, head); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO audit.anchors (seq, hash, ts) VALUES ($1, $2, $3)`, head.Seq, head.Hash, head.TS); err != nil {
			return err
		}
		lastTS = head.TS
		return nil
	})
	if lastTS > 0 {
		a.anchorLag.Set(float64(now-lastTS) / 1000)
	}
	if err != nil {
		a.anchorFailures.Inc()
		a.Log.Error("audit anchor failed", "err", err)
		a.notifyAudit(context.WithoutCancel(ctx), notify.KindAnchorFail, map[string]any{"at": now})
	}
	return err
}

// notifyAudit 把审计异常通知给每个空间的超管和审计员（F-CON-12 规则 2）。链是全局一条，所以两个空间都要知道。
// 同一种通知 1 小时最多一次：外部存储宕机时每分钟重试，不能每分钟刷一条。
func (a *App) notifyAudit(ctx context.Context, kind string, payload map[string]any) {
	var recent bool
	since := a.Clock.Now().Add(-time.Hour).UnixMilli()
	if err := a.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM auth.notifications WHERE kind = $1 AND created_at > $2)`, kind, since).Scan(&recent); err != nil {
		a.Log.Error("audit notification", "kind", kind, "err", err)
		return
	}
	if recent {
		return
	}
	for _, s := range a.Cfg.Spaces {
		ps := perm.For(s.Name)
		if err := a.notifier().ToRoles(ctx, a.DB, s.Name, []string{ps.SuperAdmin, ps.Auditor}, "", kind, payload); err != nil {
			a.Log.Error("audit notification", "kind", kind, "space", s.Name, "err", err)
		}
	}
}

// AuditVerify 是 audit verify 命令：校验、写 event 审计，失败时通知（F-CON-08 规则 8）。
func (a *App) AuditVerify(ctx context.Context, fromSeq int64) (audit.VerifyResult, error) {
	reader := anchorReader(a.Cfg)
	if reader == nil && a.Cfg.Production() {
		return audit.VerifyResult{}, errors.New("CON_AUDIT_ANCHOR_READ_ACCESS_KEY and CON_AUDIT_ANCHOR_READ_SECRET_KEY (or CON_AUDIT_ANCHOR_READ_TOKEN) are required: verifying only against the database would not detect a rewritten chain")
	}
	res, verr := audit.Verify(ctx, a.DB, fromSeq, reader)
	now := a.Clock.Now()
	params := map[string]any{"fromSeq": fromSeq, "records": res.Records, "lastSeq": res.LastSeq, "anchors": res.Anchors, "anchorSource": res.AnchorSource}
	if len(res.Warnings) > 0 {
		params["warnings"] = res.Warnings
	}
	result := audit.Success
	if res.Issue != nil {
		result = audit.Failure
		params["issue"], params["issueSeq"] = res.Issue.Type, res.Issue.Seq
	}
	if verr != nil {
		result = audit.Failure
		params["issue"] = "verifyError"
	}
	if result == audit.Failure {
		payload := map[string]any{"at": now.UnixMilli(), "issue": params["issue"]}
		if res.Issue != nil {
			payload["seq"] = res.Issue.Seq
		}
		a.notifyAudit(ctx, notify.KindAuditVerifyFail, payload)
	}
	err := a.Audit.Write(ctx, audit.Record{Space: a.auditEventSpace(), Phase: audit.PhaseEvent, RequestID: ids.New(now), Actor: CLIActor(), Action: "audit.verify", Params: params, Result: result})
	if verr != nil {
		return res, verr
	}
	if err != nil {
		return res, errors.New("audit verify could not write its own audit record")
	}
	return res, nil
}

// auditEventSpace：命令行操作不属于某个空间的会话。全局链上的任务记到第一个开启的空间。
func (a *App) auditEventSpace() string {
	if len(a.Cfg.Spaces) > 0 {
		return a.Cfg.Spaces[0].Name
	}
	return perm.Admin.Name
}

// AuditArchive 是 audit archive 命令（F-CON-09 规则 6）。用 console_archiver 连接；审计事件用运行账号写。
func (a *App) AuditArchive(ctx context.Context) ([]audit.Archived, error) {
	c := a.Cfg.Archive
	switch {
	case c.Target == "" || c.Endpoint == "" || c.AccessKey == "" || len(c.SecretKey) == 0:
		return nil, errors.New("CON_AUDIT_ARCHIVE, CON_AUDIT_ARCHIVE_ENDPOINT, CON_AUDIT_ARCHIVE_ACCESS_KEY and CON_AUDIT_ARCHIVE_SECRET_KEY are required")
	case c.Recipient == "":
		return nil, errors.New("CON_ARCHIVE_RECIPIENT is required")
	case c.DatabaseURL == "":
		return nil, errors.New("CON_ARCHIVER_DATABASE_URL is required: archiving runs as console_archiver")
	}
	reader := anchorReader(a.Cfg)
	if reader == nil && a.Cfg.Production() {
		return nil, errors.New("CON_AUDIT_ANCHOR_READ_* is required: the chain must be checked against the external anchors before a partition is dropped")
	}
	recipient, err := age.ParseX25519Recipient(c.Recipient)
	if err != nil {
		return nil, errors.New("CON_ARCHIVE_RECIPIENT is not a valid age public key")
	}
	pool, err := pgxpool.New(ctx, string(c.DatabaseURL))
	if err != nil {
		return nil, errors.New("CON_ARCHIVER_DATABASE_URL is not a valid connection string")
	}
	defer pool.Close()
	ar := &audit.Archiver{
		DB:        pool,
		Store:     objstore.New(objstore.Config{Endpoint: c.Endpoint, Region: c.Region, Bucket: c.Bucket, Prefix: c.Prefix, AccessKey: c.AccessKey, SecretKey: c.SecretKey}),
		Recipient: recipient, Sink: a.Anchor, Reader: reader, Years: c.Years, Now: a.Clock.Now,
		Record: func(ctx context.Context, d audit.Archived) error {
			now := a.Clock.Now()
			return a.Audit.Write(ctx, audit.Record{Space: a.auditEventSpace(), Phase: audit.PhaseEvent, RequestID: ids.New(now), Actor: CLIActor(), Action: "audit.archive",
				Target: audit.NewTarget("partition", d.Partition),
				Params: map[string]any{"firstSeq": d.First, "lastSeq": d.Last, "count": d.Count, "sha256": d.SHA256, "key": d.Key}, Result: audit.Success})
		},
	}
	if c.TestIdentity != "" {
		id, err := age.ParseX25519Identity(c.TestIdentity)
		if err != nil {
			return nil, errors.New("CON_TEST_ARCHIVE_IDENTITY is not a valid age identity")
		}
		ar.Identity = id
	}
	return ar.Run(ctx)
}

// EnsurePartitions 预建当月和下月的分区（CS-015 内容 1）。
func (a *App) EnsurePartitions(ctx context.Context) error {
	now := a.Clock.Now().UTC()
	first := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	for _, m := range []time.Time{first, first.AddDate(0, 1, 0)} {
		if _, err := a.DB.Exec(ctx, `SELECT audit.ensure_partition($1, $2)`, m.Year(), int(m.Month())); err != nil {
			return err
		}
	}
	return nil
}

// RunJobs 是后台定时任务，直到 ctx 取消。每分钟一轮；满 1000 条时立即多跑一次锚定。
func (a *App) RunJobs(ctx context.Context) {
	logErr := func(name string, err error) {
		if err != nil && ctx.Err() == nil {
			a.Log.Error(name, "err", err)
		}
	}
	logErr("ensure partitions", a.EnsurePartitions(ctx))
	lastReconcile, lastPartition := a.Clock.Now(), a.Clock.Now()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.anchorWake:
			logErr("audit anchor", a.AnchorTick(ctx))
		case <-t.C:
			now := a.Clock.Now()
			logErr("housekeeping", a.Housekeeping(ctx))
			logErr("audit anchor", a.AnchorTick(ctx))
			if now.Sub(lastReconcile) >= reconcileEvery {
				lastReconcile = now
				logErr("audit reconcile", a.Reconcile(ctx))
			}
			if now.Sub(lastPartition) >= time.Hour {
				lastPartition = now
				logErr("ensure partitions", a.EnsurePartitions(ctx))
			}
		}
	}
}

// SetAuditFault 是测试模式的故障注入（和 POST /console/test/faults 相同）。
func (a *App) SetAuditFault(f string) { a.auditFault.Store(f) }
