// console-server：管理后台和运维后台的服务端。一个二进制，每个账号空间一个监听地址（PRD-admin F-CON-01）。
//
// 子命令：
//
//	console-server [serve]            启动服务
//	console-server migrate up|status  数据库迁移（用 CON_OWNER_DATABASE_URL，也就是 console_owner）
//	console-server keys rotate        用当前数据密钥重新加密全部旧记录
//	console-server account bootstrap --space admin|ops --username U   创建空间超管（ops 空间少于 2 个时可以建第二个），输出一次性激活码
//	console-server account unlock --space admin|ops --username U      解锁账号（应急）
//	console-server audit verify [--from-seq N]                        校验审计链，发现问题时非 0 退出
//	console-server audit archive                                      加密归档满 1 年的审计分区（用 CON_ARCHIVER_DATABASE_URL）
//
// 配置全部来自环境变量，见 deploy/console-server.env.example。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"tianting/console/internal/app"
	"tianting/console/internal/config"
	"tianting/console/internal/dbx"
	"tianting/console/internal/secret"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(logger)
	case "migrate":
		err = migrate(os.Args[2:])
	case "keys":
		err = keys(os.Args[2:])
	case "account":
		err = account(os.Args[2:], logger)
	case "audit":
		err = auditCmd(os.Args[2:], logger)
	default:
		err = fmt.Errorf("unknown command %q; use serve, migrate, keys, account or audit", cmd)
	}
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
}

func load() (config.Config, error) {
	cfg, problems := config.Load(os.Getenv)
	if len(problems) > 0 {
		return cfg, app.JoinProblems(problems)
	}
	return cfg, nil
}

func serve(logger *slog.Logger) error {
	cfg, problems := config.Load(os.Getenv)
	a, err := app.New(cfg, logger)
	if err != nil {
		return err
	}
	defer a.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// 静态问题和要连库的问题合在一起，一次列全（规则 9）。
	problems = append(problems, a.StartupProblems(ctx)...)
	if len(problems) > 0 {
		return app.JoinProblems(problems)
	}

	// 定时任务：清理、合并拒绝记录、外部锚定、审计对账、预建分区。
	go a.RunJobs(ctx)

	errc := make(chan error, len(cfg.Spaces)+1)
	var servers []*http.Server
	for _, s := range cfg.Spaces {
		srv := &http.Server{Addr: s.Addr, Handler: a.Handler(s), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 16 << 10}
		servers = append(servers, srv)
		go func() {
			logger.Info("space listening", "space", s.Name, "addr", s.Addr, "tls", cfg.TLSCert != "")
			var err error
			if cfg.TLSCert != "" {
				err = srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
			} else {
				err = srv.ListenAndServe()
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("%s space: %w", s.Name, err)
			}
		}()
	}
	if cfg.MetricsAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", a.MetricsHandler())
		srv := &http.Server{Addr: cfg.MetricsAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		servers = append(servers, srv)
		go func() {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Warn("metrics server not available", "err", err)
			}
		}()
	}
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(shutdownCtx)
	}
	return nil
}

func migrate(args []string) error {
	url := os.Getenv("CON_OWNER_DATABASE_URL")
	if url == "" {
		return errors.New("CON_OWNER_DATABASE_URL is required: migrations run as console_owner, never as the runtime role")
	}
	ctx := context.Background()
	if len(args) == 1 && args[0] == "up" {
		done, err := dbx.Up(ctx, url)
		if err != nil {
			return err
		}
		fmt.Printf("applied %d migration(s) %v\n", len(done), done)
		return nil
	}
	if len(args) == 1 && args[0] == "status" {
		rows, err := dbx.Status(ctx, url)
		if err != nil {
			return err
		}
		bad := 0
		for _, r := range rows {
			switch {
			case r.Pending:
				fmt.Printf("%04d_%s  pending\n", r.Version, r.Name)
			case !r.ChecksumOK:
				bad++
				fmt.Printf("%04d_%s  applied %s  checksum mismatch\n", r.Version, r.Name, r.AppliedAt.UTC().Format(time.RFC3339))
			default:
				fmt.Printf("%04d_%s  applied %s  checksum ok\n", r.Version, r.Name, r.AppliedAt.UTC().Format(time.RFC3339))
			}
		}
		if bad > 0 {
			return fmt.Errorf("%d migration(s) do not match this binary", bad)
		}
		return nil
	}
	return errors.New("usage: console-server migrate up|status")
}

func account(args []string, logger *slog.Logger) error {
	if len(args) == 0 {
		return errors.New("usage: console-server account bootstrap|unlock --space S --username U")
	}
	fs := flag.NewFlagSet("account", flag.ExitOnError)
	spaceName := fs.String("space", "", "admin or ops")
	username := fs.String("username", "", "account name")
	_ = fs.Parse(args[1:])
	cfg, err := load()
	if err != nil {
		return err
	}
	a, err := app.New(cfg, logger)
	if err != nil {
		return err
	}
	defer a.Close()
	ctx := context.Background()
	switch args[0] {
	case "bootstrap":
		code, err := a.Bootstrap(ctx, *spaceName, *username)
		if err != nil {
			return err
		}
		// 激活码只显示这一次。
		fmt.Printf("activation code for %s (valid for 24 hours): %s\n", *username, code)
		return nil
	case "unlock":
		if err := a.CLIUnlock(ctx, *spaceName, *username); err != nil {
			return err
		}
		fmt.Printf("unlocked %s\n", *username)
		return nil
	}
	return errors.New("usage: console-server account bootstrap|unlock --space S --username U")
}

func auditCmd(args []string, logger *slog.Logger) error {
	const usage = "usage: console-server audit verify [--from-seq N] | audit archive"
	if len(args) == 0 {
		return errors.New(usage)
	}
	cfg, err := load()
	if err != nil {
		return err
	}
	a, err := app.New(cfg, logger)
	if err != nil {
		return err
	}
	defer a.Close()
	ctx := context.Background()
	switch args[0] {
	case "verify":
		fs := flag.NewFlagSet("audit verify", flag.ExitOnError)
		from := fs.Int64("from-seq", 0, "start from this seq (the previous record must still exist to check the link)")
		_ = fs.Parse(args[1:])
		res, err := a.AuditVerify(ctx, *from)
		if err != nil {
			return err
		}
		for _, w := range res.Warnings {
			fmt.Println("warning:", w)
		}
		if res.AnchorSource != "external" {
			fmt.Println("warning: anchors were read from the database only; configure CON_AUDIT_ANCHOR_READ_* to compare with the external store")
		}
		if res.Issue != nil {
			fmt.Println("FAILED", res.Issue.String())
			return errors.New("audit verify failed: " + res.Issue.Type)
		}
		fmt.Printf("OK records=%d first=%d last=%d anchors=%d source=%s\n", res.Records, res.FirstSeq, res.LastSeq, res.Anchors, res.AnchorSource)
		return nil
	case "archive":
		done, err := a.AuditArchive(ctx)
		for _, d := range done {
			fmt.Printf("archived %s seq=%d..%d count=%d sha256=%s key=%s\n", d.Partition, d.First, d.Last, d.Count, d.SHA256, d.Key)
		}
		if err != nil {
			return err
		}
		if len(done) == 0 {
			fmt.Println("nothing to archive")
		}
		return nil
	}
	return errors.New(usage)
}

func keys(args []string) error {
	if len(args) != 1 || args[0] != "rotate" {
		return errors.New("usage: console-server keys rotate")
	}
	cfg, err := load()
	if err != nil {
		return err
	}
	if problems := cfg.DataKeys.Problems(); len(problems) > 0 {
		return app.JoinProblems(problems)
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, string(cfg.DatabaseURL))
	if err != nil {
		return errors.New("CON_DATABASE_URL is not a valid connection string")
	}
	defer db.Close()
	n, err := secret.Rotate(ctx, db, cfg.DataKeys)
	if err != nil {
		return err
	}
	fmt.Printf("re-encrypted %d record(s) with %s\n", n, cfg.DataKeys.Active)
	return nil
}
