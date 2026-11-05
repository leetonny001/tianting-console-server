package app

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"tianting/console/internal/apierr"
	"tianting/console/internal/audit"
	"tianting/console/internal/notify"
	"tianting/console/internal/secret"
	"tianting/console/internal/totp"
)

var usernameRe = regexp.MustCompile(`^[a-z0-9._-]{3,32}$`)

const (
	recoveryCount = 10
	activationTTL = 24 * 3600 * 1000 // 毫秒
)

var codeEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

// randomCode 生成 n 位 base32（激活码、恢复码）。
func randomCode(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return codeEnc.EncodeToString(b)[:n], nil
}

func normalizeCode(s string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), "-", ""))
}

func normalizeUsername(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func credentialsError() *apierr.Error {
	return apierr.New(apierr.CredentialsInvalid, "invalid username, password or code")
}

func accountTarget(a accountRow) audit.Target { return audit.NewTarget("account", a.Username) }

func (a *App) notifier() notify.Notifier { return notify.Notifier{Now: a.Clock.Now} }

// Notifier 返回通知发送器。
func (a *App) Notifier() notify.Notifier { return a.notifier() }

// loginKey 是失败计数用的账号名：规范化，太长的截断。不合法的名字也按一个键计数和上锁，不能绕过。
func loginKey(s string) string { return truncate(normalizeUsername(s), 64) }

// dummy 是不存在的账号用来验证的哈希：响应时间和存在的账号一致（F-CON-03 规则 2）。
func (a *App) dummy(ctx context.Context) (string, error) {
	var err error
	a.dummyOnce.Do(func() { a.dummyHash, err = a.hasher.Hash(ctx, "dummy-password-for-constant-time") })
	return a.dummyHash, err
}

func (a *App) findAccount(ctx context.Context, space, username string) (*accountRow, error) {
	acct, err := scanAccount(a.DB.QueryRow(ctx, `SELECT `+accountColumns+` FROM auth.accounts WHERE space = $1 AND username = $2`, space, username))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &acct, nil
}

// checkOTP 校验动态码并消费步长。last_step 用条件更新：并发时同一个码只有一个请求成功（防重放，AC-CON-03-4）。
func (a *App) checkOTP(ctx context.Context, accountID, input string) (bool, error) {
	var kid string
	var nonce, ct []byte
	var last int64
	err := a.DB.QueryRow(ctx, `SELECT kid, nonce, ciphertext, last_step FROM auth.totp WHERE account_id = $1::uuid AND confirmed`, accountID).Scan(&kid, &nonce, &ct, &last)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	seed, err := a.Cfg.DataKeys.Decrypt(accountID, kid, nonce, ct)
	if err != nil {
		return false, err
	}
	step, ok := totp.Match(seed, strings.TrimSpace(input), a.Clock.Now())
	if !ok || step <= last {
		return false, nil
	}
	tag, err := a.DB.Exec(ctx, `UPDATE auth.totp SET last_step = $2 WHERE account_id = $1::uuid AND last_step < $2`, accountID, step)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// useRecovery 用掉一个恢复码，返回剩余个数。
func (a *App) useRecovery(ctx context.Context, accountID, code string) (ok bool, left int, err error) {
	tag, err := a.DB.Exec(ctx, `UPDATE auth.recovery_codes SET used_at = $3 WHERE account_id = $1::uuid AND code_hash = $2 AND used_at IS NULL`,
		accountID, secret.PepperHash(a.pepper(), normalizeCode(code)), a.Clock.Now().UnixMilli())
	if err != nil || tag.RowsAffected() != 1 {
		return false, 0, err
	}
	err = a.DB.QueryRow(ctx, `SELECT count(*) FROM auth.recovery_codes WHERE account_id = $1::uuid AND used_at IS NULL`, accountID).Scan(&left)
	return true, left, err
}

// login 一步提交。6 种失败统一 401 / 4015，响应完全相同；类别只进审计。
func (c *rc) login() {
	var req struct {
		Username     string `json:"username"`
		Password     string `json:"password"`
		OTP          string `json:"otp"`
		RecoveryCode string `json:"recoveryCode"`
	}
	if !c.ipAllowed() || !c.readJSON(&req) {
		return
	}
	username := loginKey(req.Username)
	locked, err := c.locked(username)
	if err != nil {
		c.failErr("check lock", err)
		return
	}
	if locked {
		c.fail(c.lockedError(username))
		return
	}
	acct, err := c.a.findAccount(c.ctx, c.space.Name, username)
	if err != nil {
		c.failErr("find account", err)
		return
	}
	hash := ""
	if acct != nil {
		hash = acct.PasswordHash
	}
	if hash == "" { // 不存在或待激活：做一次同样的计算
		if hash, err = c.a.dummy(c.ctx); err != nil {
			c.failErr("dummy hash", err)
			return
		}
	}
	match, err := c.a.hasher.Verify(c.ctx, hash, req.Password)
	if err != nil {
		c.failErr("verify password", err)
		return
	}
	fail := func(category string) {
		c.recordFailure(username, acct)
		saved := c.acct
		if acct != nil {
			c.acct = *acct
		} else {
			c.acct = accountRow{Username: username}
		}
		_ = c.event("auth.login", audit.NewTarget("account", username), map[string]any{"category": category}, audit.Failure, apierr.CredentialsInvalid)
		c.acct = saved
		c.fail(credentialsError())
	}
	switch {
	case acct == nil:
		fail("notFound")
		return
	case !match && acct.PasswordHash == "":
		fail("pending")
		return
	case !match:
		fail("password")
		return
	case acct.Status == "disabled":
		fail("disabled")
		return
	case acct.Status != "active":
		fail("pending")
		return
	}
	usedRecovery, recoveryLeft := false, -1
	if req.OTP != "" {
		ok, err := c.a.checkOTP(c.ctx, acct.ID, req.OTP)
		if err != nil {
			c.failErr("check otp", err)
			return
		}
		if !ok {
			fail("otp")
			return
		}
	} else {
		ok, left, err := c.a.useRecovery(c.ctx, acct.ID, req.RecoveryCode)
		if err != nil {
			c.failErr("use recovery code", err)
			return
		}
		if !ok {
			fail("recovery")
			return
		}
		usedRecovery, recoveryLeft = true, left
	}
	c.clearNameIP(username)
	var sid string
	if err := pgx.BeginFunc(c.ctx, c.a.DB, func(tx pgx.Tx) error {
		var err error
		sid, err = c.a.newSession(c.ctx, tx, acct.ID, c.space.Name, "full", c.now())
		return err
	}); err != nil {
		c.failErr("create session", err)
		return
	}
	c.acct, c.sid, c.sess = *acct, sid, sessionRow{State: "full"}
	if c.roles, err = c.a.activeRoles(c.ctx, acct.ID); err != nil {
		c.failErr("load roles", err)
		return
	}
	if err := c.event("auth.login", accountTarget(*acct), nil, audit.Success, 0); err != nil {
		c.fail(apierr.New(apierr.AuditUnavailable, "audit service unavailable"))
		return
	}
	resp := c.sessionPayload()
	if usedRecovery {
		_ = c.event("auth.recovery_code_used", accountTarget(*acct), map[string]any{"left": recoveryLeft}, audit.Success, 0)
		c.notifySelf(notify.KindRecoveryUsed, map[string]any{"who": acct.Username, "at": c.now(), "left": recoveryLeft})
	}
	if left := c.recoveryLeft(usedRecovery, recoveryLeft); left <= 2 {
		resp["recoveryCodesLeft"] = left
		if !usedRecovery {
			c.notifySelf(notify.KindRecoveryLow, map[string]any{"who": acct.Username, "at": c.now(), "left": left})
		}
	}
	c.setCookie(sid)
	c.ok(resp)
}

func (c *rc) recoveryLeft(known bool, left int) int {
	if known {
		return left
	}
	n := recoveryCount
	if err := c.a.DB.QueryRow(c.ctx, `SELECT count(*) FROM auth.recovery_codes WHERE account_id = $1::uuid AND used_at IS NULL`, c.acct.ID).Scan(&n); err != nil {
		return recoveryCount
	}
	return n
}

func (c *rc) notifySelf(kind string, payload map[string]any) {
	if err := c.a.notifier().ToAccount(context.WithoutCancel(c.ctx), c.a.DB, c.acct.ID, c.space.Name, kind, payload); err != nil {
		c.a.Log.Error("notify", "kind", kind, "err", err)
	}
}

// activate：账号名 + 激活码 + 新密码，成功得到 setup 会话。激活码错误计入失败次数。
func (c *rc) activate() {
	var req struct {
		Username    string `json:"username"`
		Code        string `json:"code"`
		NewPassword string `json:"newPassword"`
	}
	if !c.ipAllowed() || !c.readJSON(&req) {
		return
	}
	username := loginKey(req.Username)
	locked, err := c.locked(username)
	if err != nil {
		c.failErr("check lock", err)
		return
	}
	if locked {
		c.fail(c.lockedError(username))
		return
	}
	acct, err := c.a.findAccount(c.ctx, c.space.Name, username)
	if err != nil {
		c.failErr("find account", err)
		return
	}
	now := c.now()
	if acct == nil || acct.Status != "pending" || acct.ActivationHash == "" || now > acct.ActivationExpires ||
		secret.PepperHash(c.a.pepper(), normalizeCode(req.Code)) != acct.ActivationHash {
		c.recordFailure(username, acct)
		saved := c.acct
		c.acct = accountRow{Username: username}
		_ = c.event("auth.activate", audit.NewTarget("account", username), nil, audit.Failure, apierr.CredentialsInvalid)
		c.acct = saved
		c.fail(credentialsError())
		return
	}
	if reason := c.a.passwordProblem(c.ctx, *acct, req.NewPassword); reason != "" {
		e := apierr.New(apierr.BadRequest, "password does not meet the policy")
		e.Reason = reason
		c.fail(e)
		return
	}
	hash, err := c.a.hasher.Hash(c.ctx, req.NewPassword)
	if err != nil {
		c.failErr("hash password", err)
		return
	}
	var sid string
	if err := pgx.BeginFunc(c.ctx, c.a.DB, func(tx pgx.Tx) error {
		// activation_hash 条件防止同一个激活码并发用两次。
		tag, err := tx.Exec(c.ctx, `UPDATE auth.accounts SET password_hash = $2, password_history = $3, activation_hash = '' WHERE id = $1::uuid AND activation_hash <> ''`,
			acct.ID, hash, pushHistory(acct.PasswordHistory, hash))
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return credentialsError()
		}
		sid, err = c.a.newSession(c.ctx, tx, acct.ID, c.space.Name, "setup", now)
		return err
	}); err != nil {
		c.failErr("activate", err)
		return
	}
	c.acct, c.sid, c.sess = *acct, sid, sessionRow{State: "setup"}
	c.roles = []string{}
	_ = c.event("auth.activate", accountTarget(*acct), nil, audit.Success, 0)
	c.setCookie(sid)
	c.ok(c.sessionPayload())
}

func (c *rc) totpSetup() {
	if c.sess.State != "setup" {
		c.fail(apierr.New(apierr.BadRequest, "two-step verification is already set up"))
		return
	}
	seed, err := totp.NewSecret()
	if err != nil {
		c.failErr("totp secret", err)
		return
	}
	kid, nonce, ct, err := c.a.Cfg.DataKeys.Encrypt(c.acct.ID, seed)
	if err != nil {
		c.failErr("encrypt totp", err)
		return
	}
	// 只有还没确认的才能覆盖：确认过的种子不能被 setup 会话换掉。
	if _, err := c.a.DB.Exec(c.ctx, `INSERT INTO auth.totp (account_id, kid, nonce, ciphertext) VALUES ($1::uuid, $2, $3, $4)
		ON CONFLICT (account_id) DO UPDATE SET kid = $2, nonce = $3, ciphertext = $4, last_step = 0 WHERE NOT auth.totp.confirmed`, c.acct.ID, kid, nonce, ct); err != nil {
		c.failErr("store totp", err)
		return
	}
	c.ok(map[string]any{"otpauthUri": totp.URI("Tianting "+c.space.Name, c.acct.Username, seed)})
}

// totpConfirm：提交一次正确的动态码，发 10 个恢复码（只显示一次），会话升为 full。
func (c *rc) totpConfirm() {
	var req struct {
		OTP string `json:"otp"`
	}
	if !c.readJSON(&req) {
		return
	}
	if c.sess.State != "setup" {
		c.fail(apierr.New(apierr.BadRequest, "two-step verification is already set up"))
		return
	}
	var kid string
	var nonce, ct []byte
	err := c.a.DB.QueryRow(c.ctx, `SELECT kid, nonce, ciphertext FROM auth.totp WHERE account_id = $1::uuid AND NOT confirmed`, c.acct.ID).Scan(&kid, &nonce, &ct)
	if errors.Is(err, pgx.ErrNoRows) {
		c.fail(apierr.New(apierr.BadRequest, "call totp/setup first"))
		return
	}
	if err != nil {
		c.failErr("load totp", err)
		return
	}
	seed, err := c.a.Cfg.DataKeys.Decrypt(c.acct.ID, kid, nonce, ct)
	if err != nil {
		c.failErr("decrypt totp", err)
		return
	}
	step, ok := totp.Match(seed, strings.TrimSpace(req.OTP), c.a.Clock.Now())
	if !ok {
		c.recordFailure(c.acct.Username, &c.acct)
		c.fail(credentialsError())
		return
	}
	codes, hashes, err := c.a.newRecoveryCodes()
	if err != nil {
		c.failErr("recovery codes", err)
		return
	}
	now := c.now()
	if err := pgx.BeginFunc(c.ctx, c.a.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(c.ctx, `UPDATE auth.totp SET confirmed = true, last_step = $2 WHERE account_id = $1::uuid`, c.acct.ID, step); err != nil {
			return err
		}
		if err := replaceRecovery(c.ctx, tx, c.acct.ID, hashes); err != nil {
			return err
		}
		if _, err := tx.Exec(c.ctx, `UPDATE auth.accounts SET status = 'active', activated_at = $2 WHERE id = $1::uuid`, c.acct.ID, now); err != nil {
			return err
		}
		_, err := tx.Exec(c.ctx, `UPDATE auth.sessions SET state = 'full' WHERE id_hash = $1`, c.sess.IDHash)
		return err
	}); err != nil {
		c.failErr("confirm totp", err)
		return
	}
	c.sess.State = "full"
	_ = c.event("auth.totp_bound", accountTarget(c.acct), nil, audit.Success, 0)
	if err := c.a.notifier().ToRoles(context.WithoutCancel(c.ctx), c.a.DB, c.space.Name, []string{c.ps.SuperAdmin, c.ps.Auditor}, "", notify.KindActivated,
		map[string]any{"who": c.acct.Username, "at": now, "ip": c.ip}); err != nil {
		c.a.Log.Error("notify activated", "err", err)
	}
	resp := c.sessionPayload()
	resp["recoveryCodes"] = codes
	c.ok(resp)
}

func (a *App) newRecoveryCodes() (codes, hashes []string, err error) {
	for range recoveryCount {
		code, err := randomCode(16)
		if err != nil {
			return nil, nil, err
		}
		codes = append(codes, code)
		hashes = append(hashes, secret.PepperHash(a.pepper(), code))
	}
	return codes, hashes, nil
}

func replaceRecovery(ctx context.Context, tx pgx.Tx, accountID string, hashes []string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM auth.recovery_codes WHERE account_id = $1::uuid`, accountID); err != nil {
		return err
	}
	for _, h := range hashes {
		if _, err := tx.Exec(ctx, `INSERT INTO auth.recovery_codes (account_id, code_hash) VALUES ($1::uuid, $2)`, accountID, h); err != nil {
			return err
		}
	}
	return nil
}

func (c *rc) regenerateRecovery() {
	codes, hashes, err := c.a.newRecoveryCodes()
	if err != nil {
		c.failErr("recovery codes", err)
		return
	}
	c.audited("auth.recovery_codes_regenerated", accountTarget(c.acct), nil, "", func() (any, error) {
		err := pgx.BeginFunc(c.ctx, c.a.DB, func(tx pgx.Tx) error { return replaceRecovery(c.ctx, tx, c.acct.ID, hashes) })
		return map[string]any{"recoveryCodes": codes}, err
	})
}

// stepUpVerify：成功后 5 分钟内高危操作不再要求输入；同一会话连续 5 次失败注销会话并锁定账号 15 分钟。
func (c *rc) stepUpVerify() {
	var req struct {
		OTP string `json:"otp"`
	}
	if !c.readJSON(&req) {
		return
	}
	ok, err := c.a.checkOTP(c.ctx, c.acct.ID, req.OTP)
	if err != nil {
		c.failErr("check otp", err)
		return
	}
	if ok {
		if _, err := c.a.DB.Exec(c.ctx, `UPDATE auth.sessions SET step_up_at = $2, step_up_failures = 0 WHERE id_hash = $1`, c.sess.IDHash, c.now()); err != nil {
			c.failErr("step up", err)
			return
		}
		c.ok(struct{}{})
		return
	}
	c.stepUpFailed()
}

// stepUpFailed：动态码错误。正文授权的当次动态码和 step-up 共用同一个失败计数（F-CON-07 规则 4）。
func (c *rc) stepUpFailed() {
	_ = c.event("auth.step_up", accountTarget(c.acct), nil, audit.Failure, apierr.CredentialsInvalid)
	c.recordFailure(c.acct.Username, &c.acct)
	var fails int
	if err := c.a.DB.QueryRow(c.ctx, `UPDATE auth.sessions SET step_up_failures = step_up_failures + 1 WHERE id_hash = $1 RETURNING step_up_failures`, c.sess.IDHash).Scan(&fails); err != nil {
		c.failErr("step up", err)
		return
	}
	if fails >= 5 {
		ctx := context.WithoutCancel(c.ctx)
		if _, err := c.a.DB.Exec(ctx, `UPDATE auth.sessions SET revoked_reason = $2 WHERE id_hash = $1`, c.sess.IDHash, reasonRevoked); err != nil {
			c.failErr("revoke session", err)
			return
		}
		if err := c.a.lockAccount(ctx, c.space.Name, c.acct.Username, c.now()); err != nil {
			c.failErr("lock account", err)
			return
		}
		c.afterLock(c.acct.Username, &c.acct)
	}
	c.fail(credentialsError())
}

// changePassword：当前密码 + 当前动态码；成功后删除其他会话，保留当前会话。
func (c *rc) changePassword() {
	var req struct {
		CurrentPassword string `json:"currentPassword"`
		OTP             string `json:"otp"`
		NewPassword     string `json:"newPassword"`
	}
	if !c.readJSON(&req) {
		return
	}
	ok, err := c.a.hasher.Verify(c.ctx, c.acct.PasswordHash, req.CurrentPassword)
	if err != nil {
		c.failErr("verify password", err)
		return
	}
	if ok {
		if ok, err = c.a.checkOTP(c.ctx, c.acct.ID, req.OTP); err != nil {
			c.failErr("check otp", err)
			return
		}
	}
	if !ok {
		c.recordFailure(c.acct.Username, &c.acct)
		c.fail(credentialsError())
		return
	}
	if reason := c.a.passwordProblem(c.ctx, c.acct, req.NewPassword); reason != "" {
		e := apierr.New(apierr.BadRequest, "password does not meet the policy")
		e.Reason = reason
		c.fail(e)
		return
	}
	hash, err := c.a.hasher.Hash(c.ctx, req.NewPassword)
	if err != nil {
		c.failErr("hash password", err)
		return
	}
	c.audited("auth.password_changed", accountTarget(c.acct), nil, "", func() (any, error) {
		return struct{}{}, pgx.BeginFunc(c.ctx, c.a.DB, func(tx pgx.Tx) error {
			if _, err := tx.Exec(c.ctx, `UPDATE auth.accounts SET password_hash = $2, password_history = $3 WHERE id = $1::uuid`, c.acct.ID, hash, pushHistory(c.acct.PasswordHistory, hash)); err != nil {
				return err
			}
			// 当前运维会话保留（B-OPS-04），绑在它上面的 Grafana Cookie 作废（F-OPS-17 规则 1）。
			if _, err := tx.Exec(c.ctx, `DELETE FROM biz.grafana_sessions WHERE session_hash = $1`, c.sess.IDHash); err != nil {
				return err
			}
			return revokeAll(c.ctx, tx, c.acct.ID, c.sess.IDHash)
		})
	})
}

// passwordHistorySize：不能与最近 5 次相同。
const passwordHistorySize = 5

func pushHistory(history []string, hash string) []string {
	out := append([]string{hash}, history...)
	if len(out) > passwordHistorySize {
		out = out[:passwordHistorySize]
	}
	return out
}

// passwordProblem 返回不合规的原因（F-CON-04 规则 1），合规返回空串。
func (a *App) passwordProblem(ctx context.Context, acct accountRow, password string) string {
	n := utf8.RuneCountInString(password)
	lower := strings.ToLower(password)
	switch {
	case n < 12:
		return "tooShort"
	case n > 128:
		return "tooLong"
	case strings.Contains(lower, strings.ToLower(acct.Username)):
		return "containsUsername"
	case a.weak[lower]:
		return "weak"
	}
	for _, old := range acct.PasswordHistory {
		if same, err := a.hasher.Verify(ctx, old, password); err == nil && same {
			return "reused"
		}
	}
	return ""
}
