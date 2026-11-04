package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"tianting/console/internal/apierr"
	"tianting/console/internal/audit"
	"tianting/console/internal/ids"
)

// CS-022、CS-023：CSV 导入。两步：validate 整体校验并发 importToken；提交时再调 im-server。

const (
	importMaxRows   = 5000
	importMaxErrors = 100
	importPreview   = 20
	importMaxBytes  = 8 << 20
	importTTL       = time.Hour
	maxRemarkLen    = 32

	jobUsers         = "users"
	jobFriendsImport = "friends.import"
	jobFriendsDelete = "friends.delete"
)

// rowError 是一行的校验错误。msg 不带字段值：备注不能经错误返回或落日志。
type rowError struct {
	Line int    `json:"line"`
	Code int    `json:"code"`
	Msg  string `json:"msg"`
}

// errRows 收集校验错误，只留前 100 条。
type errRows struct {
	list  []rowError
	total int
}

func (e *errRows) add(line, code int, msg string) {
	e.total++
	if len(e.list) < importMaxErrors {
		e.list = append(e.list, rowError{line, code, msg})
	}
}

var errTooManyRows = apierr.New(apierr.BatchLimit, "a file can have at most 5000 rows")

// readUpload 把请求里的 CSV 和表单字段读进内存。不用 ParseMultipartForm：它可能把文件写到临时目录，备注不能落盘。
func (c *rc) readUpload() (file []byte, fields map[string]string, ok bool) {
	fields = map[string]string{}
	c.r.Body = http.MaxBytesReader(c.w, c.r.Body, importMaxBytes+1<<16)
	mr, err := c.r.MultipartReader()
	if err != nil {
		c.fail(apierr.New(apierr.BadRequest, "expected a multipart upload"))
		return nil, nil, false
	}
	remaining := int64(importMaxBytes)
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			c.fail(apierr.New(apierr.BadRequest, "invalid multipart upload"))
			return nil, nil, false
		}
		data, err := io.ReadAll(io.LimitReader(part, remaining+1))
		if err != nil || int64(len(data)) > remaining {
			c.fail(apierr.New(apierr.BatchLimit, "the file is too large"))
			return nil, nil, false
		}
		remaining -= int64(len(data))
		if part.FormName() == "file" {
			file = data
		} else {
			fields[part.FormName()] = string(data)
		}
	}
	if file == nil {
		c.fail(apierr.New(apierr.BadRequest, "file is required"))
		return nil, nil, false
	}
	return file, fields, true
}

func newCSV(file []byte) (*csv.Reader, *apierr.Error) {
	file = bytes.TrimPrefix(file, []byte("\xef\xbb\xbf"))
	if !utf8.Valid(file) {
		return nil, apierr.New(apierr.BadRequest, "the file must be UTF-8")
	}
	r := csv.NewReader(bytes.NewReader(file))
	r.FieldsPerRecord = -1
	r.ReuseRecord = true
	return r, nil
}

// importUser 是一行用户。
type importUser struct {
	UserID   string `json:"userId"`
	Nickname string `json:"nickname,omitempty"`
	Avatar   string `json:"avatar,omitempty"`
}

func checkUser(u importUser, line int, errs *errRows) {
	switch {
	case !validID(u.UserID):
		errs.add(line, apierr.InvalidID, "invalid userId")
	case utf8.RuneCountInString(u.Nickname) > 32:
		errs.add(line, apierr.BadRequest, "nickname is longer than 32 characters")
	case utf8.RuneCountInString(u.Avatar) > 512:
		errs.add(line, apierr.BadRequest, "avatar is longer than 512 characters")
	}
}

func parseUsersCSV(file []byte) ([]importUser, *errRows, *apierr.Error) {
	r, e := newCSV(file)
	if e != nil {
		return nil, nil, e
	}
	header, err := r.Read()
	if err != nil || len(header) != 3 || header[0] != "userId" || header[1] != "nickname" || header[2] != "avatar" {
		return nil, nil, apierr.New(apierr.BadRequest, "the header must be userId,nickname,avatar")
	}
	errs := &errRows{}
	order := map[string]int{} // 文件内重复以最后一条为准
	var out []importUser
	rows := 0
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		rows++
		if rows > importMaxRows {
			return nil, nil, errTooManyRows
		}
		if err != nil {
			line := rows + 1
			var pe *csv.ParseError
			if errors.As(err, &pe) {
				line = pe.Line
			}
			errs.add(line, apierr.BadRequest, "invalid CSV row")
			continue
		}
		line, _ := r.FieldPos(0)
		if len(rec) != 3 {
			errs.add(line, apierr.BadRequest, "a row must have 3 columns")
			continue
		}
		u := importUser{UserID: strings.TrimRight(rec[0], "\r"), Nickname: rec[1], Avatar: rec[2]}
		checkUser(u, line, errs)
		if i, seen := order[u.UserID]; seen {
			out[i] = u
		} else {
			order[u.UserID] = len(out)
			out = append(out, u)
		}
	}
	return out, errs, nil
}

// friendPair 是一行好友。备注只在内存里传给 im-server。
type friendPair struct {
	A       string `json:"a"`
	B       string `json:"b"`
	RemarkA string `json:"remarkA,omitempty"`
	RemarkB string `json:"remarkB,omitempty"`
}

func parseFriendsCSV(file []byte, withRemarks bool) ([]friendPair, *errRows, *apierr.Error) {
	r, e := newCSV(file)
	if e != nil {
		return nil, nil, e
	}
	errs := &errRows{}
	order := map[[2]string]int{}
	var out []friendPair
	rows := 0
	for first := true; ; first = false {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err == nil && first && len(rec) >= 2 && rec[0] == "a" && rec[1] == "b" {
			continue // 表头可选
		}
		rows++
		if rows > importMaxRows {
			return nil, nil, errTooManyRows
		}
		if err != nil {
			line := rows
			var pe *csv.ParseError
			if errors.As(err, &pe) {
				line = pe.Line
			}
			errs.add(line, apierr.BadRequest, "invalid CSV row")
			continue
		}
		line, _ := r.FieldPos(0)
		if len(rec) != 2 && !(withRemarks && len(rec) == 4) {
			errs.add(line, apierr.BadRequest, "wrong number of columns")
			continue
		}
		p := friendPair{A: rec[0], B: rec[1]}
		if len(rec) == 4 {
			p.RemarkA, p.RemarkB = rec[2], rec[3]
		}
		switch {
		case !validID(p.A) || !validID(p.B):
			errs.add(line, apierr.InvalidID, "invalid userId")
		case p.A == p.B:
			errs.add(line, apierr.BadRequest, "a and b must be different")
		case utf8.RuneCountInString(strings.TrimSpace(p.RemarkA)) > maxRemarkLen || utf8.RuneCountInString(strings.TrimSpace(p.RemarkB)) > maxRemarkLen:
			errs.add(line, apierr.BadRequest, "remark is longer than 32 characters")
		}
		key := [2]string{p.A, p.B}
		if p.A > p.B {
			key = [2]string{p.B, p.A}
		}
		if i, seen := order[key]; seen {
			out[i] = p
		} else {
			order[key] = len(out)
			out = append(out, p)
		}
	}
	return out, errs, nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// saveJob 存导入任务，返回 importToken。token 只对发起的账号有效，1 小时过期，只能用一次。
func (c *rc) saveJob(kind, sum string, total int, preview any, rows string) (string, error) {
	raw, err := json.Marshal(preview)
	if err != nil {
		return "", err
	}
	id := ids.New(c.a.Clock.Now())
	_, err = c.a.DB.Exec(c.ctx, `INSERT INTO biz.import_jobs (id, account_id, kind, file_sha256, total, preview, rows, created_at, expires_at) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9)`,
		id, c.acct.ID, kind, sum, total, string(raw), rows, c.now(), c.now()+importTTL.Milliseconds())
	return id, err
}

func (c *rc) validateResult(kind string, file []byte, total int, errs *errRows, preview any, rows string) {
	if errs.total > 0 {
		c.ok(map[string]any{"valid": false, "total": total, "errorCount": errs.total, "errors": errs.list})
		return
	}
	if total == 0 {
		c.fail(apierr.New(apierr.BadRequest, "the file has no rows"))
		return
	}
	sum := sha256Hex(file)
	token, err := c.saveJob(kind, sum, total, preview, rows)
	if err != nil {
		c.failErr("save import job", err)
		return
	}
	c.ok(map[string]any{"valid": true, "importToken": token, "total": total, "fileSha256": sum, "preview": preview})
}

// validateUsers：multipart CSV，或单个表单（JSON）。
func (c *rc) validateUsers() {
	var (
		file []byte
		list []importUser
		errs *errRows
	)
	if !strings.HasPrefix(c.r.Header.Get("Content-Type"), "multipart/") {
		var one importUser
		if !c.readJSON(&one) {
			return
		}
		errs = &errRows{}
		checkUser(one, 1, errs)
		list = []importUser{one}
		file, _ = json.Marshal(one)
	} else {
		var ok bool
		if file, _, ok = c.readUpload(); !ok {
			return
		}
		var e *apierr.Error
		if list, errs, e = parseUsersCSV(file); e != nil {
			c.fail(e)
			return
		}
	}
	preview := list
	if len(preview) > importPreview {
		preview = preview[:importPreview]
	}
	rows, err := json.Marshal(list)
	if err != nil {
		c.failErr("validate users", err)
		return
	}
	c.validateResult(jobUsers, file, len(list), errs, preview, string(rows))
}

// job 是读出来的导入任务。
type importJob struct {
	id, sum, rows string
	total         int
}

func (c *rc) loadJob(kind, token string) (*importJob, bool) {
	j := importJob{id: token}
	err := c.a.DB.QueryRow(c.ctx, `SELECT file_sha256, total, rows FROM biz.import_jobs WHERE id::text = $1 AND account_id = $2::uuid AND kind = $3 AND used_at IS NULL AND expires_at > $4`,
		token, c.acct.ID, kind, c.now()).Scan(&j.sum, &j.total, &j.rows)
	if err != nil {
		c.fail(&apierr.Error{Code: apierr.BadRequest, Msg: "importToken is invalid, expired or already used", Reason: "importTokenInvalid"})
		return nil, false
	}
	return &j, true
}

// useJob 把任务标成已用。并发提交只有一个成功。
func (c *rc) useJob(j *importJob) error {
	tag, err := c.a.DB.Exec(c.ctx, `UPDATE biz.import_jobs SET used_at = $2 WHERE id::text = $1 AND used_at IS NULL`, j.id, c.now())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return &apierr.Error{Code: apierr.BadRequest, Msg: "importToken is invalid, expired or already used", Reason: "importTokenInvalid"}
	}
	return nil
}

func (c *rc) importUsers() {
	var req struct {
		ImportToken string `json:"importToken"`
	}
	if !c.readJSON(&req) {
		return
	}
	j, ok := c.loadJob(jobUsers, req.ImportToken)
	if !ok {
		return
	}
	var users []importUser
	if err := json.Unmarshal([]byte(j.rows), &users); err != nil {
		c.failErr("import users", err)
		return
	}
	batches := chunks(users, imBatchSize)
	params := map[string]any{"total": j.total, "fileSha256": j.sum, "batches": len(batches)}
	c.audited("user.import", audit.Target{Type: "user", Count: j.total}, params, "", func() (any, error) {
		if err := c.useJob(j); err != nil {
			return nil, err
		}
		return c.runBatches(len(batches), func(i int, id string) error {
			return c.imDo(id, "POST", "/admin/users/import", nil, map[string]any{"users": batches[i-1]}, nil)
		})
	})
}

// validateFriends：预览不含备注，任务表不存行。
func (c *rc) validateFriends(kind string, withRemarks bool) {
	file, _, ok := c.readUpload()
	if !ok {
		return
	}
	pairs, errs, e := parseFriendsCSV(file, withRemarks)
	if e != nil {
		c.fail(e)
		return
	}
	type previewPair struct {
		A string `json:"a"`
		B string `json:"b"`
	}
	preview := make([]previewPair, 0, importPreview)
	for i := 0; i < len(pairs) && i < importPreview; i++ {
		preview = append(preview, previewPair{pairs[i].A, pairs[i].B})
	}
	c.validateResult(kind, file, len(pairs), errs, preview, "")
}

func (c *rc) validateFriendsImport() { c.validateFriends(jobFriendsImport, true) }
func (c *rc) validateFriendsDelete() { c.validateFriends(jobFriendsDelete, false) }

// submitFriends：提交时重新上传同一文件，哈希一致才拆批调用。
func (c *rc) submitFriends(kind, action, method, path string) {
	file, fields, ok := c.readUpload()
	if !ok {
		return
	}
	reason, ok := c.reasonTicket(fields["reason"], fields["ticket"])
	if !ok {
		return
	}
	j, ok := c.loadJob(kind, fields["importToken"])
	if !ok {
		return
	}
	if sha256Hex(file) != j.sum {
		c.fail(&apierr.Error{Code: apierr.BadRequest, Msg: "the file is not the one that was validated", Reason: "fileChanged"})
		return
	}
	pairs, errs, e := parseFriendsCSV(file, kind == jobFriendsImport)
	if e != nil || errs.total > 0 {
		c.fail(apierr.New(apierr.BadRequest, "the file is not valid"))
		return
	}
	batches := chunks(pairs, imBatchSize)
	params := map[string]any{"pairs": len(pairs), "fileSha256": j.sum, "batches": len(batches)}
	c.ticket = fields["ticket"]
	c.audited(action, audit.Target{Type: "friendPair", Count: len(pairs)}, params, reason, func() (any, error) {
		if err := c.useJob(j); err != nil {
			return nil, err
		}
		resp, err := c.runBatches(len(batches), func(i int, id string) error {
			return notAvailable(c.imDo(id, method, path, nil, map[string]any{"pairs": batches[i-1]}, nil))
		})
		return resp, err
	})
}

func (c *rc) importFriends() {
	c.submitFriends(jobFriendsImport, "friend.import", "POST", "/admin/friends/import")
}

func (c *rc) deleteFriends() {
	c.submitFriends(jobFriendsDelete, "friend.delete", "DELETE", "/admin/friends")
}

// notAvailable：im-server 没有注册这个接口（AC-ADM-15-7）。
func notAvailable(err error) error {
	var e *apierr.Error
	if errors.As(err, &e) && e.Code == apierr.NotFound {
		return &apierr.Error{Code: apierr.NotFound, Msg: "this feature is not available on the server yet", Reason: "notAvailable"}
	}
	return err
}
