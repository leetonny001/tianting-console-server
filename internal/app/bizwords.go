package app

import (
	"net/http"
	"net/url"
	"strconv"

	"tianting/console/internal/apierr"
	"tianting/console/internal/audit"
)

// CS-206：词库和按用户查命中次数（PRD-chat F-MOD-01、F-MOD-02 规则 7、第 11.6、14.1 节；im-server 接口见 protocol/ADMIN.md"敏感词和举报"）。
// 权限点 moderation.words（运营、审核）；命中查询的权限点是 report.read（只给审核，console-chat 第 27 条，P-48 ③）。
// 主凭证 console 带 moderation.words、report.read 转调 im-server。
// 审计只记操作、wordId 和数量，**不记词内容**（AC-MOD-01-6，console-chat 第 24 条）；console 没有请求日志，请求体不进日志。
// 响应是白名单结构（console-chat 第 20、22 条）：只放词库页、命中统计要读的字段。

const (
	actionWordAdd    = "moderation.word.add"
	actionWordUpdate = "moderation.word.update"
	actionWordDelete = "moderation.word.delete"
	actionWordImport = "moderation.word.import"
	actionHitsView   = "moderation.hits.view"

	maxWordImport = 5000 // 一次最多 5000 条（F-MOD-01 规则 1，AC-MOD-01-4）
	// maxImportBody：5000 条 × 64 个码点 × 4 字节，加上 JSON 的引号、逗号和转义。
	maxImportBody = 4 << 20
)

// wordJSON 是词库的一行：词 ID、原文（后台按纯文本显示，AC-MOD-01-7）、状态、创建和修改时间。
type wordJSON struct {
	WordID    int64  `json:"wordId"`
	Word      string `json:"word"`
	State     string `json:"state"`
	CreatedAt int64  `json:"createdAt"`
	UpdatedAt int64  `json:"updatedAt"`
}

// listWords：搜索（q，按标准化后的子串）、按状态筛选、翻页。不写审计（im-server 也不写）。
// im-server 的 nextCursor 是数字（0 表示没有更多），这里换成和其他列表一样的字符串（空串表示没有更多）。
func (c *rc) listWords() {
	q, ok := c.listParams("cursor")
	if !ok {
		return
	}
	if s := c.r.URL.Query().Get("state"); s != "" {
		if s != "active" && s != "disabled" {
			c.fail(apierr.New(apierr.BadRequest, "state must be active or disabled"))
			return
		}
		q.Set("state", s)
	}
	var page struct {
		Words      []wordJSON `json:"words"`
		NextCursor int64      `json:"nextCursor"`
	}
	if err := c.im(http.MethodGet, "/admin/moderation/words", q, nil, &page); err != nil {
		c.failErr("list words", err)
		return
	}
	if page.Words == nil {
		page.Words = []wordJSON{}
	}
	next := ""
	if page.NextCursor > 0 {
		next = strconv.FormatInt(page.NextCursor, 10)
	}
	c.ok(map[string]any{"words": page.Words, "nextCursor": next})
}

// addWord：单个添加。intent 不带词（AC-MOD-01-6）；result 记 wordId 和是不是新加的（按标准化后去重，backend-chat 第 100 条）。
func (c *rc) addWord() {
	var req struct {
		Word string `json:"word"`
	}
	if !c.readJSON(&req) {
		return
	}
	c.audited(actionWordAdd, audit.NewTarget("word"), nil, "", func() (any, error) {
		var out struct {
			Word    wordJSON `json:"word"`
			Created bool     `json:"created"`
		}
		if err := c.im(http.MethodPost, "/admin/moderation/words", nil, map[string]any{"word": req.Word}, &out); err != nil {
			return nil, err
		}
		c.resultParams = map[string]any{"wordId": out.Word.WordID, "created": out.Created}
		return out, nil
	})
}

// wordPath 校验路径里的 wordId（正整数）。
func (c *rc) wordPath() (int64, string, bool) {
	raw := c.r.PathValue("id")
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id < 1 {
		c.fail(apierr.New(apierr.BadRequest, "invalid wordId"))
		return 0, "", false
	}
	return id, "/admin/moderation/words/" + strconv.FormatInt(id, 10), true
}

// patchWord：只改状态（停用、启用）。
func (c *rc) patchWord() {
	id, path, ok := c.wordPath()
	if !ok {
		return
	}
	var req struct {
		State string `json:"state"`
	}
	if !c.readJSON(&req) {
		return
	}
	if req.State != "active" && req.State != "disabled" {
		c.fail(apierr.New(apierr.BadRequest, "state must be active or disabled"))
		return
	}
	target := audit.NewTarget("word", strconv.FormatInt(id, 10))
	c.audited(actionWordUpdate, target, map[string]any{"wordId": id, "state": req.State}, "", func() (any, error) {
		var out struct {
			Word wordJSON `json:"word"`
		}
		err := c.im(http.MethodPatch, path, nil, map[string]any{"state": req.State}, &out)
		return out, err
	})
}

func (c *rc) deleteWord() {
	id, path, ok := c.wordPath()
	if !ok {
		return
	}
	c.audited(actionWordDelete, audit.NewTarget("word", strconv.FormatInt(id, 10)), map[string]any{"wordId": id}, "", func() (any, error) {
		return struct{}{}, c.im(http.MethodDelete, path, nil, nil, nil)
	})
}

// importWords：页面读 txt（一行一个）后拆成数组提交（backend-chat 第 103 条）。超过 5000 条 400 / 4131，不写审计、不调用 im-server。
// intent 只记条数，result 记新增、重复、无效的数量。
func (c *rc) importWords() {
	var req struct {
		Words []string `json:"words"`
	}
	if !c.readJSONLimit(&req, maxImportBody) {
		return
	}
	if len(req.Words) > maxWordImport {
		c.fail(apierr.New(apierr.BatchLimit, "at most %d words per import", maxWordImport))
		return
	}
	if req.Words == nil {
		req.Words = []string{}
	}
	c.audited(actionWordImport, audit.NewTarget("word"), map[string]any{"count": len(req.Words)}, "", func() (any, error) {
		var out struct {
			Added     int `json:"added"`
			Duplicate int `json:"duplicate"`
			Invalid   int `json:"invalid"`
		}
		if err := c.im(http.MethodPost, "/admin/moderation/words/import", nil, map[string]any{"words": req.Words}, &out); err != nil {
			return nil, err
		}
		c.resultParams = map[string]any{"count": len(req.Words), "added": out.Added, "duplicate": out.Duplicate, "invalid": out.Invalid}
		return out, nil
	})
}

// hitJSON 是一条最近的命中：时间、场景、词 ID。没有任何内容（backend-chat 第 114 条）。
type hitJSON struct {
	At     int64  `json:"at"`
	Scene  string `json:"scene"`
	WordID int64  `json:"wordId"`
}

// getHits：按用户查保留期内的命中次数和最近 50 条。查询本身写审计（目标是 userId）。
func (c *rc) getHits() {
	uid := c.r.URL.Query().Get("userId")
	if !validID(uid) {
		c.fail(apierr.New(apierr.InvalidID, "invalid userId"))
		return
	}
	c.audited(actionHitsView, audit.NewTarget("user", uid), nil, "", func() (any, error) {
		var out struct {
			UserID string         `json:"userId"`
			Days   int            `json:"days"`
			Counts map[string]int `json:"counts"`
			Recent []hitJSON      `json:"recent"`
		}
		if err := c.im(http.MethodGet, "/admin/moderation/hits", url.Values{"userId": {uid}}, nil, &out); err != nil {
			return nil, err
		}
		if out.Counts == nil {
			out.Counts = map[string]int{}
		}
		if out.Recent == nil {
			out.Recent = []hitJSON{}
		}
		c.resultParams = map[string]any{"count": len(out.Recent)}
		return out, nil
	})
}
