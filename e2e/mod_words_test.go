package e2e

// CS-206：词库接口和按用户查命中次数（PRD-chat F-MOD-01、F-MOD-02 规则 7、第 14.1 节；console-chat 第 24、27 条，P-48 ③）。

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

const wordsURL = "/console/api/moderation/words"

var (
	wordFields     = []string{"wordId", "word", "state", "createdAt", "updatedAt"}
	hitsFields     = []string{"userId", "days", "counts", "recent"}
	hitEntryFields = []string{"at", "scene", "wordId"}
)

// TC-MOD-01-05（AC-MOD-01-5）、TC-MOD-01-06（AC-MOD-01-6）经 console：
// support 添加词 403 / 4030、不调用 im-server；运营添加、重复添加（标准化后去重）、搜索、停用、导入、删除都经 console 成功，
// 响应只有白名单字段（im-server 多返回的字段不透传）；导入 5001 条 400 / 4131、不调用 im-server（AC-MOD-01-4 的 console 一侧）；
// console 审计每个操作都有 intent 和 result，记 wordId 和数量；console 全库、console 日志、im-server 审计都搜不到词（ZXQWORD）。
func TestTC_MOD_01_05_06_WordsViaConsole(t *testing.T) {
	const word = "ZXQWORD"
	w := newModWorld(t, 150*time.Second)
	super := w.super("adm1")
	op := super.create("op1", "operator")
	kf := super.create("kf1", "support")
	mod := super.create("mod1", "moderator")

	// AC-MOD-01-5：support 添加词 403 / 4030；超管、审计员同样没有（矩阵另测）。
	expect(t, "support add", kf.do("POST", wordsURL, map[string]any{"word": word}), 403, 4030)
	expect(t, "super add", super.do("POST", wordsURL, map[string]any{"word": word}), 403, 4030)
	if n := w.im.count("POST", "/admin/moderation/words"); n != 0 {
		t.Fatalf("denied add reached im-server %d times", n)
	}
	if rows := w.auditRows(`action = 'moderation.word.add' AND result = 'denied'`); len(rows) < 2 {
		t.Errorf("denied audit = %v", rows)
	}

	// im-server 以后多返回的字段（norm、compact、未知字段）不透传。
	w.im.mu.Lock()
	w.im.rewrite = func(path string, body []byte) []byte {
		if !strings.HasPrefix(path, "/admin/moderation/") {
			return body
		}
		out := injectFields(body, "words", map[string]any{"norm": "zxqword-norm", "compact": "zxq", "futureField": 1})
		// 单个的 word 对象里也加
		return []byte(strings.Replace(string(out), `"word":{`, `"word":{"norm":"zxqword-norm","futureField":1,`, 1))
	}
	w.im.mu.Unlock()

	r := op.do("POST", wordsURL, map[string]any{"word": word})
	expect(t, "operator add", r, 200, 0)
	keysWithin(t, "add", r.body, "word", "created")
	wd := asMap(t, "add.word", r.body["word"])
	keysWithin(t, "add.word", wd, wordFields...)
	id := fnum(wd["wordId"])
	if wd["word"] != word || wd["state"] != "active" || r.body["created"] != true || id <= 0 {
		t.Fatalf("add = %s", r.raw)
	}
	// 全角写法标准化后相同：返回已有的那条，created=false（backend-chat 第 100 条）。审核也能维护词库。
	r = mod.do("POST", wordsURL, map[string]any{"word": "ＺＸＱＷＯＲＤ"})
	expect(t, "moderator add duplicate", r, 200, 0)
	if fnum(asMap(t, "dup.word", r.body["word"])["wordId"]) != id || r.body["created"] != false {
		t.Errorf("duplicate = %s", r.raw)
	}
	expect(t, "empty word", op.do("POST", wordsURL, map[string]any{"word": "  "}), 400, 4000)

	// 搜索：按标准化后的子串。nextCursor 是字符串，没有更多时为空。
	r = op.do("GET", wordsURL+"?q=zxqword&limit=20", nil)
	expect(t, "search", r, 200, 0)
	keysWithin(t, "list", r.body, "words", "nextCursor")
	list := asList(t, "words", r.body["words"])
	if len(list) != 1 || fnum(asMap(t, "row", list[0])["wordId"]) != id || r.body["nextCursor"] != "" {
		t.Fatalf("search = %s", r.raw)
	}
	keysWithin(t, "list row", asMap(t, "row", list[0]), wordFields...)
	expect(t, "bad limit", op.do("GET", wordsURL+"?limit=7", nil), 400, 4000)
	expect(t, "bad state", op.do("GET", wordsURL+"?state=gone", nil), 400, 4000)

	// 停用。
	r = op.do("PATCH", fmt.Sprintf("%s/%d", wordsURL, id), map[string]any{"state": "disabled"})
	expect(t, "disable", r, 200, 0)
	keysWithin(t, "patch", r.body, "word")
	if asMap(t, "patch.word", r.body["word"])["state"] != "disabled" {
		t.Errorf("patch = %s", r.raw)
	}
	r = op.do("GET", wordsURL+"?state=disabled", nil)
	if l := asList(t, "disabled", r.body["words"]); len(l) != 1 {
		t.Errorf("disabled list = %s", r.raw)
	}
	expect(t, "bad patch", op.do("PATCH", fmt.Sprintf("%s/%d", wordsURL, id), map[string]any{"state": "x"}), 400, 4000)
	expect(t, "bad id", op.do("PATCH", wordsURL+"/abc", map[string]any{"state": "active"}), 400, 4000)

	// 导入：新增 1、重复 2（同一批里的和已有的）、无效 2（空行、65 个码点）。
	r = op.do("POST", wordsURL+"/import", map[string]any{"words": []string{word + "-2", "", word + "-2", strings.Repeat("字", 65), word}})
	expect(t, "import", r, 200, 0)
	keysWithin(t, "import", r.body, "added", "duplicate", "invalid")
	if fnum(r.body["added"]) != 1 || fnum(r.body["duplicate"]) != 2 || fnum(r.body["invalid"]) != 2 {
		t.Errorf("import = %s", r.raw)
	}
	imports := w.im.count("POST", "/admin/moderation/words/import")
	big := make([]string, 5001)
	for i := range big {
		big[i] = fmt.Sprintf("%s-%d", word, i)
	}
	expect(t, "import 5001", op.do("POST", wordsURL+"/import", map[string]any{"words": big}), 400, 4131)
	if w.im.count("POST", "/admin/moderation/words/import") != imports {
		t.Error("an oversized import reached im-server")
	}
	// 5000 条整批能过 console（请求体上限够用）；ZXQWORD-2 上面已经导入过。
	r = op.do("POST", wordsURL+"/import", map[string]any{"words": big[:5000]})
	expect(t, "import 5000", r, 200, 0)
	if fnum(r.body["added"]) != 4999 || fnum(r.body["duplicate"]) != 1 {
		t.Errorf("import 5000 = %s", r.raw)
	}

	// 删除；再删 404 / 4040 透传。
	expect(t, "delete", op.do("DELETE", fmt.Sprintf("%s/%d", wordsURL, id), nil), 200, 0)
	expect(t, "delete again", op.do("DELETE", fmt.Sprintf("%s/%d", wordsURL, id), nil), 404, 4040)

	// 审计：每个操作都有 intent 和 result；记 wordId 和数量。
	for _, a := range []string{"moderation.word.add", "moderation.word.update", "moderation.word.import", "moderation.word.delete"} {
		if len(w.auditRows(`action = $1 AND phase = 'intent'`, a)) == 0 || len(w.auditRows(`action = $1 AND phase = 'result' AND result = 'success'`, a)) == 0 {
			t.Errorf("no audit for %s", a)
		}
	}
	if rows := w.auditRows(`action = 'moderation.word.add' AND phase = 'result' AND result = 'success'`); len(rows) != 2 || !strings.Contains(fmt.Sprint(rows[0]["params"]), fmt.Sprintf(`"wordId":%d`, id)) {
		t.Errorf("add results = %v", rows)
	}
	if rows := w.auditRows(`action = 'moderation.word.import' AND phase = 'result' AND result = 'success'`); len(rows) == 0 ||
		!strings.Contains(fmt.Sprint(rows[0]["params"]), `"added":1`) || !strings.Contains(fmt.Sprint(rows[0]["params"]), `"invalid":2`) {
		t.Errorf("import results = %v", rows)
	}
	if rows := w.auditRows(`action = 'moderation.word.delete' AND phase = 'result'`); len(rows) != 2 || rows[1]["code"] != int32(4040) {
		t.Errorf("delete results = %v", rows)
	}

	// AC-MOD-01-6：console 全库、console 日志、im-server 审计都搜不到词（原文、全角、标准化后的小写）。
	needles := map[string]string{"word": word, "fullwidth": "ＺＸＱＷＯＲＤ", "norm": "zxqword"}
	noneContains(t, "console database", w.dumpDB(), needles)
	noneContains(t, "console logs", w.logs.String(), needles)
	noneContains(t, "im-server audit", w.imAuditDump(), needles)
}

// TC-MOD-02-14（AC-MOD-02-14 的 console 一侧）：经 console 加词后用户发送被拦（4510），审核员经 console 按用户查到命中次数和最近记录
// （没有任何内容，响应只有白名单字段），查询写审计 moderation.hits.view；运营（只有 moderation.words）403 / 4030、不调用 im-server（P-48 ③）。
// 重发去重、91 天清理在 im-server（TC-MOD-02-14，BE-494）。
func TestTC_MOD_02_14_HitsViaConsole(t *testing.T) {
	const word, text = "ZXQWORD", "hello ZXQWORD there"
	w := newModWorld(t, 150*time.Second)
	super := w.super("adm1")
	op := super.create("op1", "operator")
	mod := super.create("mod1", "moderator")
	p := uniq("hit")
	u1, u2 := p+"a", p+"b"
	w.users(u1, u2)
	g := w.group(u1, u2)
	r := op.do("POST", wordsURL, map[string]any{"word": word})
	expect(t, "add", r, 200, 0)
	wordID := fnum(asMap(t, "word", r.body["word"])["wordId"])

	c := w.dial(u1, "web")
	blocked := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) { // 规则 2：10 秒内生效
		f := c.send("group:"+g, text)
		if e, _ := f["error"].(map[string]any); e != nil && fnum(e["code"]) == 4510 {
			blocked = true
			break
		}
	}
	if !blocked {
		t.Fatal("the word added through console did not block within 10 seconds")
	}

	hitsURL := "/console/api/moderation/hits?userId=" + u1
	before := w.im.count("GET", "/admin/moderation/hits")
	expect(t, "operator hits", op.do("GET", hitsURL, nil), 403, 4030)
	if w.im.count("GET", "/admin/moderation/hits") != before {
		t.Error("denied hits query reached im-server")
	}
	w.im.mu.Lock()
	w.im.rewrite = func(path string, body []byte) []byte {
		if path != "/admin/moderation/hits" {
			return body
		}
		return injectFields(body, "recent", map[string]any{"text": "ZXQ-LEAK", "futureField": true})
	}
	w.im.mu.Unlock()
	r = mod.do("GET", hitsURL, nil)
	expect(t, "moderator hits", r, 200, 0)
	keysWithin(t, "hits", r.body, hitsFields...)
	if r.body["userId"] != u1 || fnum(r.body["days"]) != 90 || fnum(asMap(t, "counts", r.body["counts"])["text"]) < 1 {
		t.Errorf("hits = %s", r.raw)
	}
	recent := asList(t, "recent", r.body["recent"])
	if len(recent) == 0 {
		t.Fatalf("no recent hits: %s", r.raw)
	}
	h := asMap(t, "hit", recent[0])
	keysWithin(t, "hit", h, hitEntryFields...)
	if h["scene"] != "text" || fnum(h["wordId"]) != wordID || fnum(h["at"]) <= 0 {
		t.Errorf("hit = %v", h)
	}
	if strings.Contains(r.raw, "hello") || strings.Contains(r.raw, word) || strings.Contains(r.raw, "ZXQ-LEAK") {
		t.Errorf("content in hits: %s", r.raw)
	}
	// 没有命中的用户：空。
	r = mod.do("GET", "/console/api/moderation/hits?userId="+u2, nil)
	expect(t, "no hits", r, 200, 0)
	if len(asList(t, "recent", r.body["recent"])) != 0 || len(asMap(t, "counts", r.body["counts"])) != 0 {
		t.Errorf("u2 hits = %s", r.raw)
	}
	expect(t, "bad userId", mod.do("GET", "/console/api/moderation/hits?userId=a%20b", nil), 400, 4004)
	// 查询本身写审计，目标是 userId。
	rows := w.auditRows(`action = 'moderation.hits.view' AND phase = 'result' AND result = 'success'`)
	if len(rows) != 2 || !strings.Contains(fmt.Sprint(rows[0]["target"]), u1) {
		t.Errorf("hits audit = %v", rows)
	}
	noneContains(t, "console logs and database", w.logs.String()+w.dumpDB(), map[string]string{"text": text})
}
