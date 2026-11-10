package e2e

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

// adminUserRowFields 是后台页面实际读的用户详情字段：tianting-admin src/api/types.ts 的 UserRow
// （UserDetail 页、Moderation 的 MutedBadge、AccountPanel）。accountUnavailable 只在账号信息取不到时出现（TC-ACC-09 那条用例另测）。
var adminUserRowFields = []string{"account", "avatar", "ban", "createdAt", "mutedUntil", "nickname", "official", "online", "userId"}

// adminUserBanFields 是 UserRow.ban 的字段。
var adminUserBanFields = []string{"at", "by", "reason", "until"}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// console-chat 问题 20（CS-205 发现）：用户详情按白名单输出，和元数据、正文、会话列表一样不透传 im-server 多出来的字段。
//  1. 页面用到的字段一个不少：有昵称、头像、封禁、永久禁言的用户，键集合正好是 UserRow 的字段，ban 正好是 UserRow.ban 的字段；
//     mutedUntil 是 null 也要有这个键（没有键 = 没有禁言）；没有封禁、禁言的用户 ban 是 null、没有 mutedUntil。
//  2. im-server 多返回的字段（会话设置 convSettings 里的置顶、免打扰，未知字段，ban 里的未知字段）出不去。
//
// 白名单漏掉页面在用的字段、或者改回原样透传，这里都失败。
func TestUserDetailWhitelist(t *testing.T) {
	b := newBizWorld(t)
	super := b.super("adm1")
	mod := super.create("mod1", "moderator")
	kf := super.create("kf1", "support")
	u, plain := uniq("ud"), uniq("up")
	if err := b.sysDo("POST", "/admin/users/import", map[string]any{"users": []any{
		map[string]any{"userId": u, "nickname": "小明", "avatar": "https://cdn.example.com/a/" + u + ".png"},
		map[string]any{"userId": plain},
	}}, nil); err != nil {
		t.Fatal(err)
	}
	mod.stepUp()
	expect(t, "ban", mod.do("POST", "/console/api/users/"+u+"/ban", map[string]any{"duration": "1d", "reason": "spam spam"}), 200, 0)
	expect(t, "mute", kf.do("POST", "/console/api/mutes", map[string]any{"scope": "user", "userId": u, "duration": "permanent", "reason": "spam spam"}), 200, 0)

	check := func(label string, r reply) {
		t.Helper()
		expect(t, label, r, 200, 0)
		if got := sortedKeys(r.body); !slices.Equal(got, adminUserRowFields) {
			t.Errorf("%s fields = %v, want %v: %s", label, got, adminUserRowFields, r.raw)
		}
		ban, _ := r.body["ban"].(map[string]any)
		if got := sortedKeys(ban); !slices.Equal(got, adminUserBanFields) {
			t.Errorf("%s ban fields = %v, want %v: %s", label, got, adminUserBanFields, r.raw)
		}
		if ban["reason"] != "spam spam" || ban["by"] == "" || ban["at"] == nil || ban["until"] == nil {
			t.Errorf("%s ban = %v", label, ban)
		}
		if mu, has := r.body["mutedUntil"]; !has || mu != nil {
			t.Errorf("%s permanent mute = %v (present %v)", label, mu, has)
		}
		if r.body["userId"] != u || r.body["nickname"] != "小明" || r.body["avatar"] != "https://cdn.example.com/a/"+u+".png" ||
			r.body["official"] != false || r.body["online"] != false || r.body["createdAt"] == nil || r.body["account"] == nil {
			t.Errorf("%s profile = %s", label, r.raw)
		}
	}

	// 1. 页面用到的字段。
	check("banned and muted", kf.do("GET", "/console/api/users/"+u, nil))
	p := kf.do("GET", "/console/api/users/"+plain, nil)
	expect(t, "plain", p, 200, 0)
	if want := []string{"account", "ban", "createdAt", "official", "online", "userId"}; !slices.Equal(sortedKeys(p.body), want) {
		t.Errorf("plain fields = %v, want %v: %s", sortedKeys(p.body), want, p.raw)
	}
	if ban, has := p.body["ban"]; !has || ban != nil {
		t.Errorf("plain ban = %v (present %v)", ban, has)
	}

	// 2. im-server 多返回的字段出不去。
	var rewritten atomic.Int32
	var banInjected atomic.Bool
	b.im.mu.Lock()
	b.im.rewrite = func(path string, body []byte) []byte {
		if path != "/admin/users/"+u {
			return body
		}
		rewritten.Add(1)
		body = bytes.Replace(body, []byte(`{`), []byte(`{"convSettings":[{"convId":"group:g1","pinned":true,"notifyOff":true,"clearedSeq":10}],"zxqUnknown":"ZXQ-UD-1",`), 1)
		body = bytes.Replace(body, []byte(`"ban":{`), []byte(`"ban":{"zxqBanExtra":"ZXQ-UD-2",`), 1)
		if bytes.Contains(body, []byte("ZXQ-UD-2")) {
			banInjected.Store(true)
		}
		return body
	}
	b.im.mu.Unlock()
	defer func() {
		b.im.mu.Lock()
		b.im.rewrite = nil
		b.im.mu.Unlock()
	}()
	leak := kf.do("GET", "/console/api/users/"+u, nil)
	if rewritten.Load() != 1 || !banInjected.Load() {
		t.Fatalf("im-server response was not rewritten (%d)", rewritten.Load())
	}
	for _, bad := range []string{"ZXQ", "convSettings", "zxq", `"pinned"`, `"notifyOff"`, `"clearedSeq"`} {
		if strings.Contains(leak.raw, bad) {
			t.Errorf("extra field %q forwarded: %s", bad, leak.raw)
		}
	}
	check("with extra fields", leak)
	var asJSON map[string]json.RawMessage
	if err := json.Unmarshal([]byte(leak.raw), &asJSON); err != nil {
		t.Fatalf("detail is not a JSON object: %s", leak.raw)
	}
}
