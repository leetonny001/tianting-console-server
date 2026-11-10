package e2e

// TC-CHAT-90-29（AC-CHAT-90-5 的 C4 部分，console-server 一侧，BE-480）：E1 + 假 S3 + console-server。
// 消息正文、文件名、引用文字、@ 的正文都带特征串；经 console 走撤回相关的后台流程（元数据、普通正文、隔离正文、fetch、删除已撤回的），
// 然后 console 日志、im-server 日志、console 全库、im-server 审计都搜不到特征串，并用 deploy/ops/scan-logs 再扫一次。
// im-server 自己的那一半在 tianting-server 的 server/e2e/c4_markers_test.go。本地结果，CI 不运行。

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestTC_CHAT_90_29_ConsoleLogsAndAudit(t *testing.T) {
	w := newRecallWorld(t)
	super := w.super("adm1")
	mod := super.create("mod1", "moderator")
	kf := super.create("kf1", "support")
	p := uniq("zx")
	u1, u2 := p+"a", p+"b"
	w.users(u1, u2)
	g := uniq("zg")
	if err := w.sysDo("POST", "/admin/groups", map[string]any{"groupId": g, "name": "n", "members": []string{u1, u2}, "owner": u1}, nil); err != nil {
		t.Fatal(err)
	}
	conv := "group:" + g
	c := w.dial(u1, "web")
	target := msgIDOf(t, c.send(conv, "ZXQ-QUO-1 original"))
	msgIDOf(t, c.sendAttachment(conv, "text", map[string]any{"text": "ZXQ-QUO-2 reply ZXQ-MEN-1", "quote": map[string]any{"msgId": target}, "mentions": map[string]any{"userIds": []string{u2}}}))
	msgIDOf(t, c.sendAttachment(conv, "text", map[string]any{"text": "ZXQ-MEN-2 everyone", "mentions": map[string]any{"all": true}}))
	recalled := msgIDOf(t, c.send(conv, "ZXQ-RCL-1 secret"))
	c.recall(conv, recalled)
	fileID, imgMsg, photo, _ := w.recalledImage(c, u1, conv, "ZXQ-RCL-3-photo.png")
	c.recall(conv, target) // 被引用的消息也撤回

	// 元数据、普通正文、隔离正文（读到原文是对照）、fetch（拿到字节是对照）、删除已撤回的。
	expect(t, "meta", kf.do("POST", "/console/api/messages/meta/query", map[string]any{"convId": conv}), 200, 0)
	for _, quarantine := range []bool{false, true} {
		w.tick()
		expect(t, "grant", mod.do("POST", "/console/api/messages/grants", map[string]any{"convId": conv, "ticket": "T-29", "reason": "c4 scan", "otp": mod.otp(), "quarantine": quarantine}), 200, 0)
		r := mod.do("POST", "/console/api/messages/body", map[string]any{"convId": conv, "quarantine": quarantine})
		expect(t, "body", r, 200, 0)
		if quarantine && (!strings.Contains(r.raw, "ZXQ-RCL-1 secret") || !strings.Contains(r.raw, "ZXQ-QUO-1 original")) {
			t.Fatalf("control: the quarantine page should have the recalled text: %s", r.raw)
		}
	}
	if r := mod.do("POST", "/console/api/files/"+fileID+"/fetch", map[string]any{"convId": conv, "msgId": imgMsg}); r.status != 200 || r.raw != string(photo) {
		t.Fatalf("control: fetch the recalled image: %d", r.status)
	}
	// 审计写失败的错误路径（console 会记日志，日志扫描才有内容）。
	w.a.SetAuditFault("fail")
	expect(t, "audit down", mod.do("POST", "/console/api/files/"+fileID+"/fetch", map[string]any{"convId": conv, "msgId": imgMsg}), 503, 5031)
	w.a.SetAuditFault("ok")
	mod.stepUp()
	expect(t, "delete recalled", mod.do("POST", "/console/api/messages/delete", map[string]any{"convId": conv, "msgIds": []string{recalled}, "reason": "c4 scan"}), 200, 0)

	logs, imLogs := w.logs.String(), w.proc.logs.String()
	if logs == "" || imLogs == "" {
		t.Fatal("logs were not captured: the scan would prove nothing")
	}
	dump, imAudit := w.dumpDB(), w.imAuditDump()
	for _, id := range []string{fileID, imgMsg, recalled} {
		if !strings.Contains(imAudit, id) {
			t.Errorf("control: im-server audit has no %s", id)
		}
	}
	if !strings.Contains(dump, fileID) {
		t.Error("control: console audit has no fileId for the fetch")
	}
	markers := map[string]string{"recall": "ZXQ-RCL", "quote": "ZXQ-QUO", "mention": "ZXQ-MEN"}
	for label, data := range map[string]string{"console log": logs, "im-server log": imLogs, "console database": dump, "im-server audit": imAudit} {
		noneContains(t, label, data, markers)
	}

	src := os.Getenv("TIANTING_SERVER_DIR")
	if src == "" {
		src = "../../im-mvp/server"
	}
	scanner := filepath.Join(src, "..", "deploy", "ops", "scan-logs")
	if _, err := os.Stat(scanner); err != nil {
		t.Fatalf("scan-logs not available: %v", err) // TC-CHAT-90-29 指定这个工具
	}
	dir := t.TempDir()
	files := []string{filepath.Join(dir, "console.log"), filepath.Join(dir, "im.log"), filepath.Join(dir, "console-db.txt"), filepath.Join(dir, "im-audit.txt")}
	for i, data := range []string{logs, imLogs, dump, imAudit} {
		if err := os.WriteFile(files[i], []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"-I", scanner, "--marker=ZXQ-RCL", "--marker=ZXQ-QUO", "--marker=ZXQ-MEN"}
	if out, err := exec.Command("python3", append(args, files...)...).CombinedOutput(); err != nil {
		t.Errorf("scan-logs: %v: %s", err, out)
	}
	hit := filepath.Join(dir, "hit.log")
	if err := os.WriteFile(hit, []byte("x ZXQ-RCL-1 y\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("python3", append(args, hit)...).Run(); err == nil {
		t.Error("control: scan-logs found nothing in a file that has the marker")
	}
}
