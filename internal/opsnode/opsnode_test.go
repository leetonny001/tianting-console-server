package opsnode

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tianting/console/internal/imclient"
)

// 和 im-server 用同一组向量（protocol/vectors/ops-sign.json，由 scripts/sync-protocol.sh 同步）。
func TestOpsSignVectors(t *testing.T) {
	raw, err := os.ReadFile("../../protocol/vectors/ops-sign.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Vectors []struct {
			Method, Path, Timestamp, Nonce, Body, Operator, RequestID, TargetNode, StringToSign string
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range f.Vectors {
		got := imclient.StringToSign(imclient.Request{Method: v.Method, Path: v.Path, Timestamp: v.Timestamp, Nonce: v.Nonce, Body: []byte(v.Body), Operator: v.Operator, RequestID: v.RequestID, TargetNode: v.TargetNode})
		if got != v.StringToSign {
			t.Errorf("%s:\n got %q\nwant %q", v.Path, got, v.StringToSign)
		}
	}
}

func TestLoadTableListsAllProblems(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "k")
	marker := strings.Repeat("s", 32)
	if err := os.WriteFile(key, []byte(base64.StdEncoding.EncodeToString([]byte(marker))), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad")
	if err := os.WriteFile(bad, []byte("not-base64!"), 0o600); err != nil {
		t.Fatal(err)
	}
	table := filepath.Join(dir, "t.json")
	body, _ := json.Marshal([]map[string]string{
		{"nodeId": "n1", "addr": "10.0.0.1:9091", "keyFile": key},                                     // 没有服务名
		{"nodeId": "n2", "addr": "10.0.0.2:9091", "tlsServerName": "n2.ops.internal", "keyFile": bad}, // 私钥格式错
		{"nodeId": "n3", "tlsServerName": "n3.ops.internal", "keyFile": key},                          // 没有地址
		{"nodeId": "n4", "addr": "127.0.0.1:9091", "keyFile": key},                                    // 回环可以不用 TLS（非生产）
		{"nodeId": "n1", "addr": "10.0.0.5:9091", "tlsServerName": "x", "keyFile": key},               // 重复
	})
	if err := os.WriteFile(table, body, 0o600); err != nil {
		t.Fatal(err)
	}
	_, problems := LoadTable(table, false)
	joined := strings.Join(problems, "\n")
	for _, want := range []string{"n1 has no tlsServerName", "n2: keyFile is not base64", "n3 has no addr", "n1 appears twice"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "n4") {
		t.Errorf("loopback without TLS is fine outside production:\n%s", joined)
	}
	if strings.Contains(joined, marker) {
		t.Error("key in problems")
	}
	_, problems = LoadTable(table, true)
	if !strings.Contains(strings.Join(problems, "\n"), "n4 has no tlsServerName") {
		t.Errorf("production must require TLS: %v", problems)
	}
	// 打印不出私钥。
	list, _ := LoadTable(table, false)
	if s := strings.Join([]string{list[0].Key.String()}, ""); strings.Contains(s, marker) {
		t.Error("key printed")
	}
}
