package audit

import "testing"

// 固定向量：规则变了这里会失败（docs/audit-hash.md）。已写入的记录要能被校验命令重算。
func TestHashVector(t *testing.T) {
	in := HashInput{
		Seq: 1, ID: "018f0000-0000-7000-8000-000000000001", TS: 1800000000000, Space: "admin", Phase: "event", RequestID: "r1",
		AccountID: "a1", Username: "kf<1>", Roles: `["support"]`, IP: "10.0.0.1", UA: "ua", Action: "auth.login",
		Target: `{"count":1,"ids":["u1"],"type":"user"}`, Params: `{"k":"中文 & <x>"}`, Result: "success",
	}
	got, err := ComputeHash(in)
	if err != nil {
		t.Fatal(err)
	}
	const want = "be7a25a8b31317e2c4313ebe1d9d01441f7f052f24aaabb23a3843a7772a307f"
	if got != want {
		t.Fatalf("hash = %s", got)
	}
	in.PrevHash = got
	second, err := ComputeHash(in)
	if err != nil || second == got {
		t.Errorf("prevHash must change the hash: %s %v", second, err)
	}
	in.PrevHash, in.Reason = "", "changed"
	if h, _ := ComputeHash(in); h == got {
		t.Error("changing a field must change the hash")
	}
}

func TestCanonical(t *testing.T) {
	got, err := Canonical(map[string]any{"b": 1, "a": "<&>", "c": []string{"x"}})
	if err != nil || got != `{"a":"<&>","b":1,"c":["x"]}` {
		t.Errorf("%s %v", got, err)
	}
}

func TestNewTargetTruncates(t *testing.T) {
	var many []string
	for range 60 {
		many = append(many, "u")
	}
	tg := NewTarget("user", many...)
	if tg.Count != 60 || len(tg.IDs) != 50 {
		t.Errorf("%d %d", tg.Count, len(tg.IDs))
	}
}
