package space

import (
	"strings"
	"testing"
)

// AC-CON-10-3：基线 CSP 和 PRD 规则 4 逐字一致。
func TestBaselineCSP(t *testing.T) {
	want := "default-src 'self'; script-src 'self'; style-src 'self' 'nonce-abc'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
	if got := (Policy{}).CSP("abc"); got != want {
		t.Errorf("csp = %s", got)
	}
}

// 空间只能收紧：运维策略的每条指令都不比基线宽。
func TestOpsPolicyIsStricter(t *testing.T) {
	_, p, err := Defaults(Ops)
	if err != nil {
		t.Fatal(err)
	}
	base := directives(Policy{}.CSP("n"))
	ops := directives(p.CSP("n"))
	if len(base) != len(ops) {
		t.Fatalf("directive sets differ: %v vs %v", base, ops)
	}
	for name, values := range ops {
		for _, v := range values {
			if !contains(base[name], v) {
				t.Errorf("ops %s adds %s", name, v)
			}
		}
	}
	if contains(ops["img-src"], "data:") || len(ops["style-src"]) != 1 || !p.FrameDeny {
		t.Errorf("ops = %v", ops)
	}
	for _, csp := range []string{Policy{}.CSP("n"), p.CSP("n")} {
		if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
			t.Errorf("unsafe source in %s", csp)
		}
	}
}

func TestNonceIsRandom(t *testing.T) {
	if NewNonce() == NewNonce() {
		t.Error("nonce repeats")
	}
	if _, _, err := Defaults("nope"); err == nil {
		t.Error("unknown space accepted")
	}
}

func directives(csp string) map[string][]string {
	out := map[string][]string{}
	for _, d := range strings.Split(csp, "; ") {
		f := strings.Fields(d)
		out[f[0]] = f[1:]
	}
	return out
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
