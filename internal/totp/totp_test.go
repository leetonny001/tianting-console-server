package totp

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 附录 B 的 SHA-1 向量（8 位，取后 6 位就是 6 位的结果）。
func TestRFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for unix, want := range map[int64]string{
		59: "94287082", 1111111109: "07081804", 1111111111: "14050471", 1234567890: "89005924", 2000000000: "69279037", 20000000000: "65353130",
	} {
		step := Step(time.Unix(unix, 0))
		if got := code(secret, step, 8); got != want {
			t.Errorf("%d: %s, want %s", unix, got, want)
		}
		if got := Code(secret, step); got != want[2:] {
			t.Errorf("%d: 6 digits %s, want %s", unix, got, want[2:])
		}
	}
}

func TestMatchWindow(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(1234567890, 0)
	cur := Step(now)
	for d, want := range map[int64]bool{-2: false, -1: true, 0: true, 1: true, 2: false} {
		step, ok := Match(secret, Code(secret, cur+d), now)
		if ok != want || (ok && step != cur+d) {
			t.Errorf("offset %d: step=%d ok=%v", d, step, ok)
		}
	}
	if _, ok := Match(secret, "", now); ok {
		t.Error("empty code")
	}
}

func TestURI(t *testing.T) {
	u := URI("Tianting admin", "kf1", []byte("12345678901234567890"))
	if !strings.HasPrefix(u, "otpauth://totp/Tianting%20admin:kf1?") || !strings.Contains(u, "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ") {
		t.Error(u)
	}
	s, err := NewSecret()
	if err != nil || len(s) != 20 {
		t.Errorf("%d %v", len(s), err)
	}
}
