package secret

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var fast = ArgonParams{MemoryKiB: 1024, Time: 1, Threads: 1}

func key(b byte) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string(rune(b)), 32)))
}

func TestKeyringRoundTripAndBinding(t *testing.T) {
	k, err := ParseKeyring("k1:"+key('a')+",k2:"+key('b'), "k2")
	if err != nil || len(k.Problems()) != 0 {
		t.Fatalf("%v %v", err, k.Problems())
	}
	kid, nonce, ct, err := k.Encrypt("a7", []byte("JBSWY3DPEHPK3PXP"))
	if err != nil || kid != "k2" {
		t.Fatal(kid, err)
	}
	if strings.Contains(string(ct), "JBSWY3") {
		t.Error("ciphertext contains the seed")
	}
	if got, err := k.Decrypt("a7", kid, nonce, ct); err != nil || string(got) != "JBSWY3DPEHPK3PXP" {
		t.Errorf("%s %v", got, err)
	}
	if _, err := k.Decrypt("a8", kid, nonce, ct); err == nil {
		t.Error("ciphertext moved to another account decrypts")
	}
	if _, err := k.Decrypt("a7", "gone", nonce, ct); err == nil || !strings.Contains(err.Error(), "gone") {
		t.Errorf("missing kid: %v", err)
	}
}

func TestKeyringProblems(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	k, err := ParseKeyring("k1:"+short, "")
	if err != nil {
		t.Fatal(err)
	}
	if p := k.Problems(); len(p) != 1 || !strings.Contains(p[0], "k1") || strings.Contains(p[0], short) {
		t.Errorf("short key = %v", p)
	}
	k, _ = ParseKeyring("k1:"+key('a'), "k9")
	if p := k.Problems(); len(p) != 1 || !strings.Contains(p[0], "ACTIVE") {
		t.Errorf("bad active = %v", p)
	}
	if p := (Keyring{}).Problems(); len(p) != 1 {
		t.Errorf("empty = %v", p)
	}
	if _, err := ParseKeyring("nokid", ""); err == nil || strings.Contains(err.Error(), "nokid") {
		t.Errorf("malformed entry leaks: %v", err)
	}
}

// 密钥不进日志和响应（CS-003 内容 2）。
func TestBytesAreRedacted(t *testing.T) {
	s := struct {
		K Bytes
		M map[string]Bytes
	}{Bytes("TOP-SECRET-VALUE"), map[string]Bytes{"k1": Bytes("TOP-SECRET-VALUE")}}
	j, _ := json.Marshal(s)
	for _, out := range []string{fmt.Sprintf("%v", s), fmt.Sprintf("%+v", s), fmt.Sprintf("%#v", s), fmt.Sprint(s.K), string(j)} {
		if strings.Contains(out, "TOP-SECRET") {
			t.Errorf("leak: %s", out)
		}
	}
}

// AC-CON-04-2：相同密码的哈希以 $argon2id$ 开头且不同。默认参数写在规格里。
func TestPasswordHash(t *testing.T) {
	h, ctx := NewHasher(fast), context.Background()
	a, err := h.Hash(ctx, "same-password")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := h.Hash(ctx, "same-password")
	if !strings.HasPrefix(a, "$argon2id$") || a == b {
		t.Errorf("a=%s b=%s", a, b)
	}
	if ok, err := h.Verify(ctx, a, "same-password"); !ok || err != nil {
		t.Errorf("verify: %v %v", ok, err)
	}
	if ok, err := h.Verify(ctx, a, "wrong"); ok || err != nil {
		t.Errorf("wrong password: %v %v", ok, err)
	}
	if _, err := h.Verify(ctx, "plain", "x"); err == nil {
		t.Error("bad encoding accepted")
	}
	if DefaultArgon != (ArgonParams{MemoryKiB: 64 * 1024, Time: 3, Threads: 1}) {
		t.Errorf("default params = %+v", DefaultArgon)
	}
	// 参数取自哈希：改了默认参数，旧密码还能验证。
	other := NewHasher(ArgonParams{MemoryKiB: 2048, Time: 2, Threads: 1})
	if ok, err := other.Verify(ctx, a, "same-password"); !ok || err != nil {
		t.Errorf("params from hash: %v %v", ok, err)
	}
}

// AC-CON-11-4（并发部分）：同时进行的计算不超过 4 个，排队超时 ErrBusy。
func TestHasherLimitsConcurrency(t *testing.T) {
	h := NewHasher(ArgonParams{MemoryKiB: 8 * 1024, Time: 2, Threads: 1})
	var peak atomic.Int32
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				if n := int32(len(h.sem)); n > peak.Load() {
					peak.Store(n)
				}
			}
		}
	}()
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := h.Hash(context.Background(), "p"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	close(stop)
	if p := peak.Load(); p > 4 || p == 0 {
		t.Errorf("peak = %d", p)
	}

	// 全部占满：下一个 ErrBusy。
	busy := NewHasher(fast)
	busy.Timeout = 50 * time.Millisecond
	for range 4 {
		busy.sem <- struct{}{}
	}
	if _, err := busy.Hash(context.Background(), "p"); !errors.Is(err, ErrBusy) {
		t.Errorf("err = %v", err)
	}
	if _, err := busy.Verify(context.Background(), "$argon2id$v=19$m=1024,t=1,p=1$AAAA$AAAA", "p"); !errors.Is(err, ErrBusy) {
		t.Errorf("verify err = %v", err)
	}
}

func TestPepperAndSessionHash(t *testing.T) {
	if PepperHash([]byte("p1"), "code") == PepperHash([]byte("p2"), "code") {
		t.Error("pepper has no effect")
	}
	if SessionHash("a") == SessionHash("b") || len(SessionHash("a")) != 64 {
		t.Error("session hash")
	}
}
