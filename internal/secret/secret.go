// Package secret 是密钥材料（PRD-admin F-CON-11）：数据加密、带 pepper 的哈希、密码哈希。
package secret

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime/debug"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// Bytes 是不会被打印出来的密钥：%v、%+v、%#v、JSON 都只输出占位符。
type Bytes []byte

const redacted = "[redacted]"

func (Bytes) String() string               { return redacted }
func (Bytes) GoString() string             { return redacted }
func (Bytes) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
func (Bytes) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// MinDataKeyLen 是数据密钥的最小长度。
const MinDataKeyLen = 32

// Keyring 是 CON_DATA_KEYS：kid → 密钥。
type Keyring struct {
	Active string
	Keys   map[string]Bytes
}

// ParseKeyring 解析 "k1:base64,k2:base64"。错误信息只报 kid，不带值。
func ParseKeyring(raw, active string) (Keyring, error) {
	k := Keyring{Active: active, Keys: map[string]Bytes{}}
	if raw == "" {
		return k, nil
	}
	for i, item := range strings.Split(raw, ",") {
		id, b64, ok := strings.Cut(strings.TrimSpace(item), ":")
		if !ok || id == "" {
			return Keyring{}, fmt.Errorf("entry #%d must be kid:base64", i+1)
		}
		key, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return Keyring{}, fmt.Errorf("key %s is not valid base64", id)
		}
		if _, dup := k.Keys[id]; dup {
			return Keyring{}, fmt.Errorf("key %s appears twice", id)
		}
		k.Keys[id] = key
	}
	if len(k.Keys) == 1 && k.Active == "" {
		for id := range k.Keys {
			k.Active = id
		}
	}
	return k, nil
}

// Problems 检查密钥强度。
func (k Keyring) Problems() []string {
	var out []string
	if len(k.Keys) == 0 {
		return []string{"CON_DATA_KEYS is required"}
	}
	if _, ok := k.Keys[k.Active]; !ok {
		out = append(out, "CON_DATA_ACTIVE_KID must name a key in CON_DATA_KEYS")
	}
	for id, key := range k.Keys {
		if len(key) < MinDataKeyLen {
			out = append(out, fmt.Sprintf("CON_DATA_KEYS[%s] must be at least %d bytes", id, MinDataKeyLen))
		}
	}
	return out
}

func gcm(key []byte) (cipher.AEAD, error) {
	sum := sha256.Sum256(key) // 密钥可以比 32 字节长；统一派生成 AES-256 的长度
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// aad 把账号 ID 绑进密文：把一个账号的密文复制给另一个账号时解不开。
func aad(accountID string) []byte { return []byte(accountID) }

// Encrypt 用当前密钥加密。
func (k Keyring) Encrypt(accountID string, plain []byte) (kid string, nonce, ciphertext []byte, err error) {
	key, ok := k.Keys[k.Active]
	if !ok {
		return "", nil, nil, errors.New("no active data key")
	}
	a, err := gcm(key)
	if err != nil {
		return "", nil, nil, err
	}
	nonce = make([]byte, a.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", nil, nil, err
	}
	return k.Active, nonce, a.Seal(nil, nonce, plain, aad(accountID)), nil
}

// Decrypt 解密。
func (k Keyring) Decrypt(accountID string, kid string, nonce, ciphertext []byte) ([]byte, error) {
	key, ok := k.Keys[kid]
	if !ok {
		return nil, fmt.Errorf("data key %s is not configured", kid)
	}
	a, err := gcm(key)
	if err != nil {
		return nil, err
	}
	return a.Open(nil, nonce, ciphertext, aad(accountID))
}

// PepperHash 是恢复码、激活码的哈希：HMAC-SHA256(pepper, code)。库被拖走也没法离线猜。
func PepperHash(pepper []byte, code string) string {
	m := hmac.New(sha256.New, pepper)
	m.Write([]byte(code))
	return hex.EncodeToString(m.Sum(nil))
}

// SessionHash 是会话 ID 的哈希：会话 ID 本身是高熵随机数，不需要 pepper。
func SessionHash(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

// ArgonParams 是 Argon2id 参数。
type ArgonParams struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
}

// DefaultArgon 是 PRD 的默认值：m=64MiB, t=3, p=1。
var DefaultArgon = ArgonParams{MemoryKiB: 64 * 1024, Time: 3, Threads: 1}

// ErrBusy 表示排队超时：调用方返回 503 / 5030（AC-CON-11-4）。
var ErrBusy = errors.New("password hashing is busy")

// Hasher 限制同时进行的 Argon2id：每个 64MiB，不限制的话 50 个并发登录就能把内存打爆。
type Hasher struct {
	Params  ArgonParams
	Timeout time.Duration
	sem     chan struct{}
}

// NewHasher 创建哈希器：同时最多 4 个，排队超过 2 秒返回 ErrBusy。
func NewHasher(p ArgonParams) *Hasher {
	return &Hasher{Params: p, Timeout: 2 * time.Second, sem: make(chan struct{}, 4)}
}

func (h *Hasher) acquire(ctx context.Context) error {
	t := time.NewTimer(h.Timeout)
	defer t.Stop()
	select {
	case h.sem <- struct{}{}:
		return nil
	case <-t.C:
		return ErrBusy
	case <-ctx.Done():
		return ctx.Err()
	}
}

// release 立刻把 Argon2id 的工作内存还给操作系统。每次计算分配 64MiB，交给 GC 的节奏回收时，
// 50 个并发登录的 RSS 增量能到 450MB（AC-CON-11-4 要求 ≤ 300MB）。登录是低频操作，多一次 GC 的成本可以接受。
func release() { debug.FreeOSMemory() }

// Hash 返回 PHC 格式的哈希：$argon2id$v=19$m=...,t=...,p=...$salt$hash。
func (h *Hasher) Hash(ctx context.Context, password string) (string, error) {
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer func() { <-h.sem }()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	p := h.Params
	sum := argon2.IDKey([]byte(password), salt, p.Time, p.MemoryKiB, p.Threads, 32)
	release()
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.MemoryKiB, p.Time, p.Threads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(sum)), nil
}

// Verify 校验密码。参数取自哈希本身：改默认参数之后旧密码还能验证。
func (h *Hasher) Verify(ctx context.Context, encoded, password string) (bool, error) {
	var v int
	var p ArgonParams
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("not an argon2id hash")
	}
	if _, err := fmt.Sscanf(parts[2], "v=%d", &v); err != nil || v != argon2.Version {
		return false, errors.New("unsupported argon2 version")
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.MemoryKiB, &p.Time, &p.Threads); err != nil {
		return false, errors.New("bad argon2 parameters")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, errors.New("bad argon2 salt")
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false, errors.New("bad argon2 hash")
	}
	if err := h.acquire(ctx); err != nil {
		return false, err
	}
	defer func() { <-h.sem }()
	got := argon2.IDKey([]byte(password), salt, p.Time, p.MemoryKiB, p.Threads, uint32(len(want))) // #nosec G115 -- 长度来自自己写入的 32 字节哈希
	release()
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
