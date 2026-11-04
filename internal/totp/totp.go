// Package totp 是 RFC 6238 动态码：SHA-1、6 位、30 秒步长（PRD-admin F-CON-03 规则 3）。
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6238 和认证器 App 的默认算法，是 HMAC-SHA1，不是用 SHA-1 做摘要
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"
)

// Period 是步长。
const Period = 30

var enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret 生成 160 位密钥（RFC 4226 推荐长度）。
func NewSecret() ([]byte, error) {
	b := make([]byte, 20)
	_, err := rand.Read(b)
	return b, err
}

// Encode 把密钥编码成认证器 App 用的 Base32。
func Encode(secret []byte) string { return enc.EncodeToString(secret) }

// Step 返回时间对应的步长。
func Step(t time.Time) int64 { return t.Unix() / Period }

// Code 返回某个步长的动态码。
func Code(secret []byte, step int64) string { return code(secret, step, 6) }

func code(secret []byte, step int64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) // #nosec G115 -- 步长为正
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, v%mod)
}

// Match 在当前步长前后各 1 个步长内找匹配的码，返回匹配的步长（AC-CON-03-5）。防重放由调用方用 last_step 判断。
// 从旧到新比较，且总是比较完三个，不因命中提前返回。
func Match(secret []byte, input string, now time.Time) (step int64, ok bool) {
	cur := Step(now)
	for s := cur - 1; s <= cur+1; s++ {
		if subtle.ConstantTimeCompare([]byte(Code(secret, s)), []byte(input)) == 1 && !ok {
			step, ok = s, true
		}
	}
	return step, ok
}

// URI 返回认证器 App 扫码用的 otpauth 地址。
func URI(issuer, account string, secret []byte) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{"secret": {Encode(secret)}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + label + "?" + q.Encode()
}
