// Package ids 生成 UUIDv7（时间有序，RFC 9562）。
package ids

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"time"
)

// New 返回 now 对应的 UUIDv7。
func New(now time.Time) string {
	var b [16]byte
	if _, err := rand.Read(b[6:]); err != nil {
		panic(err) // crypto/rand 失败时不能继续发出可预测的 ID
	}
	var ms [8]byte
	binary.BigEndian.PutUint64(ms[:], uint64(now.UnixMilli())) // #nosec G115 -- 时间戳为正
	copy(b[:6], ms[2:])
	b[6] = b[6]&0x0f | 0x70
	b[8] = b[8]&0x3f | 0x80
	s := hex.EncodeToString(b[:])
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}
