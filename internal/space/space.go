// Package space 定义账号空间（PRD-admin F-CON-01）：一个二进制、每个空间一个监听地址，会话只在自己的空间有效。
// 运维空间（PRD-ops）注册时只能收紧响应头策略：Policy 的字段全部是"去掉什么"，结构上放宽不了。
package space

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/netip"
	"strings"
)

// 空间名。
const (
	Admin = "admin"
	Ops   = "ops"
)

// Policy 是空间在基线 CSP 上的收紧项（PRD-admin F-CON-10 规则 4）。
type Policy struct {
	NoDataImages bool // img-src 去掉 data:
	NoStyleNonce bool // style-src 去掉 nonce
	FrameDeny    bool // 加 X-Frame-Options: DENY
}

// Space 是一个账号空间的部署配置。
type Space struct {
	Name         string
	Addr         string
	Origin       string
	AllowedCIDRs []netip.Prefix
	WebDir       string // 前端构建产物目录；为空时不托管静态资源
	CookieName   string
	Policy       Policy
}

// Defaults 是两个空间内置的 Cookie 名和策略。
func Defaults(name string) (cookie string, p Policy, err error) {
	switch name {
	case Admin:
		return "__Host-admin_sid", Policy{}, nil
	case Ops: // PRD-ops F-OPS-03 规则 4
		return "__Host-ops_sid", Policy{NoDataImages: true, NoStyleNonce: true, FrameDeny: true}, nil
	}
	return "", Policy{}, fmt.Errorf("unknown space %q", name)
}

// NewNonce 生成每次响应一个的 CSP nonce。
func NewNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand 失败时不能继续发出可预测的 nonce
	}
	return base64.RawStdEncoding.EncodeToString(b)
}

// CSP 生成响应头。script-src 永远不含 unsafe-inline。
func (p Policy) CSP(nonce string) string {
	style := "style-src 'self' 'nonce-" + nonce + "'"
	if p.NoStyleNonce {
		style = "style-src 'self'"
	}
	img := "img-src 'self' data:"
	if p.NoDataImages {
		img = "img-src 'self'"
	}
	return strings.Join([]string{
		"default-src 'self'", "script-src 'self'", style, img, "connect-src 'self'",
		"object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'", "form-action 'self'",
	}, "; ")
}
