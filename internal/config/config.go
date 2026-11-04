// Package config 读取 console-server 配置（PRD-admin F-CON-01）。
//
// 静态检查一次列出全部问题；连数据库才能确认的检查（运行账号、审计探针）在 app.StartupProblems 里，和这里的结果合并后一起报告。
package config

import (
	"cmp"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"tianting/console/internal/secret"
	"tianting/console/internal/space"
)

// 运行环境。
const (
	EnvDevelopment = "development"
	EnvProduction  = "production"
)

// Config 是全部配置。密钥都是 secret.Bytes，打印不出来。
type Config struct {
	Env            string
	Spaces         []space.Space
	TrustedProxies []netip.Prefix
	TestMode       bool
	TicketPattern  *regexp.Regexp
	DatabaseURL    Redacted // 运行账号 console_app
	OwnerURL       Redacted // 迁移账号 console_owner，只给 migrate 用
	MetricsAddr    string
	TLSCert        string
	TLSKey         string

	DataKeys     secret.Keyring
	HashPepper   secret.Bytes
	IMAdminURL   string
	IMCaller     string
	IMSigningKey secret.Bytes // Ed25519 私钥（64 字节）
	IMMsgReadKey secret.Bytes
	IMTimeout    time.Duration
	AuditAnchor  string
}

// Redacted 是不会被打印的字符串（数据库连接串里有密码）。
type Redacted string

func (Redacted) String() string               { return "[redacted]" }
func (Redacted) GoString() string             { return "[redacted]" }
func (Redacted) MarshalText() ([]byte, error) { return []byte("[redacted]"), nil }

// Production 判断是否生产环境。
func (c Config) Production() bool { return c.Env == EnvProduction }

// Space 按名字找空间。
func (c Config) Space(name string) (space.Space, bool) {
	i := slices.IndexFunc(c.Spaces, func(s space.Space) bool { return s.Name == name })
	if i < 0 {
		return space.Space{}, false
	}
	return c.Spaces[i], true
}

const defaultTicketPattern = `^[A-Za-z0-9_-]{3,32}$`

// Load 读取配置，problems 是全部问题（格式错误 + 生产启动保护的静态部分）。
func Load(getenv func(string) string) (cfg Config, problems []string) {
	bad := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	cfg.Env = cmp.Or(getenv("CON_ENV"), EnvDevelopment)
	if cfg.Env != EnvDevelopment && cfg.Env != EnvProduction {
		bad("CON_ENV must be %q or %q", EnvDevelopment, EnvProduction)
	}
	prod := cfg.Env == EnvProduction
	switch getenv("CON_TEST_MODE") {
	case "", "0", "false":
	case "1", "true":
		cfg.TestMode = true
	default:
		bad("CON_TEST_MODE must be 1 or 0")
	}
	if prod && cfg.TestMode {
		bad("CON_TEST_MODE must not be enabled in production")
	}

	cfg.TrustedProxies = parseCIDRs(getenv("CON_TRUSTED_PROXIES"), "CON_TRUSTED_PROXIES", bad)
	cfg.TLSCert, cfg.TLSKey = getenv("CON_TLS_CERT"), getenv("CON_TLS_KEY")
	if (cfg.TLSCert == "") != (cfg.TLSKey == "") {
		bad("CON_TLS_CERT and CON_TLS_KEY must be set together")
	}
	cfg.MetricsAddr = getenv("CON_METRICS_ADDR")
	if cfg.MetricsAddr == "off" {
		cfg.MetricsAddr = ""
	} else if cfg.MetricsAddr == "" {
		cfg.MetricsAddr = "127.0.0.1:9190"
	}

	names := []string{space.Admin, space.Ops}
	if raw := getenv("CON_SPACES"); raw != "" {
		names = names[:0]
		for _, n := range strings.Split(raw, ",") {
			names = append(names, strings.TrimSpace(n))
		}
	}
	addrs := map[string]string{space.Admin: "127.0.0.1:8090", space.Ops: "127.0.0.1:8091"}
	for _, name := range names {
		cookie, policy, err := space.Defaults(name)
		if err != nil {
			bad("CON_SPACES: %v", err)
			continue
		}
		upper := strings.ToUpper(name)
		s := space.Space{
			Name: name, CookieName: cookie, Policy: policy,
			Addr:   cmp.Or(getenv("CON_"+upper+"_ADDR"), addrs[name]),
			Origin: getenv("CON_" + upper + "_ORIGIN"), WebDir: getenv("CON_" + upper + "_WEB_DIR"),
			AllowedCIDRs: parseCIDRs(getenv("CON_"+upper+"_ALLOWED_CIDRS"), "CON_"+upper+"_ALLOWED_CIDRS", bad),
		}
		if prod {
			if len(s.AllowedCIDRs) == 0 {
				bad("CON_%s_ALLOWED_CIDRS is required in production", upper)
			}
			for _, p := range s.AllowedCIDRs {
				if p.Bits() == 0 {
					bad("CON_%s_ALLOWED_CIDRS must not contain %s in production", upper, p)
				}
			}
			if !strings.HasPrefix(s.Origin, "https://") {
				bad("CON_%s_ORIGIN must be https:// in production", upper)
			}
		}
		cfg.Spaces = append(cfg.Spaces, s)
	}
	if len(cfg.Spaces) == 2 && cfg.Spaces[0].Addr == cfg.Spaces[1].Addr {
		bad("CON_ADMIN_ADDR and CON_OPS_ADDR must be different")
	}

	pattern := cmp.Or(getenv("CON_TICKET_PATTERN"), defaultTicketPattern)
	re, err := regexp.Compile(pattern)
	if err != nil {
		bad("CON_TICKET_PATTERN is not a valid regular expression")
	}
	cfg.TicketPattern = re

	cfg.DatabaseURL = Redacted(getenv("CON_DATABASE_URL"))
	cfg.OwnerURL = Redacted(getenv("CON_OWNER_DATABASE_URL"))
	if cfg.DatabaseURL == "" && prod {
		bad("CON_DATABASE_URL is required in production")
	}

	keys, err := secret.ParseKeyring(getenv("CON_DATA_KEYS"), getenv("CON_DATA_ACTIVE_KID"))
	if err != nil {
		bad("CON_DATA_KEYS: %v", err)
	}
	cfg.DataKeys = keys
	if prod {
		for _, p := range keys.Problems() {
			bad("%s", p)
		}
	}
	cfg.HashPepper = decodeSecret(getenv("CON_HASH_PEPPER"), "CON_HASH_PEPPER", bad)
	if prod && len(cfg.HashPepper) < secret.MinDataKeyLen {
		bad("CON_HASH_PEPPER must be at least %d bytes in production", secret.MinDataKeyLen)
	}

	cfg.IMAdminURL = getenv("CON_IM_ADMIN_URL")
	cfg.IMCaller = cmp.Or(getenv("CON_IM_CALLER"), "console")
	cfg.IMSigningKey = parseSigningKey(getenv("CON_IM_SIGNING_KEY"), "CON_IM_SIGNING_KEY", bad)
	cfg.IMMsgReadKey = parseSigningKey(getenv("CON_IM_MSGREAD_KEY"), "CON_IM_MSGREAD_KEY", bad)
	if prod && len(cfg.IMSigningKey) == 0 {
		bad("CON_IM_SIGNING_KEY is required in production")
	}
	cfg.IMTimeout = 10 * time.Second
	if v := getenv("CON_IM_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			bad("CON_IM_TIMEOUT is not a valid duration")
		}
		cfg.IMTimeout = d
	}
	cfg.AuditAnchor = getenv("CON_AUDIT_ANCHOR")
	if prod && cfg.AuditAnchor == "" {
		bad("CON_AUDIT_ANCHOR is required in production")
	}
	problems = append(problems, keysDistinct(cfg)...)
	return cfg, problems
}

func parseCIDRs(raw, name string, bad func(string, ...any)) []netip.Prefix {
	var out []netip.Prefix
	if raw == "" {
		return out
	}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if p, err := netip.ParsePrefix(item); err == nil {
			out = append(out, p.Masked())
			continue
		}
		ip, err := netip.ParseAddr(item)
		if err != nil {
			bad("%s: %q is not an IP or CIDR", name, item)
			continue
		}
		ip = ip.Unmap()
		out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
	}
	return out
}

func decodeSecret(raw, name string, bad func(string, ...any)) secret.Bytes {
	if raw == "" {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		bad("%s is not valid base64", name)
	}
	return b
}

// parseSigningKey 接受 base64 的 32 字节种子或 64 字节私钥。
func parseSigningKey(raw, name string, bad func(string, ...any)) secret.Bytes {
	b := decodeSecret(raw, name, bad)
	switch len(b) {
	case 0:
		return nil
	case ed25519.SeedSize:
		return secret.Bytes(ed25519.NewKeyFromSeed(b))
	case ed25519.PrivateKeySize:
		return b
	}
	bad("%s must be a base64 Ed25519 seed (32 bytes) or private key (64 bytes)", name)
	return nil
}

// keysDistinct：各类密钥互不相同（CS-003 内容 2）。比较种子部分，私钥的前 32 字节就是种子。
func keysDistinct(c Config) []string {
	type item struct {
		name string
		val  []byte
	}
	var items []item
	for id, k := range c.DataKeys.Keys {
		items = append(items, item{"CON_DATA_KEYS[" + id + "]", k})
	}
	items = append(items, item{"CON_HASH_PEPPER", c.HashPepper})
	if len(c.IMSigningKey) >= ed25519.SeedSize {
		items = append(items, item{"CON_IM_SIGNING_KEY", c.IMSigningKey[:ed25519.SeedSize]})
	}
	if len(c.IMMsgReadKey) >= ed25519.SeedSize {
		items = append(items, item{"CON_IM_MSGREAD_KEY", c.IMMsgReadKey[:ed25519.SeedSize]})
	}
	if u, err := url.Parse(string(c.DatabaseURL)); err == nil && u.User != nil {
		if pw, ok := u.User.Password(); ok && pw != "" {
			items = append(items, item{"database password", []byte(pw)})
		}
	}
	slices.SortFunc(items, func(a, b item) int { return strings.Compare(a.name, b.name) })
	var out []string
	for i, a := range items {
		for _, b := range items[i+1:] {
			if len(a.val) > 0 && string(a.val) == string(b.val) {
				out = append(out, a.name+" and "+b.name+" must be different")
			}
		}
	}
	return out
}
