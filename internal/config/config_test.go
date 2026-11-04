package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

var (
	dataKey = strings.Repeat("d", 32)
	pepper  = strings.Repeat("p", 32)
	seed    = strings.Repeat("s", 32)
)

func prodEnv(extra map[string]string) func(string) string {
	m := map[string]string{
		"CON_ENV": "production", "CON_SPACES": "admin", "CON_ADMIN_ALLOWED_CIDRS": "10.0.0.0/8",
		"CON_ADMIN_ORIGIN": "https://admin.example.internal", "CON_DATABASE_URL": "postgres://console_app:pw-secret@db/console",
		"CON_DATA_KEYS": "k1:" + b64(dataKey), "CON_HASH_PEPPER": b64(pepper), "CON_IM_SIGNING_KEY": b64(seed), "CON_AUDIT_ANCHOR": "s3://anchor",
	}
	for k, v := range extra {
		m[k] = v
	}
	return func(k string) string { return m[k] }
}

func TestProductionValid(t *testing.T) {
	cfg, problems := Load(prodEnv(nil))
	if len(problems) != 0 {
		t.Fatal(problems)
	}
	if !cfg.Production() || len(cfg.Spaces) != 1 || len(cfg.IMSigningKey) != ed25519.PrivateKeySize || cfg.DataKeys.Active != "k1" {
		t.Errorf("cfg = %+v", cfg)
	}
}

// AC-CON-01-4 的静态部分、AC-CON-11-3。
func TestProductionProblems(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		extra      map[string]string
	}{
		{"test mode", "CON_TEST_MODE", map[string]string{"CON_TEST_MODE": "1"}},
		{"no cidrs", "CON_ADMIN_ALLOWED_CIDRS", map[string]string{"CON_ADMIN_ALLOWED_CIDRS": ""}},
		{"0.0.0.0/0", "0.0.0.0/0", map[string]string{"CON_ADMIN_ALLOWED_CIDRS": "10.0.0.0/8,0.0.0.0/0"}},
		{"::/0", "::/0", map[string]string{"CON_ADMIN_ALLOWED_CIDRS": "::/0"}},
		{"http origin", "CON_ADMIN_ORIGIN", map[string]string{"CON_ADMIN_ORIGIN": "http://admin"}},
		{"no anchor", "CON_AUDIT_ANCHOR", map[string]string{"CON_AUDIT_ANCHOR": ""}},
		{"no signing key", "CON_IM_SIGNING_KEY", map[string]string{"CON_IM_SIGNING_KEY": ""}},
		{"16 byte data key", "k1", map[string]string{"CON_DATA_KEYS": "k1:" + b64(strings.Repeat("d", 16))}},
		{"no data keys", "CON_DATA_KEYS", map[string]string{"CON_DATA_KEYS": ""}},
		{"data key equals signing key", "must be different", map[string]string{"CON_DATA_KEYS": "k1:" + b64(seed)}},
		{"pepper equals data key", "must be different", map[string]string{"CON_HASH_PEPPER": b64(dataKey)}},
		{"db password equals data key", "database password", map[string]string{"CON_DATABASE_URL": "postgres://u:" + dataKey + "@db/c"}},
		{"bad signing key", "CON_IM_SIGNING_KEY", map[string]string{"CON_IM_SIGNING_KEY": b64("short")}},
	} {
		_, problems := Load(prodEnv(tc.extra))
		joined := strings.Join(problems, "\n")
		if !strings.Contains(joined, tc.want) {
			t.Errorf("%s: problems = %v", tc.name, problems)
		}
		for _, secret := range []string{dataKey, seed, pepper, b64(dataKey), b64(seed)} {
			if strings.Contains(joined, secret) {
				t.Errorf("%s: problems leak a secret: %s", tc.name, joined)
			}
		}
	}
	// 一次列出全部问题（规则 9）。
	_, problems := Load(prodEnv(map[string]string{"CON_TEST_MODE": "1", "CON_AUDIT_ANCHOR": "", "CON_ADMIN_ALLOWED_CIDRS": ""}))
	if len(problems) < 3 {
		t.Errorf("problems = %v", problems)
	}
}

func TestDevelopmentDefaults(t *testing.T) {
	cfg, problems := Load(func(string) string { return "" })
	if len(problems) != 0 {
		t.Fatal(problems)
	}
	if len(cfg.Spaces) != 2 || cfg.Spaces[0].CookieName != "__Host-admin_sid" || !cfg.Spaces[1].Policy.FrameDeny || cfg.Spaces[0].Addr == cfg.Spaces[1].Addr {
		t.Errorf("spaces = %+v", cfg.Spaces)
	}
	if !cfg.TicketPattern.MatchString("CS-1024") || cfg.TicketPattern.MatchString("a b") {
		t.Error("default ticket pattern")
	}
	if _, ok := cfg.Space("ops"); !ok {
		t.Error("ops space")
	}
}

func TestInvalidValues(t *testing.T) {
	for k, v := range map[string]string{
		"CON_ENV": "staging", "CON_SPACES": "admin,nope", "CON_TEST_MODE": "yes", "CON_TRUSTED_PROXIES": "not-an-ip",
		"CON_TICKET_PATTERN": "(", "CON_IM_TIMEOUT": "soon", "CON_TLS_CERT": "only-cert", "CON_ADMIN_ADDR": "127.0.0.1:8091",
	} {
		_, problems := Load(func(key string) string {
			if key == k {
				return v
			}
			return ""
		})
		if len(problems) == 0 {
			t.Errorf("%s=%s accepted", k, v)
		}
	}
}

// 配置结构体打印、序列化都不带密钥（CS-003 内容 2）。
func TestConfigDoesNotPrintSecrets(t *testing.T) {
	cfg, problems := Load(prodEnv(map[string]string{"CON_OWNER_DATABASE_URL": "postgres://console_owner:owner-secret@db/console"}))
	if len(problems) != 0 {
		t.Fatal(problems)
	}
	j, _ := json.Marshal(cfg)
	for _, out := range []string{fmt.Sprintf("%v", cfg), fmt.Sprintf("%+v", cfg), fmt.Sprintf("%#v", cfg), string(j)} {
		for _, secret := range []string{"pw-secret", "owner-secret", dataKey, pepper, seed} {
			if strings.Contains(out, secret) {
				t.Errorf("printed config contains %s", secret)
			}
		}
	}
}
