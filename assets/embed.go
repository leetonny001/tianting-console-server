// Package assets 打包弱密码表。
package assets

import (
	_ "embed" // 弱密码表
	"strings"
)

//go:embed weak-passwords.txt
var weak string

// WeakPasswords 返回小写的弱密码集合。
func WeakPasswords() map[string]bool {
	out := map[string]bool{}
	for _, l := range strings.Split(weak, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out[strings.ToLower(l)] = true
		}
	}
	return out
}
