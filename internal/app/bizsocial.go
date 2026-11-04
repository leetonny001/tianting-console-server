package app

import (
	"encoding/json"
	"reflect"
	"sort"

	"tianting/console/internal/apierr"
	"tianting/console/internal/audit"
)

// CS-023：社交配置。

const socialSettingsPath = "/admin/settings/social"

func (c *rc) getSocialSettings() {
	var out map[string]any
	if err := c.im("GET", socialSettingsPath, nil, nil, &out); err != nil {
		c.failErr("social settings", notAvailable(err))
		return
	}
	c.ok(out)
}

func (c *rc) patchSocialSettings() {
	var req map[string]json.RawMessage
	if !c.readJSON(&req) {
		return
	}
	str := func(k string) string {
		var s string
		_ = json.Unmarshal(req[k], &s)
		delete(req, k)
		return s
	}
	reason, ok := c.reasonTicket(str("reason"), "")
	if !ok {
		return
	}
	confirm := str("confirmMode")
	var cur map[string]any
	if err := c.im("GET", socialSettingsPath, nil, nil, &cur); err != nil {
		c.failErr("social settings", notAvailable(err))
		return
	}
	// 只把修改了的字段传给 im-server（AC-ADM-16-5）。
	changes := map[string]any{}
	patch := map[string]json.RawMessage{}
	names := make([]string, 0, len(req))
	for k := range req {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		var v any
		if err := json.Unmarshal(req[k], &v); err != nil {
			c.fail(apierr.New(apierr.BadRequest, "invalid value"))
			return
		}
		if old, known := cur[k]; known && reflect.DeepEqual(old, v) {
			continue
		}
		patch[k] = req[k]
		changes[k] = describeChange(cur[k], v)
	}
	if raw, changing := patch["mode"]; changing {
		var mode string
		if json.Unmarshal(raw, &mode) != nil || confirm != mode {
			c.fail(&apierr.Error{Code: apierr.BadRequest, Msg: "confirmMode must equal the new mode", Reason: "confirmMismatch"})
			return
		}
	}
	if len(patch) == 0 {
		c.ok(cur)
		return
	}
	c.audited("social.settings", audit.Target{Type: "settings"}, changes, reason, func() (any, error) {
		var out map[string]any
		err := c.im("PATCH", socialSettingsPath, nil, patch, &out)
		return out, notAvailable(err)
	})
}
