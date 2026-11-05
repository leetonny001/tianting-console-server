package app

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"tianting/console/internal/apierr"
	"tianting/console/internal/audit"
	"tianting/console/internal/imclient"
	"tianting/console/internal/prom"
)

// CS-130：告警静默（PRD-ops F-OPS-18）。唯一会改变 Alertmanager 状态的接口，只影响通知，不影响 IM。

const (
	actionSilenceCreate = "ops.silence.create"
	actionSilenceExpire = "ops.silence.expire"
	silenceMinMinutes   = 15
	silenceMaxMinutes   = 24 * 60
)

// 告警名只能是字母、数字和少数连接符：把正则元字符挡在外面。发给 Alertmanager 时虽然写死了等值匹配，
// 但 alertname=.* 这样的输入一定是有人以为能用正则，不能默默收下一条什么都不匹配的静默。
var silenceAlertRe = regexp.MustCompile(`^[\p{L}\p{N}_.-][\p{L}\p{N}_. -]{0,127}$`)

type silenceMatcher struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	IsRegex *bool  `json:"isRegex"`
	IsEqual *bool  `json:"isEqual"`
}

// checkSilenceMatchers：只允许 alertname、node_id 的等值匹配，至少一个，每个名字最多一个。
func checkSilenceMatchers(in []silenceMatcher) ([]prom.Matcher, *apierr.Error) {
	bad := func(msg string) ([]prom.Matcher, *apierr.Error) {
		return nil, &apierr.Error{Code: apierr.BadRequest, Msg: msg, Reason: "silenceMatcherInvalid"}
	}
	if len(in) == 0 {
		return bad("at least one matcher is required")
	}
	seen := map[string]bool{}
	out := make([]prom.Matcher, 0, len(in))
	for _, m := range in {
		if (m.IsRegex != nil && *m.IsRegex) || (m.IsEqual != nil && !*m.IsEqual) {
			return bad("only equality matchers are allowed")
		}
		switch m.Name {
		case "alertname":
			if !silenceAlertRe.MatchString(m.Value) || strings.TrimSpace(m.Value) != m.Value {
				return bad("invalid alertname")
			}
		case "node_id":
			if !validID(m.Value) {
				return bad("invalid node_id")
			}
		default:
			return bad("only alertname and node_id can be matched")
		}
		if seen[m.Name] {
			return bad("duplicate matcher")
		}
		seen[m.Name] = true
		out = append(out, prom.Matcher{Name: m.Name, Value: m.Value, IsEqual: true})
	}
	return out, nil
}

// silenceTarget 是审计目标 alert:<匹配条件>。
func silenceTarget(ms []prom.Matcher) audit.Target {
	parts := make([]string, 0, len(ms))
	for _, m := range ms {
		op := "="
		switch {
		case m.IsRegex && m.IsEqual:
			op = "=~"
		case m.IsRegex:
			op = "!~"
		case !m.IsEqual:
			op = "!="
		}
		parts = append(parts, m.Name+op+m.Value)
	}
	return audit.NewTarget("alert", strings.Join(parts, ","))
}

// silenceError 把 Alertmanager 的错误转成接口错误。结果未知时交给 audited 记 unknown、回 5040。
func (c *rc) silenceError(err error) error {
	switch {
	case errors.Is(err, prom.ErrResultUnknown):
		return imclient.ErrResultUnknown
	case errors.Is(err, prom.ErrSilenceNotFound):
		return apierr.New(apierr.NotFound, "silence not found")
	case errors.Is(err, prom.ErrUnavailable):
		c.a.Log.Error("alertmanager", "err", err, "requestId", c.requestID)
		return apierr.New(apierr.Unavailable, "alertmanager is unavailable")
	}
	return err
}

// ticketReason：工单号和理由都必填（规则同 F-OPS-08）。
func (c *rc) ticketReason(ticket, rawReason string) (string, bool) {
	if ticket == "" {
		c.fail(&apierr.Error{Code: apierr.BadRequest, Msg: "ticket is required", Reason: "ticketInvalid"})
		return "", false
	}
	return c.reasonTicket(rawReason, ticket)
}

func (c *rc) opsSilenceCreate() {
	var req struct {
		Matchers        []silenceMatcher `json:"matchers"`
		DurationMinutes int              `json:"durationMinutes"`
		Ticket          string           `json:"ticket"`
		Reason          string           `json:"reason"`
	}
	if !c.readJSON(&req) {
		return
	}
	matchers, bad := checkSilenceMatchers(req.Matchers)
	if bad != nil {
		c.fail(bad)
		return
	}
	if req.DurationMinutes < silenceMinMinutes || req.DurationMinutes > silenceMaxMinutes {
		c.fail(&apierr.Error{Code: apierr.BadRequest, Msg: "duration must be 15 minutes to 24 hours", Reason: "silenceDurationInvalid"})
		return
	}
	reason, ok := c.ticketReason(req.Ticket, req.Reason)
	if !ok {
		return
	}
	c.ticket = req.Ticket
	starts := c.a.Clock.Now()
	ends := starts.Add(time.Duration(req.DurationMinutes) * time.Minute)
	params := map[string]any{"durationMinutes": req.DurationMinutes, "endsAt": ends.UnixMilli()}
	c.audited(actionSilenceCreate, silenceTarget(matchers), params, reason, func() (any, error) {
		// 不跟着请求取消：写到一半断开就不知道有没有生效了。
		id, err := c.a.Alertmanager.CreateSilence(context.WithoutCancel(c.ctx), matchers, starts, ends, c.acct.Username, req.Ticket)
		if err != nil {
			return nil, c.silenceError(err)
		}
		c.resultParams = map[string]any{"silenceId": id, "durationMinutes": req.DurationMinutes, "endsAt": ends.UnixMilli()}
		return opsEnvelope{Data: prom.Silence{ID: id, Matchers: matchers, CreatedBy: c.acct.Username, StartsAt: starts.UTC().Format(time.RFC3339), EndsAt: ends.UTC().Format(time.RFC3339)},
			MissingNodes: []string{}, DataTime: c.now()}, nil
	})
}

// opsSilenceExpire 处理 POST /silences/{id}:expire。ServeMux 只能按整段匹配，后缀在这里判断。
func (c *rc) opsSilenceExpire() {
	id, ok := strings.CutSuffix(c.r.PathValue("id"), ":expire")
	if !ok {
		c.fail(apierr.New(apierr.NotFound, "not found"))
		return
	}
	if !uuidRe.MatchString(id) {
		c.fail(apierr.New(apierr.InvalidID, "invalid silence id"))
		return
	}
	var req struct {
		Ticket string `json:"ticket"`
		Reason string `json:"reason"`
	}
	if !c.readJSON(&req) {
		return
	}
	reason, ok := c.ticketReason(req.Ticket, req.Reason)
	if !ok {
		return
	}
	c.ticket = req.Ticket
	// 先读一次，审计才能记下匹配条件和时长。读不到也要留痕，所以不在这里返回。
	ctx := context.WithoutCancel(c.ctx)
	sil, lookup := c.a.Alertmanager.GetSilence(ctx, id)
	target := audit.NewTarget("alert", id)
	params := map[string]any{"silenceId": id}
	if lookup == nil {
		target = silenceTarget(sil.Matchers)
		s, err1 := time.Parse(time.RFC3339, sil.StartsAt)
		e, err2 := time.Parse(time.RFC3339, sil.EndsAt)
		if err1 == nil && err2 == nil {
			params["durationMinutes"] = int(e.Sub(s).Minutes())
		}
	}
	c.audited(actionSilenceExpire, target, params, reason, func() (any, error) {
		c.resultParams = params
		if lookup != nil {
			return nil, c.silenceError(lookup)
		}
		if sil.State == "expired" {
			return nil, conflict("the silence has already ended")
		}
		if err := c.a.Alertmanager.ExpireSilence(ctx, id); err != nil {
			return nil, c.silenceError(err)
		}
		return opsEnvelope{Data: map[string]any{"id": id}, MissingNodes: []string{}, DataTime: c.now()}, nil
	})
}
