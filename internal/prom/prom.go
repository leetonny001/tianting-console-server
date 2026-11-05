// Package prom 是 Prometheus 和 Alertmanager 的客户端（PRD-ops F-OPS-04）。查询语句都在这个文件里。
// Prometheus 只读；Alertmanager 除了读告警，只有创建和结束静默两个写操作（F-OPS-18），都只能经 console-server。
package prom

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	queryTimeout  = time.Second
	writeTimeout  = 5 * time.Second
	maxConcurrent = 4 // 每个实例
)

// ErrUnavailable 表示数据源不可用。卡片要显示"数据不可用"，绝不能当成 0。
var ErrUnavailable = errors.New("data source unavailable")

// ErrResultUnknown：写请求可能已经到了 Alertmanager，但没有拿到答复。调用方不能当成失败。
var ErrResultUnknown = errors.New("alertmanager result unknown")

// ErrSilenceNotFound：Alertmanager 里没有这条静默。
var ErrSilenceNotFound = errors.New("silence not found")

// Sample 是一个序列的值。
type Sample struct {
	Labels map[string]string
	Value  float64
}

// Client 查询 Prometheus。
type Client struct {
	Base string
	HTTP *http.Client
	sem  chan struct{}
}

// New 创建客户端。base 为空表示没有配置。
func New(base string) *Client {
	return &Client{Base: strings.TrimRight(base, "/"), HTTP: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, sem: make(chan struct{}, maxConcurrent)}
}

// Query 执行即时查询。
func (c *Client) Query(ctx context.Context, expr string) ([]Sample, error) {
	if c == nil || c.Base == "" {
		return nil, ErrUnavailable
	}
	select {
	case c.sem <- struct{}{}:
		defer func() { <-c.sem }()
	case <-ctx.Done():
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Base+"/api/v1/query?"+url.Values{"query": {expr}}.Encode(), nil)
	if err != nil {
		return nil, ErrUnavailable
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer resp.Body.Close()
	var out struct {
		Status string `json:"status"`
		Data   struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Metric map[string]string `json:"metric"`
				Value  [2]any            `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&out) != nil || out.Status != "success" {
		return nil, ErrUnavailable
	}
	samples := make([]Sample, 0, len(out.Data.Result))
	for _, r := range out.Data.Result {
		s, _ := r.Value[1].(string)
		v, err := strconv.ParseFloat(s, 64)
		if err != nil {
			continue
		}
		samples = append(samples, Sample{r.Metric, v})
	}
	return samples, nil
}

// Scalar 查询一个数。没有序列（指标还没出现）算 0：Prometheus 活着，只是还没有这类事件。
func (c *Client) Scalar(ctx context.Context, expr string) (float64, error) {
	s, err := c.Query(ctx, expr)
	if err != nil {
		return 0, err
	}
	var sum float64
	for _, x := range s {
		sum += x.Value
	}
	return sum, nil
}

// 命令统计不算 auth 和心跳（F-OPS-04 卡片说明）。
const commandFilter = `cmd!~"auth|ping"`

// 查询语句。
var (
	QueryMessageRate    = `sum(rate(im_messages_total[1m]))`
	QueryCommandsByCode = `sum by (code) (increase(im_commands_total{` + commandFilter + `}[5m]))`
	QueryHandshake      = `sum by (code) (increase(im_disconnects_total{phase="handshake"}[5m]))`
	QuerySession        = `sum by (code) (increase(im_disconnects_total{phase="session"}[5m]))`
	QueryUnattributed   = `sum by (code) (increase(im_disconnects_total{phase="handshake",code=~"4401|4010|4009"}[1h]))`
	QueryPeakConns      = `max by (node_id) (max_over_time(sum by (node_id) (im_connections)[7d:5m]))`
)

// QueryMessagesToday 是今日累计：从 Asia/Shanghai 零点到现在。increase 会处理进程重启。
func QueryMessagesToday(sinceMidnight time.Duration) string {
	secs := max(int64(sinceMidnight.Seconds()), 60)
	return fmt.Sprintf(`sum(increase(im_messages_total[%ds]))`, secs)
}

// Alert 是一条正在触发的告警。
type Alert struct {
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Node     string `json:"node"`
	StartsAt string `json:"startsAt"`
	Summary  string `json:"summary"`
}

// Alertmanager 读取当前告警和静默，创建、结束静默。
type Alertmanager struct {
	Base string
	HTTP *http.Client
}

func (a *Alertmanager) client() *http.Client {
	if a.HTTP != nil {
		return a.HTTP
	}
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// Alerts 返回未静默、未抑制的告警。
func (a *Alertmanager) Alerts(ctx context.Context) ([]Alert, error) {
	if a == nil || a.Base == "" {
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(a.Base, "/")+"/api/v2/alerts?active=true&silenced=false&inhibited=false", nil)
	if err != nil {
		return nil, ErrUnavailable
	}
	resp, err := a.client().Do(req)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer resp.Body.Close()
	var raw []struct {
		Labels      map[string]string `json:"labels"`
		Annotations map[string]string `json:"annotations"`
		StartsAt    string            `json:"startsAt"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&raw) != nil {
		return nil, ErrUnavailable
	}
	out := make([]Alert, 0, len(raw))
	for _, r := range raw {
		node := r.Labels["node_id"]
		if node == "all" { // 汇总类告警（alerts.yml）：不属于某个节点，页面显示"全局"
			node = ""
		}
		out = append(out, Alert{Name: r.Labels["alertname"], Severity: r.Labels["severity"], Node: node, StartsAt: r.StartsAt, Summary: r.Annotations["summary"]})
	}
	return out, nil
}

// Matcher 是静默的一个匹配条件。
type Matcher struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	IsRegex bool   `json:"isRegex"`
	IsEqual bool   `json:"isEqual"`
}

// Silence 是一条静默。comment 是工单号，不给只读账号看，所以不进 JSON。
type Silence struct {
	ID        string    `json:"id"`
	Matchers  []Matcher `json:"matchers"`
	CreatedBy string    `json:"createdBy"`
	StartsAt  string    `json:"startsAt"`
	EndsAt    string    `json:"endsAt"`
	State     string    `json:"-"`
	Comment   string    `json:"-"`
}

// wireSilence 是 Alertmanager v2 API 的静默。isEqual 老版本没有这个字段，缺省按等值。
type wireSilence struct {
	ID     string `json:"id"`
	Status struct {
		State string `json:"state"`
	} `json:"status"`
	Matchers []struct {
		Name    string `json:"name"`
		Value   string `json:"value"`
		IsRegex bool   `json:"isRegex"`
		IsEqual *bool  `json:"isEqual"`
	} `json:"matchers"`
	StartsAt  string `json:"startsAt"`
	EndsAt    string `json:"endsAt"`
	CreatedBy string `json:"createdBy"`
	Comment   string `json:"comment"`
}

func (w wireSilence) silence() Silence {
	s := Silence{ID: w.ID, CreatedBy: w.CreatedBy, StartsAt: w.StartsAt, EndsAt: w.EndsAt, State: w.Status.State, Comment: w.Comment, Matchers: []Matcher{}}
	for _, m := range w.Matchers {
		s.Matchers = append(s.Matchers, Matcher{Name: m.Name, Value: m.Value, IsRegex: m.IsRegex, IsEqual: m.IsEqual == nil || *m.IsEqual})
	}
	return s
}

// Silences 返回当前生效的静默，先到期的在前。
func (a *Alertmanager) Silences(ctx context.Context) ([]Silence, error) {
	if a == nil || a.Base == "" {
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(a.Base, "/")+"/api/v2/silences", nil)
	if err != nil {
		return nil, ErrUnavailable
	}
	resp, err := a.client().Do(req)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer resp.Body.Close()
	var raw []wireSilence
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&raw) != nil {
		return nil, ErrUnavailable
	}
	out := []Silence{}
	for _, r := range raw {
		if r.Status.State == "active" {
			out = append(out, r.silence())
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].EndsAt != out[j].EndsAt {
			return out[i].EndsAt < out[j].EndsAt
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// GetSilence 读一条静默。不存在时返回 ErrSilenceNotFound。
func (a *Alertmanager) GetSilence(ctx context.Context, id string) (Silence, error) {
	if a == nil || a.Base == "" {
		return Silence{}, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(a.Base, "/")+"/api/v2/silence/"+url.PathEscape(id), nil)
	if err != nil {
		return Silence{}, ErrUnavailable
	}
	resp, err := a.client().Do(req)
	if err != nil {
		return Silence{}, ErrUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return Silence{}, ErrSilenceNotFound
	}
	var raw wireSilence
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&raw) != nil {
		return Silence{}, ErrUnavailable
	}
	return raw.silence(), nil
}

// writeError 判断写请求失败时有没有可能已经生效：连不上肯定没生效，其他情况（超时、连接中断）不知道。
func writeError(err error) error {
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		return ErrUnavailable
	}
	return ErrResultUnknown
}

// CreateSilence 创建静默，返回 ID。matchers 由调用方校验过，这里只发等值匹配：isRegex 写死 false。
func (a *Alertmanager) CreateSilence(ctx context.Context, matchers []Matcher, startsAt, endsAt time.Time, createdBy, comment string) (string, error) {
	if a == nil || a.Base == "" {
		return "", ErrUnavailable
	}
	type wireMatcher struct {
		Name    string `json:"name"`
		Value   string `json:"value"`
		IsRegex bool   `json:"isRegex"`
		IsEqual bool   `json:"isEqual"`
	}
	wire := make([]wireMatcher, 0, len(matchers))
	for _, m := range matchers {
		wire = append(wire, wireMatcher{Name: m.Name, Value: m.Value, IsRegex: false, IsEqual: true})
	}
	body, err := json.Marshal(map[string]any{
		"matchers": wire, "createdBy": createdBy, "comment": comment,
		"startsAt": startsAt.UTC().Format(time.RFC3339), "endsAt": endsAt.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(a.Base, "/")+"/api/v2/silences", bytes.NewReader(body))
	if err != nil {
		return "", ErrUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client().Do(req)
	if err != nil {
		return "", writeError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: create silence: status %d", ErrUnavailable, resp.StatusCode)
	}
	var out struct {
		SilenceID string `json:"silenceID"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out) != nil || out.SilenceID == "" {
		return "", ErrResultUnknown // 状态码说成功了，只是拿不到 ID
	}
	return out.SilenceID, nil
}

// ExpireSilence 提前结束静默。
func (a *Alertmanager) ExpireSilence(ctx context.Context, id string) error {
	if a == nil || a.Base == "" {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, strings.TrimRight(a.Base, "/")+"/api/v2/silence/"+url.PathEscape(id), nil)
	if err != nil {
		return ErrUnavailable
	}
	resp, err := a.client().Do(req)
	if err != nil {
		return writeError(err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusNotFound:
		return ErrSilenceNotFound
	}
	return fmt.Errorf("%w: expire silence: status %d", ErrUnavailable, resp.StatusCode)
}
