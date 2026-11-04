// Package prom 是 Prometheus 和 Alertmanager 的只读客户端（PRD-ops F-OPS-04）。查询语句都在这个文件里。
package prom

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	queryTimeout  = time.Second
	maxConcurrent = 4 // 每个实例
)

// ErrUnavailable 表示数据源不可用。卡片要显示"数据不可用"，绝不能当成 0。
var ErrUnavailable = errors.New("data source unavailable")

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

// Alertmanager 读取当前告警。只读。
type Alertmanager struct {
	Base string
	HTTP *http.Client
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
	hc := a.HTTP
	if hc == nil {
		hc = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, err := hc.Do(req)
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
