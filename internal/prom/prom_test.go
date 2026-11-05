package prom

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestQuery(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query().Get("query")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"code":"4290"},"value":[1,"3.5"]},{"metric":{"code":"0"},"value":[1,"1"]}]}}`))
	}))
	defer srv.Close()
	c := New(srv.URL)
	s, err := c.Query(context.Background(), QueryCommandsByCode)
	if err != nil || len(s) != 2 || s[0].Labels["code"] != "4290" || s[0].Value != 3.5 {
		t.Fatalf("%v %v", s, err)
	}
	if !strings.Contains(got, `cmd!~"auth|ping"`) {
		t.Errorf("query = %s", got)
	}
	if v, err := c.Scalar(context.Background(), "x"); err != nil || v != 4.5 {
		t.Errorf("scalar = %v %v", v, err)
	}
}

func TestUnavailableIsNotZero(t *testing.T) {
	ctx := context.Background()
	if _, err := New("").Scalar(ctx, "x"); !errors.Is(err, ErrUnavailable) {
		t.Error("no url:", err)
	}
	if _, err := New("http://127.0.0.1:1").Scalar(ctx, "x"); !errors.Is(err, ErrUnavailable) {
		t.Error("refused:", err)
	}
	for _, body := range []string{`not json`, `{"status":"error"}`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
		if _, err := New(srv.URL).Scalar(ctx, "x"); !errors.Is(err, ErrUnavailable) {
			t.Errorf("%s: %v", body, err)
		}
		srv.Close()
	}
	var am *Alertmanager
	if _, err := am.Alerts(ctx); !errors.Is(err, ErrUnavailable) {
		t.Error(err)
	}
}

func TestTodayWindow(t *testing.T) {
	if q := QueryMessagesToday(2 * time.Hour); q != `sum(increase(im_messages_total[7200s]))` {
		t.Error(q)
	}
	if q := QueryMessagesToday(0); !strings.Contains(q, "[60s]") { // 零点刚过：区间不能为 0
		t.Error(q)
	}
}

// alerts.yml 里汇总类告警的 node_id 是 all，页面按"全局"显示。
func TestAlertsAggregateNode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"labels":{"alertname":"备份过期","severity":"critical","node_id":"all"},"startsAt":"2026-11-04T00:00:00Z"},
			{"labels":{"alertname":"节点不可达","severity":"critical","node_id":"n1"},"startsAt":"2026-11-04T00:00:00Z"}]`))
	}))
	defer srv.Close()
	got, err := (&Alertmanager{Base: srv.URL}).Alerts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Node != "" || got[1].Node != "n1" {
		t.Fatalf("got %+v", got)
	}
}

// 创建静默的请求体符合 v2 API：等值匹配写死，createdBy、comment、时间都在。
func TestCreateSilence(t *testing.T) {
	var got map[string]any
	var path, ct string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, ct = r.Method+" "+r.URL.Path, r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got)
		_, _ = w.Write([]byte(`{"silenceID":"abc"}`))
	}))
	defer srv.Close()
	a := &Alertmanager{Base: srv.URL + "/"}
	start := time.Date(2027, 1, 15, 8, 0, 0, 0, time.FixedZone("x", 8*3600))
	// 调用方传错也不能变成正则。
	id, err := a.CreateSilence(context.Background(), []Matcher{{Name: "alertname", Value: "节点不可达", IsRegex: true}}, start, start.Add(time.Hour), "eng1", "CS-1")
	if err != nil || id != "abc" {
		t.Fatal(id, err)
	}
	if path != "POST /api/v2/silences" || ct != "application/json" {
		t.Errorf("%s %s", path, ct)
	}
	if got["createdBy"] != "eng1" || got["comment"] != "CS-1" || got["startsAt"] != "2027-01-15T00:00:00Z" || got["endsAt"] != "2027-01-15T01:00:00Z" {
		t.Errorf("body = %v", got)
	}
	m := got["matchers"].([]any)[0].(map[string]any)
	if m["name"] != "alertname" || m["value"] != "节点不可达" || m["isRegex"] != false || m["isEqual"] != true {
		t.Errorf("matcher = %v", m)
	}
}

func TestSilenceErrors(t *testing.T) {
	ctx := context.Background()
	var nilAM *Alertmanager
	if _, err := nilAM.Silences(ctx); !errors.Is(err, ErrUnavailable) {
		t.Error(err)
	}
	if _, err := nilAM.CreateSilence(ctx, nil, time.Now(), time.Now(), "a", "b"); !errors.Is(err, ErrUnavailable) {
		t.Error(err)
	}
	// 连不上：肯定没有生效。
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	closed := &Alertmanager{Base: url}
	if _, err := closed.CreateSilence(ctx, nil, time.Now(), time.Now(), "a", "b"); !errors.Is(err, ErrUnavailable) {
		t.Error(err)
	}
	// 连接中途断开：不知道有没有生效。
	drop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		c, _, _ := w.(http.Hijacker).Hijack()
		c.Close()
	}))
	defer drop.Close()
	am := &Alertmanager{Base: drop.URL}
	if _, err := am.CreateSilence(ctx, nil, time.Now(), time.Now(), "a", "b"); !errors.Is(err, ErrResultUnknown) {
		t.Error(err)
	}
	if err := am.ExpireSilence(ctx, "x"); !errors.Is(err, ErrResultUnknown) {
		t.Error(err)
	}
	// 拒绝：没有生效；200 但读不到 ID：生效了，只是不知道 ID。
	status := http.StatusBadRequest
	body := ""
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer s.Close()
	am = &Alertmanager{Base: s.URL}
	if _, err := am.CreateSilence(ctx, nil, time.Now(), time.Now(), "a", "b"); !errors.Is(err, ErrUnavailable) {
		t.Error(err)
	}
	status = http.StatusOK
	if _, err := am.CreateSilence(ctx, nil, time.Now(), time.Now(), "a", "b"); !errors.Is(err, ErrResultUnknown) {
		t.Error(err)
	}
	status = http.StatusNotFound
	if err := am.ExpireSilence(ctx, "x"); !errors.Is(err, ErrSilenceNotFound) {
		t.Error(err)
	}
	if _, err := am.GetSilence(ctx, "x"); !errors.Is(err, ErrSilenceNotFound) {
		t.Error(err)
	}
}

// 只返回生效的静默，先到期的在前；老版本没有 isEqual 字段时按等值。
func TestSilencesActiveOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/silences" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`[
			{"id":"b","status":{"state":"active"},"matchers":[{"name":"alertname","value":"x","isRegex":false}],"startsAt":"2027-01-15T00:00:00Z","endsAt":"2027-01-15T02:00:00Z","createdBy":"e1","comment":"CS-1"},
			{"id":"a","status":{"state":"active"},"matchers":[{"name":"alertname","value":"y.*","isRegex":true,"isEqual":false}],"startsAt":"2027-01-15T00:00:00Z","endsAt":"2027-01-15T01:00:00Z","createdBy":"e2","comment":"CS-2"},
			{"id":"c","status":{"state":"expired"},"matchers":[],"startsAt":"2027-01-15T00:00:00Z","endsAt":"2027-01-15T00:30:00Z","createdBy":"e3","comment":"CS-3"},
			{"id":"d","status":{"state":"pending"},"matchers":[],"startsAt":"2027-01-16T00:00:00Z","endsAt":"2027-01-16T00:30:00Z","createdBy":"e4","comment":"CS-4"}
		]`))
	}))
	defer srv.Close()
	list, err := (&Alertmanager{Base: srv.URL}).Silences(context.Background())
	if err != nil || len(list) != 2 || list[0].ID != "a" || list[1].ID != "b" {
		t.Fatalf("%+v %v", list, err)
	}
	if !list[1].Matchers[0].IsEqual || list[0].Matchers[0].IsEqual || !list[0].Matchers[0].IsRegex {
		t.Errorf("%+v", list)
	}
	raw, _ := json.Marshal(list)
	if strings.Contains(string(raw), "CS-") {
		t.Errorf("comment in JSON: %s", raw)
	}
}
