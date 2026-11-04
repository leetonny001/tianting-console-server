package prom

import (
	"context"
	"errors"
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
