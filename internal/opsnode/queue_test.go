package opsnode

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tianting/console/internal/clock"
	"tianting/console/internal/imclient"
)

func queueFleet(t *testing.T, h http.HandlerFunc) *Node {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f, err := New([]Entry{{NodeID: "n1", Addr: strings.TrimPrefix(srv.URL, "http://"), Kid: "k1", Key: []byte(priv)}}, "", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	return f.Nodes[0]
}

// 名额满时排队，不是直接失败：几个工程师同时排查不能变成"节点未响应"。
func TestCallQueuesWithinPerNodeLimit(t *testing.T) {
	var now, peak atomic.Int32
	n := queueFleet(t, func(w http.ResponseWriter, _ *http.Request) {
		c := now.Add(1)
		defer now.Add(-1)
		for {
			p := peak.Load()
			if c <= p || peak.CompareAndSwap(p, c) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		_, _ = w.Write([]byte(`{}`))
	})
	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- n.Call(context.Background(), imclient.Call{Operator: "t", RequestID: "r"}, "GET", "/x", nil, nil)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("call: %v", err)
		}
	}
	if p := peak.Load(); p != maxPerNode {
		t.Errorf("peak = %d, want %d", p, maxPerNode)
	}
}

// 节点卡住：排队有上限，加上单次超时仍在 2.5 秒内（AC-OPS-08-11）。
func TestCallQueueIsBounded(t *testing.T) {
	release := make(chan struct{})
	n := queueFleet(t, func(http.ResponseWriter, *http.Request) { <-release })
	defer close(release)
	var wg sync.WaitGroup
	for range maxPerNode {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = n.Call(context.Background(), imclient.Call{Operator: "t", RequestID: "r"}, "GET", "/x", nil, nil)
		}()
	}
	for len(n.sem) < maxPerNode {
		time.Sleep(time.Millisecond)
	}
	start := time.Now()
	err := n.Call(context.Background(), imclient.Call{Operator: "t", RequestID: "r"}, "GET", "/x", nil, nil)
	if !errors.Is(err, ErrBusy) {
		t.Errorf("err = %v", err)
	}
	if d := time.Since(start); d < queueWait || d > 2*queueWait {
		t.Errorf("waited %v", d)
	}
	wg.Wait()
}
