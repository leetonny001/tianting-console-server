// Package opsnode 是 console-server 调用 im-server 节点运维接口的客户端（PRD-ops F-OPS-16、7.2 节）。
//
// 每个节点一把独立的 Ed25519 私钥，签名和管理接口同一实现（imclient）。地址只来自静态的节点凭证表。
// TLS 只信任内部 CA，服务名必须和表里一致；校验失败时请求根本发不出去，签名不会泄露给冒充者。
package opsnode

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"tianting/console/internal/clock"
	"tianting/console/internal/imclient"
	"tianting/console/internal/secret"
)

const (
	callerID      = "console-ops"
	nodeTimeout   = 1500 * time.Millisecond
	maxConcurrent = 8 // 每个实例
	maxPerNode    = 2
)

// ErrIdentity 表示 TLS 身份校验失败："未通过身份校验"，没有发出任何请求。
var ErrIdentity = errors.New("node failed TLS identity check")

// ErrBusy 表示本实例对这个节点的并发已满。
var ErrBusy = errors.New("too many concurrent requests to this node")

// Entry 是节点凭证表的一行。Key 从文件读取，打印不出来。
type Entry struct {
	NodeID        string       `json:"nodeId"`
	Addr          string       `json:"addr"`
	TLSServerName string       `json:"tlsServerName"`
	Kid           string       `json:"kid"`
	KeyFile       string       `json:"keyFile"`
	MetricsAddr   string       `json:"metricsAddr"`
	Key           secret.Bytes `json:"-"`
}

func loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

// LoadTable 读取节点凭证表（JSON 数组）。问题一次列全；错误信息不含私钥内容。production 时每个节点都要有 TLS 服务名。
func LoadTable(path string, production bool) ([]Entry, []string) {
	raw, err := os.ReadFile(path) // #nosec G304 -- 路径来自运维配置
	if err != nil {
		return nil, []string{"CON_OPS_NODES: cannot read the node credential table"}
	}
	var list []Entry
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, []string{"CON_OPS_NODES: the node credential table is not valid JSON"}
	}
	var problems []string
	bad := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	seen := map[string]bool{}
	for i := range list {
		e := &list[i]
		name := e.NodeID
		if name == "" {
			bad("node credential table row %d has no nodeId", i+1)
			name = fmt.Sprintf("row %d", i+1)
		}
		if seen[name] {
			bad("node %s appears twice in the node credential table", name)
		}
		seen[name] = true
		if e.Addr == "" {
			bad("node %s has no addr", name)
		}
		if e.TLSServerName == "" && (production || !loopback(e.Addr)) {
			bad("node %s has no tlsServerName", name)
		}
		key, err := readKey(e.KeyFile)
		if err != nil {
			bad("node %s: %v", name, err)
			continue
		}
		e.Key = key
	}
	return list, problems
}

func readKey(path string) (secret.Bytes, error) {
	if path == "" {
		return nil, errors.New("keyFile is not set")
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- 路径来自运维配置
	if err != nil {
		return nil, errors.New("cannot read keyFile")
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, errors.New("keyFile is not base64")
	}
	switch len(b) {
	case ed25519.SeedSize:
		return secret.Bytes(ed25519.NewKeyFromSeed(b)), nil
	case ed25519.PrivateKeySize:
		return secret.Bytes(b), nil
	}
	return nil, errors.New("keyFile is not an Ed25519 seed or private key")
}

// Node 是一个节点的客户端。
type Node struct {
	Entry Entry
	cl    *imclient.Client
	sem   chan struct{}
}

// Fleet 是全部节点。
type Fleet struct {
	Nodes []*Node
	sem   chan struct{}
}

// New 创建客户端。caFile 为空时只能连回环地址（开发环境）。
func New(entries []Entry, caFile string, clk clock.Clock) (*Fleet, error) {
	var pool *x509.CertPool
	if caFile != "" {
		pem, err := os.ReadFile(caFile) // #nosec G304 -- 路径来自运维配置
		if err != nil {
			return nil, errors.New("CON_OPS_CA_FILE: cannot read the file")
		}
		pool = x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("CON_OPS_CA_FILE: no certificates found")
		}
	}
	f := &Fleet{sem: make(chan struct{}, maxConcurrent)}
	for _, e := range entries {
		scheme := "http://"
		hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		if e.TLSServerName != "" {
			scheme = "https://"
			// 只信任内部 CA（pool 为 nil 时用系统根，开发环境才会走到）。
			hc.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: e.TLSServerName, MinVersion: tls.VersionTLS12}}
		}
		cl, err := imclient.New(imclient.Config{
			BaseURL: scheme + e.Addr, Caller: callerID, Key: ed25519.PrivateKey(e.Key), Timeout: nodeTimeout, Node: e.NodeID, Clock: clk, HTTP: hc,
		})
		if err != nil {
			return nil, fmt.Errorf("node %s: %w", e.NodeID, err)
		}
		f.Nodes = append(f.Nodes, &Node{Entry: e, cl: cl, sem: make(chan struct{}, maxPerNode)})
	}
	return f, nil
}

// Call 调用一个节点。身份校验失败返回 ErrIdentity。
func (n *Node) Call(ctx context.Context, call imclient.Call, method, path string, body, out any) error {
	select {
	case n.sem <- struct{}{}:
		defer func() { <-n.sem }()
	default:
		return ErrBusy
	}
	err := n.cl.Do(ctx, call, method, path, nil, body, out)
	if isIdentityError(err) {
		return ErrIdentity
	}
	return err
}

func isIdentityError(err error) bool {
	var verify *tls.CertificateVerificationError
	var host x509.HostnameError
	var authority x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	return errors.As(err, &verify) || errors.As(err, &host) || errors.As(err, &authority) || errors.As(err, &invalid)
}

// Each 对全部节点并发执行 fn（实例并发上限 8）。返回失败的节点及其错误。
func (f *Fleet) Each(ctx context.Context, fn func(ctx context.Context, n *Node) error) map[string]error {
	var (
		mu     sync.Mutex
		failed = map[string]error{}
		wg     sync.WaitGroup
	)
	for _, n := range f.Nodes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var err error
			select {
			case f.sem <- struct{}{}:
				err = fn(ctx, n)
				<-f.sem
			case <-ctx.Done():
				err = ctx.Err()
			}
			if err != nil {
				mu.Lock()
				failed[n.Entry.NodeID] = err
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return failed
}
