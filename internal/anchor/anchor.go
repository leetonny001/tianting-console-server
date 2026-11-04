// Package anchor 是审计链的外部锚定（PRD-admin F-CON-08 规则 7）。
//
// 写和读分成两个接口、两份凭证：服务进程只拿写入凭证，只有校验命令拿读取凭证。
// 校验比对的是外部存储，不是库里的 audit.anchors：能改审计表的人同样能改那张表。
package anchor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"tianting/console/internal/objstore"
)

// Point 是一个锚定点。
type Point struct {
	Seq  int64  `json:"seq"`
	Hash string `json:"hash"`
	TS   int64  `json:"ts"`
}

// Sink 写锚定。
type Sink interface {
	Put(ctx context.Context, p Point) error
}

// Reader 读全部锚定点。同一个 seq 可能有多条：调用方必须逐条比较，不能只信其中一条。
type Reader interface {
	List(ctx context.Context) ([]Point, error)
}

const keyPrefix = "anchors/"

// Key 是对象键：seq 和 hash 都在键里。持有写入凭证的人只能新增对象，覆盖不掉已有的锚定：
// 改过的链写进来的是另一个键，原来的对象还在，校验时两条都要匹配。
func Key(p Point) string { return fmt.Sprintf("%s%020d-%s.json", keyPrefix, p.Seq, p.Hash) }

// ParseKey 从对象键还原 seq 和 hash。
func ParseKey(key string) (Point, bool) {
	s, ok := strings.CutPrefix(key, keyPrefix)
	if !ok {
		return Point{}, false
	}
	s, ok = strings.CutSuffix(s, ".json")
	if !ok {
		return Point{}, false
	}
	seqText, hash, ok := strings.Cut(s, "-")
	if !ok {
		return Point{}, false
	}
	seq, err := strconv.ParseInt(seqText, 10, 64)
	if err != nil || seq <= 0 || hash == "" {
		return Point{}, false
	}
	return Point{Seq: seq, Hash: hash}, true
}

// S3 把锚定写进 Object Lock 桶。
type S3 struct {
	Store  *objstore.Store
	Retain time.Duration
}

// Put 写一个锚定对象并锁定。
func (s *S3) Put(ctx context.Context, p Point) error {
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return s.Store.Put(ctx, Key(p), bytes.NewReader(body), time.Now().Add(s.Retain))
}

// List 列举对象键。键里已经有 seq 和 hash，不用逐个读对象。
func (s *S3) List(ctx context.Context) ([]Point, error) {
	keys, err := s.Store.List(ctx, keyPrefix)
	if err != nil {
		return nil, err
	}
	out := make([]Point, 0, len(keys))
	for _, k := range keys {
		p, ok := ParseKey(k)
		if !ok {
			return nil, fmt.Errorf("unexpected object in anchor store: %q", k)
		}
		out = append(out, p)
	}
	return out, nil
}

// HTTP 把锚定写给日志平台：POST 一条 JSON；校验命令 GET 同一地址，返回 JSON 数组。
type HTTP struct {
	URL    string
	Token  string // Authorization: Bearer
	Client *http.Client
}

func (h *HTTP) client() *http.Client {
	if h.Client != nil {
		return h.Client
	}
	return &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (h *HTTP) do(ctx context.Context, method string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, h.URL, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("invalid anchor URL")
	}
	req.Header.Set("Content-Type", "application/json")
	if h.Token != "" {
		req.Header.Set("Authorization", "Bearer "+h.Token)
	}
	resp, err := h.client().Do(req)
	if err != nil {
		return nil, errors.New("anchor endpoint is not reachable")
	}
	return resp, nil
}

// Put 发送一个锚定点。
func (h *HTTP) Put(ctx context.Context, p Point) error {
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	resp, err := h.do(ctx, http.MethodPost, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("anchor endpoint returned %d", resp.StatusCode)
	}
	return nil
}

// List 读全部锚定点。
func (h *HTTP) List(ctx context.Context) ([]Point, error) {
	resp, err := h.do(ctx, http.MethodGet, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("anchor endpoint returned %d", resp.StatusCode)
	}
	var out []Point
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256<<20)).Decode(&out); err != nil {
		return nil, errors.New("anchor endpoint returned invalid JSON")
	}
	return out, nil
}
