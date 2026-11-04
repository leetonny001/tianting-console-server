// Package objstore 是 S3 兼容对象存储的最小客户端：写入（带 Object Lock）、列举、读取、删除。
//
// 只用来存审计锚定和归档（PRD-admin F-CON-08 规则 7、F-CON-09 规则 6）。自己实现 SigV4 而不引入 SDK：
// 用到的接口只有四个，依赖越少，审计链路的供应链风险越小；签名用 AWS 公开的向量测试。
package objstore

import (
	"context"
	"crypto/hmac"
	"crypto/md5" // #nosec G501 -- S3 协议要求带 Object Lock 的写入有 Content-MD5，这里只做传输校验
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"tianting/console/internal/secret"
)

// Config 是一个桶和一份凭证。Prefix 是对象键前缀，可以为空。
type Config struct {
	Endpoint  string // https://s3.example.internal
	Region    string // 默认 us-east-1
	Bucket    string
	Prefix    string
	AccessKey string
	SecretKey secret.Bytes
	HTTP      *http.Client
}

// Store 是对象存储客户端。签名永远用真实时间：对象存储会拒绝时间偏差大的请求，[C 钟] 只影响业务时间。
type Store struct{ c Config }

// New 创建客户端。
func New(c Config) *Store {
	if c.Region == "" {
		c.Region = "us-east-1"
	}
	if c.HTTP == nil {
		c.HTTP = &http.Client{Timeout: 5 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	c.Endpoint = strings.TrimRight(c.Endpoint, "/")
	c.Prefix = strings.Trim(c.Prefix, "/")
	return &Store{c: c}
}

// Error 是对象存储返回的错误。只有状态码和错误名，不带请求头和签名。
type Error struct {
	Status int
	Code   string
}

func (e *Error) Error() string { return fmt.Sprintf("object store: %d %s", e.Status, e.Code) }

// IsDenied 判断是否权限错误。
func IsDenied(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == http.StatusForbidden
}

func (s *Store) fullKey(key string) string {
	if s.c.Prefix == "" {
		return key
	}
	return s.c.Prefix + "/" + key
}

// Put 写入一个对象并锁定到 retainUntil（COMPLIANCE 模式：到期前任何凭证都删不掉）。
// 桶没有开启 Object Lock 时对象存储会拒绝，这正是想要的：不会静默写进一个可删除的桶。
func (s *Store) Put(ctx context.Context, key string, body io.ReadSeeker, retainUntil time.Time) error {
	sum, md, size, err := digest(body)
	if err != nil {
		return err
	}
	h := map[string]string{
		"content-md5":                         md,
		"x-amz-object-lock-mode":              "COMPLIANCE",
		"x-amz-object-lock-retain-until-date": retainUntil.UTC().Format("2006-01-02T15:04:05Z"),
	}
	resp, err := s.do(ctx, http.MethodPut, s.fullKey(key), nil, h, sum, body, size)
	if err != nil {
		return err
	}
	return drain(resp)
}

func digest(body io.ReadSeeker) (shaHex, md5B64 string, size int64, err error) {
	sh, md := sha256.New(), md5.New() // #nosec G401 -- 见包顶部 import 的说明
	size, err = io.Copy(io.MultiWriter(sh, md), body)
	if err != nil {
		return "", "", 0, err
	}
	if _, err := body.Seek(0, io.SeekStart); err != nil {
		return "", "", 0, err
	}
	return hex.EncodeToString(sh.Sum(nil)), base64.StdEncoding.EncodeToString(md.Sum(nil)), size, nil
}

// Get 读一个对象，调用方负责关闭。
func (s *Store) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	resp, err := s.do(ctx, http.MethodGet, s.fullKey(key), nil, nil, emptySHA256, nil, 0)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, drain(resp)
	}
	return resp.Body, nil
}

// Delete 删除一个对象。服务本身不会调用：测试用它断言写入凭证删不掉锚定（AC-CON-08-12）。
func (s *Store) Delete(ctx context.Context, key string) error {
	resp, err := s.do(ctx, http.MethodDelete, s.fullKey(key), nil, nil, emptySHA256, nil, 0)
	if err != nil {
		return err
	}
	return drain(resp)
}

// List 列出 prefix 下全部对象键（去掉配置的前缀），自动翻页。
func (s *Store) List(ctx context.Context, prefix string) ([]string, error) {
	var out []string
	token := ""
	for {
		q := url.Values{"list-type": {"2"}, "prefix": {s.fullKey(prefix)}}
		if token != "" {
			q.Set("continuation-token", token)
		}
		resp, err := s.do(ctx, http.MethodGet, "", q, nil, emptySHA256, nil, 0)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode/100 != 2 {
			return nil, drain(resp)
		}
		var page struct {
			IsTruncated           bool   `xml:"IsTruncated"`
			NextContinuationToken string `xml:"NextContinuationToken"`
			Contents              []struct {
				Key string `xml:"Key"`
			} `xml:"Contents"`
		}
		err = xml.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&page)
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("object store: invalid list response: %w", err)
		}
		for _, c := range page.Contents {
			k := c.Key
			if s.c.Prefix != "" {
				k = strings.TrimPrefix(k, s.c.Prefix+"/")
			}
			out = append(out, k)
		}
		if !page.IsTruncated {
			return out, nil
		}
		if page.NextContinuationToken == "" {
			return nil, errors.New("object store: truncated list without continuation token")
		}
		token = page.NextContinuationToken
	}
}

// drain 读完响应体；非 2xx 转成 *Error。
func drain(resp *http.Response) error {
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 == 2 {
		return nil
	}
	var body struct {
		Code string `xml:"Code"`
	}
	_ = xml.Unmarshal(data, &body)
	return &Error{Status: resp.StatusCode, Code: body.Code}
}

const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func (s *Store) do(ctx context.Context, method, key string, query url.Values, headers map[string]string, payloadSHA string, body io.Reader, size int64) (*http.Response, error) {
	path := "/" + s.c.Bucket
	if key != "" {
		path += "/" + key
	}
	target := s.c.Endpoint + EscapePath(path)
	if len(query) > 0 {
		target += "?" + CanonicalQuery(query)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.ContentLength = size
	}
	now := time.Now().UTC()
	signed := map[string]string{"host": req.URL.Host, "x-amz-date": now.Format("20060102T150405Z"), "x-amz-content-sha256": payloadSHA}
	for k, v := range headers {
		signed[k] = v
	}
	for k, v := range signed {
		if k != "host" {
			req.Header.Set(k, v)
		}
	}
	req.Header.Set("Authorization", SignV4(SignInput{
		Method: method, Path: path, Query: query, Headers: signed, PayloadSHA: payloadSHA,
		Region: s.c.Region, Service: "s3", AccessKey: s.c.AccessKey, SecretKey: s.c.SecretKey, Time: now,
	}))
	resp, err := s.c.HTTP.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) { // 只留原因，地址由配置决定、没有必要进日志
			return nil, fmt.Errorf("object store: %w", ue.Err)
		}
		return nil, err
	}
	if resp.StatusCode/100 != 2 && method != http.MethodGet {
		return resp, drain(resp)
	}
	return resp, nil
}

// SignInput 是一次 SigV4 签名的输入。Path 没有转义；Headers 的键是小写。
type SignInput struct {
	Method, Path    string
	Query           url.Values
	Headers         map[string]string
	PayloadSHA      string
	Region, Service string
	AccessKey       string
	SecretKey       []byte
	Time            time.Time
}

// SignV4 返回 Authorization 头（AWS Signature Version 4，单次路径转义，S3 的规则）。
func SignV4(in SignInput) string {
	names := make([]string, 0, len(in.Headers))
	for k := range in.Headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var canon strings.Builder
	for _, k := range names {
		canon.WriteString(k + ":" + strings.TrimSpace(in.Headers[k]) + "\n")
	}
	signedHeaders := strings.Join(names, ";")
	canonical := strings.Join([]string{in.Method, EscapePath(in.Path), CanonicalQuery(in.Query), canon.String(), signedHeaders, in.PayloadSHA}, "\n")
	date := in.Time.UTC().Format("20060102")
	scope := date + "/" + in.Region + "/" + in.Service + "/aws4_request"
	sum := sha256.Sum256([]byte(canonical))
	toSign := "AWS4-HMAC-SHA256\n" + in.Time.UTC().Format("20060102T150405Z") + "\n" + scope + "\n" + hex.EncodeToString(sum[:])
	key := hmacSHA256(append([]byte("AWS4"), in.SecretKey...), date)
	key = hmacSHA256(key, in.Region)
	key = hmacSHA256(key, in.Service)
	key = hmacSHA256(key, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(key, toSign))
	return "AWS4-HMAC-SHA256 Credential=" + in.AccessKey + "/" + scope + ", SignedHeaders=" + signedHeaders + ", Signature=" + sig
}

func hmacSHA256(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

// EscapePath 按 SigV4 规则转义路径：只保留非保留字符和 /。
func EscapePath(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == '/' {
			b.WriteByte(c)
		} else {
			b.WriteString(escapeByte(c))
		}
	}
	return b.String()
}

func escapeByte(c byte) string {
	if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~' {
		return string(c)
	}
	return "%" + strings.ToUpper(strconv.FormatInt(int64(c)+256, 16)[1:])
}

func escapeQuery(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		b.WriteString(escapeByte(s[i]))
	}
	return b.String()
}

// CanonicalQuery 是按键排序、严格转义的查询串。
func CanonicalQuery(q url.Values) string {
	parts := make([]string, 0, len(q))
	for k, vs := range q {
		for _, v := range vs {
			parts = append(parts, escapeQuery(k)+"="+escapeQuery(v))
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, "&")
}
