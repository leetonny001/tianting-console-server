// Package objstoretest 是测试用的 WORM 桶：校验 SigV4 签名、凭证权限和 Object Lock 头，所有删除都被拒绝。
// CI 另外跑一次真实的 MinIO（见 tools/minio-test.sh）；这个假桶让没有容器的环境也能测全部逻辑。
package objstoretest

import (
	"crypto/md5" // #nosec G501 -- 校验协议里的 Content-MD5
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"tianting/console/internal/objstore"
)

// Cred 是一份凭证。
type Cred struct{ AccessKey, SecretKey string }

// Object 是桶里的对象。
type Object struct {
	Body        []byte
	RetainUntil time.Time
	Mode        string
}

// Server 是假桶。
type Server struct {
	Writer, Reader Cred
	ReadWrite      Cred // 能读能写、不能删：归档凭证要读回核对
	PageSize       int  // 每页最多几个键，0 表示不限

	t      *testing.T
	bucket string
	srv    *httptest.Server
	mu     sync.Mutex
	objs   map[string]Object
	down   bool
}

// New 启动假桶。Writer 只能写，Reader 只能读，ReadWrite 两者都行；谁都不能删。
func New(t *testing.T, bucket string) *Server {
	s := &Server{
		t: t, bucket: bucket, objs: map[string]Object{},
		Writer: Cred{"writer-" + bucket, "writer-secret-" + bucket}, Reader: Cred{"reader-" + bucket, "reader-secret-" + bucket},
		ReadWrite: Cred{"rw-" + bucket, "rw-secret-" + bucket},
	}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.srv.Close)
	return s
}

// URL 是 endpoint。
func (s *Server) URL() string { return s.srv.URL }

// SetDown 让桶不可用。
func (s *Server) SetDown(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.down = v
}

// Objects 返回全部对象的副本。
func (s *Server) Objects() map[string]Object {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]Object, len(s.objs))
	for k, v := range s.objs {
		out[k] = v
	}
	return out
}

func fail(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, "<Error><Code>%s</Code></Error>", code)
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	down := s.down
	s.mu.Unlock()
	if down {
		fail(w, http.StatusServiceUnavailable, "ServiceUnavailable")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		fail(w, http.StatusBadRequest, "IncompleteBody")
		return
	}
	cred, ok := s.authenticate(w, r, body)
	if !ok {
		return
	}
	key := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/"+s.bucket), "/")
	switch {
	case r.Method == http.MethodPut:
		s.put(w, r, cred, key, body)
	case r.Method == http.MethodDelete:
		fail(w, http.StatusForbidden, "AccessDenied") // 写入凭证没有删除权限；读取凭证也没有；对象被锁定
	case r.Method == http.MethodGet && key == "":
		s.list(w, r, cred)
	case r.Method == http.MethodGet:
		if cred == s.Writer {
			fail(w, http.StatusForbidden, "AccessDenied")
			return
		}
		s.mu.Lock()
		o, found := s.objs[key]
		s.mu.Unlock()
		if !found {
			fail(w, http.StatusNotFound, "NoSuchKey")
			return
		}
		_, _ = w.Write(o.Body)
	default:
		fail(w, http.StatusMethodNotAllowed, "MethodNotAllowed")
	}
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request, body []byte) (Cred, bool) {
	auth := r.Header.Get("Authorization")
	var access, signedHeaders string
	for _, part := range strings.Split(strings.TrimPrefix(auth, "AWS4-HMAC-SHA256 "), ", ") {
		if v, ok := strings.CutPrefix(part, "Credential="); ok {
			access, _, _ = strings.Cut(v, "/")
		}
		if v, ok := strings.CutPrefix(part, "SignedHeaders="); ok {
			signedHeaders = v
		}
	}
	var cred Cred
	switch access {
	case s.Writer.AccessKey:
		cred = s.Writer
	case s.Reader.AccessKey:
		cred = s.Reader
	case s.ReadWrite.AccessKey:
		cred = s.ReadWrite
	default:
		fail(w, http.StatusForbidden, "InvalidAccessKeyId")
		return Cred{}, false
	}
	sum := sha256.Sum256(body)
	if r.Header.Get("X-Amz-Content-Sha256") != hex.EncodeToString(sum[:]) {
		fail(w, http.StatusBadRequest, "XAmzContentSHA256Mismatch")
		return Cred{}, false
	}
	ts, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	if err != nil || time.Since(ts).Abs() > 15*time.Minute { // 和真实存储一样拒绝时间偏差大的请求
		fail(w, http.StatusForbidden, "RequestTimeTooSkewed")
		return Cred{}, false
	}
	headers := map[string]string{}
	for _, name := range strings.Split(signedHeaders, ";") {
		if name == "host" {
			headers[name] = r.Host
		} else {
			headers[name] = r.Header.Get(name)
		}
	}
	want := objstore.SignV4(objstore.SignInput{
		Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Headers: headers, PayloadSHA: hex.EncodeToString(sum[:]),
		Region: "us-east-1", Service: "s3", AccessKey: cred.AccessKey, SecretKey: []byte(cred.SecretKey), Time: ts,
	})
	if want != auth {
		fail(w, http.StatusForbidden, "SignatureDoesNotMatch")
		return Cred{}, false
	}
	return cred, true
}

func (s *Server) put(w http.ResponseWriter, r *http.Request, cred Cred, key string, body []byte) {
	if cred == s.Reader {
		fail(w, http.StatusForbidden, "AccessDenied")
		return
	}
	md := md5.Sum(body) // #nosec G401 -- 协议校验
	if r.Header.Get("Content-MD5") != base64.StdEncoding.EncodeToString(md[:]) {
		fail(w, http.StatusBadRequest, "BadDigest")
		return
	}
	until, err := time.Parse("2006-01-02T15:04:05Z", r.Header.Get("X-Amz-Object-Lock-Retain-Until-Date"))
	mode := r.Header.Get("X-Amz-Object-Lock-Mode")
	if err != nil || mode != "COMPLIANCE" || !until.After(time.Now()) {
		fail(w, http.StatusBadRequest, "InvalidRequest")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objs[key] = Object{Body: body, RetainUntil: until, Mode: mode}
}

func (s *Server) list(w http.ResponseWriter, r *http.Request, cred Cred) {
	if cred == s.Writer {
		fail(w, http.StatusForbidden, "AccessDenied")
		return
	}
	q := r.URL.Query()
	start, _ := strconv.Atoi(q.Get("continuation-token"))
	s.mu.Lock()
	var keys []string
	for k := range s.objs {
		if strings.HasPrefix(k, q.Get("prefix")) {
			keys = append(keys, k)
		}
	}
	page := s.PageSize
	s.mu.Unlock()
	sort.Strings(keys)
	type content struct{ Key string }
	out := struct {
		XMLName               xml.Name `xml:"ListBucketResult"`
		IsTruncated           bool
		NextContinuationToken string `xml:",omitempty"`
		Contents              []content
	}{}
	for i := start; i < len(keys); i++ {
		if page > 0 && i-start == page {
			out.IsTruncated, out.NextContinuationToken = true, strconv.Itoa(i)
			break
		}
		out.Contents = append(out.Contents, content{keys[i]})
	}
	w.Header().Set("Content-Type", "application/xml")
	_ = xml.NewEncoder(w).Encode(out)
}
