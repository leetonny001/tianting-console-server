package e2e

// im-server 打开文件功能（IM_FILES_ENABLED）时要的对象存储：只为 CS-201 的端到端用例造文件消息。
// 和 tianting-web/e2e/fake_s3.py 的做法相同（path-style，不校验签名），只做 im-server 和上传用到的操作：
// PUT（含带条件的复制）、HEAD、GET（Range、If-Match、response-content-*）、DELETE、ListObjectsV2。
// console 自己的 internal/objstore/objstoretest 是审计锚点用的（校验签名、Object Lock），不支持复制，所以不复用。

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type fakeS3Object struct {
	body  []byte
	ctype string
	etag  string
}

type fakeS3 struct {
	srv  *httptest.Server
	mu   sync.Mutex
	objs map[string]fakeS3Object // bucket + "/" + key
}

func newFakeS3(t *testing.T) *fakeS3 {
	t.Helper()
	f := &fakeS3{objs: map[string]fakeS3Object{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

// env 是 im-server 打开文件功能要的变量。凭证只是占位，假 S3 不校验。
func (f *fakeS3) env() []string {
	return []string{
		"IM_FILES_ENABLED=1",
		"IM_OBJSTORE_ENDPOINT=" + f.srv.URL,
		"IM_OBJSTORE_REGION=us-east-1",
		"IM_OBJSTORE_BUCKET=chat",
		"IM_OBJSTORE_PUBLIC_BUCKET=avatars",
		"IM_OBJSTORE_PUBLIC_BASE_URL=" + f.srv.URL + "/avatars",
		"IM_OBJSTORE_ACCESS_KEY=console-e2e-fake",
		"IM_OBJSTORE_SECRET_KEY=console-e2e-fake-not-a-secret",
	}
}

func splitObject(p string) (bucket, key string) {
	p, _ = url.PathUnescape(p)
	bucket, key, _ = strings.Cut(strings.TrimPrefix(p, "/"), "/")
	return bucket, key
}

func etagOf(b []byte) string {
	sum := md5.Sum(b)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

func s3Error(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, "<Error><Code>%s</Code></Error>", code)
}

func (f *fakeS3) handle(w http.ResponseWriter, r *http.Request) {
	bucket, key := splitObject(r.URL.Path)
	q := r.URL.Query()
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodPut && r.Header.Get("x-amz-copy-source") != "":
		sb, sk := splitObject(r.Header.Get("x-amz-copy-source"))
		cur, ok := f.objs[sb+"/"+sk]
		if !ok {
			s3Error(w, 404, "NoSuchKey")
			return
		}
		if want := r.Header.Get("x-amz-copy-source-if-match"); want != "" && want != cur.etag {
			s3Error(w, 412, "PreconditionFailed")
			return
		}
		ctype := r.Header.Get("Content-Type")
		if ctype == "" {
			ctype = cur.ctype
		}
		obj := fakeS3Object{body: cur.body, ctype: ctype, etag: etagOf(append(append([]byte{}, cur.body...), "copy"...))}
		f.objs[bucket+"/"+key] = obj
		w.Header().Set("Content-Type", "application/xml")
		out, _ := xml.Marshal(struct {
			XMLName xml.Name `xml:"CopyObjectResult"`
			ETag    string
		}{ETag: obj.etag})
		_, _ = w.Write(out)
	case r.Method == http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		ctype := r.Header.Get("Content-Type")
		if ctype == "" {
			ctype = "application/octet-stream"
		}
		obj := fakeS3Object{body: body, ctype: ctype, etag: etagOf(body)}
		f.objs[bucket+"/"+key] = obj
		w.Header().Set("ETag", obj.etag)
	case r.Method == http.MethodDelete:
		delete(f.objs, bucket+"/"+key)
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodGet && key == "" && q.Has("list-type"):
		prefix := q.Get("prefix")
		var keys []string
		for k := range f.objs {
			if b, rest, _ := strings.Cut(k, "/"); b == bucket && strings.HasPrefix(rest, prefix) {
				keys = append(keys, rest)
			}
		}
		sort.Strings(keys)
		type content struct{ Key string }
		out, _ := xml.Marshal(struct {
			XMLName     xml.Name `xml:"ListBucketResult"`
			IsTruncated bool
			Contents    []content
		}{Contents: func() []content {
			c := make([]content, len(keys))
			for i, k := range keys {
				c[i] = content{k}
			}
			return c
		}()})
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write(out)
	case r.Method == http.MethodGet || r.Method == http.MethodHead:
		cur, ok := f.objs[bucket+"/"+key]
		if !ok {
			if r.Method == http.MethodHead {
				w.WriteHeader(404)
				return
			}
			s3Error(w, 404, "NoSuchKey")
			return
		}
		if want := r.Header.Get("If-Match"); want != "" && want != cur.etag {
			s3Error(w, 412, "PreconditionFailed")
			return
		}
		body, status := cur.body, http.StatusOK
		if rng := r.Header.Get("Range"); strings.HasPrefix(rng, "bytes=") {
			a, b, _ := strings.Cut(strings.TrimPrefix(rng, "bytes="), "-")
			start, _ := strconv.Atoi(a)
			end := len(body) - 1
			if n, err := strconv.Atoi(b); err == nil && n < end {
				end = n
			}
			if start > end {
				start = end + 1
			}
			body, status = body[start:end+1], http.StatusPartialContent
		}
		ctype := cur.ctype
		if v := q.Get("response-content-type"); v != "" {
			ctype = v
		}
		w.Header().Set("ETag", cur.etag)
		w.Header().Set("Content-Type", ctype)
		if v := q.Get("response-content-disposition"); v != "" {
			w.Header().Set("Content-Disposition", v)
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(status)
		if r.Method == http.MethodGet {
			_, _ = w.Write(body)
		}
	default:
		s3Error(w, 405, "MethodNotAllowed")
	}
}
