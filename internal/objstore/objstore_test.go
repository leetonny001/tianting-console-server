package objstore_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"

	. "tianting/console/internal/objstore"
	"tianting/console/internal/objstore/objstoretest"
)

const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// AWS 公开的 SigV4 向量（get-vanilla），和 S3 文档里 GET Object 的例子。这两个结果不是这份代码算出来的。
func TestSignV4Vectors(t *testing.T) {
	ts := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	got := SignV4(SignInput{
		Method: "GET", Path: "/", Headers: map[string]string{"host": "example.amazonaws.com", "x-amz-date": "20150830T123600Z"},
		PayloadSHA: emptySHA256, Region: "us-east-1", Service: "service", AccessKey: "AKIDEXAMPLE",
		SecretKey: []byte("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"), Time: ts,
	})
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if got != want {
		t.Errorf("get-vanilla:\n got %s\nwant %s", got, want)
	}
	got = SignV4(SignInput{
		Method: "GET", Path: "/test.txt", Headers: map[string]string{
			"host": "examplebucket.s3.amazonaws.com", "range": "bytes=0-9", "x-amz-content-sha256": emptySHA256, "x-amz-date": "20130524T000000Z",
		},
		PayloadSHA: emptySHA256, Region: "us-east-1", Service: "s3", AccessKey: "AKIAIOSFODNN7EXAMPLE",
		SecretKey: []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"), Time: time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC),
	})
	if !strings.HasSuffix(got, "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41") {
		t.Errorf("s3 get object: %s", got)
	}
}

func TestCanonicalQuery(t *testing.T) {
	got := CanonicalQuery(url.Values{"prefix": {"a b/c"}, "list-type": {"2"}})
	if got != "list-type=2&prefix=a%20b%2Fc" {
		t.Error(got)
	}
	if EscapePath("/b/a b/年.json") != "/b/a%20b/%E5%B9%B4.json" {
		t.Error(EscapePath("/b/a b/年.json"))
	}
}

func TestStoreAgainstFake(t *testing.T) {
	f := objstoretest.New(t, "bkt")
	ctx := context.Background()
	w := New(Config{Endpoint: f.URL(), Bucket: "bkt", Prefix: "pre", AccessKey: f.Writer.AccessKey, SecretKey: []byte(f.Writer.SecretKey)})
	r := New(Config{Endpoint: f.URL(), Bucket: "bkt", Prefix: "pre", AccessKey: f.Reader.AccessKey, SecretKey: []byte(f.Reader.SecretKey)})
	until := time.Now().Add(time.Hour)
	f.PageSize = 2
	for _, k := range []string{"a/1", "a/2", "a/3", "b/1"} {
		if err := w.Put(ctx, k, strings.NewReader("v:"+k), until); err != nil {
			t.Fatal(err)
		}
	}
	keys, err := r.List(ctx, "a/")
	if err != nil || len(keys) != 3 || keys[2] != "a/3" {
		t.Fatalf("list = %v %v", keys, err)
	}
	rc, err := r.Get(ctx, "a/2")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(rc)
	rc.Close()
	if string(data) != "v:a/2" {
		t.Errorf("get = %q", data)
	}
	// 写入凭证只能写；读取凭证只能读；谁都删不掉。
	if _, err := w.List(ctx, "a/"); !IsDenied(err) {
		t.Errorf("writer list: %v", err)
	}
	if _, err := w.Get(ctx, "a/2"); !IsDenied(err) {
		t.Errorf("writer get: %v", err)
	}
	if err := r.Put(ctx, "x", bytes.NewReader(nil), until); !IsDenied(err) {
		t.Errorf("reader put: %v", err)
	}
	for _, s := range []*Store{w, r} {
		if err := s.Delete(ctx, "a/2"); !IsDenied(err) {
			t.Errorf("delete: %v", err)
		}
	}
	// 凭证不对：签名校验失败。
	bad := New(Config{Endpoint: f.URL(), Bucket: "bkt", AccessKey: f.Writer.AccessKey, SecretKey: []byte("wrong")})
	err = bad.Put(ctx, "y", strings.NewReader("z"), until)
	var se *Error
	if !errors.As(err, &se) || se.Code != "SignatureDoesNotMatch" {
		t.Errorf("bad secret: %v", err)
	}
	// 错误里没有密钥。
	if strings.Contains(err.Error(), f.Writer.SecretKey) {
		t.Error("secret in error")
	}
	f.SetDown(true)
	if err := w.Put(ctx, "z", strings.NewReader("z"), until); err == nil {
		t.Error("down store accepted a write")
	}
}
