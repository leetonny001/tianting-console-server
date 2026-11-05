package pushtpl

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

const notice = `{"notice":{"type":"object","title":"公告","required":["title","text"],"additionalProperties":false,
"properties":{"title":{"type":"string","minLength":1,"maxLength":5},"text":{"type":"string"},"level":{"enum":["info","warn"],"type":"string"},
"n":{"type":"integer","minimum":1,"maximum":9007199254740993},"tags":{"type":"array","items":{"type":"string","pattern":"^[a-z]+$"},"maxItems":2},"ok":{"type":["boolean","null"]}}}}`

func TestValidate(t *testing.T) {
	s, err := Parse([]byte(notice))
	if err != nil {
		t.Fatal(err)
	}
	tpl := s.Get("notice")
	if tpl == nil || tpl.Title != "公告" || s.Get("nope") != nil {
		t.Fatalf("get: %+v", tpl)
	}
	for _, good := range []string{
		`{"title":"你好世界啊","text":"x"}`, // maxLength 按码点，不按字节
		`{"title":"a","text":"","level":"warn","n":9007199254740993,"tags":["a","b"],"ok":null}`,
		`{"title":"a","text":"","n":2.0,"ok":true}`,
	} {
		if err := tpl.Validate([]byte(good)); err != nil {
			t.Errorf("%s: %v", good, err)
		}
	}
	for _, c := range []struct{ data, rule string }{
		{`{"text":"x"}`, "required"},
		{`{"title":"","text":"x"}`, "minLength"},
		{`{"title":"123456","text":"x"}`, "maxLength"},
		{`{"title":1,"text":"x"}`, "type"},
		{`{"title":"a","text":"x","level":"err"}`, "enum"},
		{`{"title":"a","text":"x","n":0}`, "minimum"},
		{`{"title":"a","text":"x","n":9007199254740994}`, "maximum"},
		{`{"title":"a","text":"x","n":1.5}`, "type"},
		{`{"title":"a","text":"x","tags":["A"]}`, "pattern"},
		{`{"title":"a","text":"x","tags":["a","b","c"]}`, "maxItems"},
		{`{"title":"a","text":"x","SECRETKEY":1}`, "additionalProperties"},
		{`[]`, "type"},
	} {
		err := tpl.Validate([]byte(c.data))
		var fe *FieldError
		if !errors.As(err, &fe) || fe.Rule != c.rule {
			t.Errorf("%s: %v, want %s", c.data, err, c.rule)
			continue
		}
		if strings.Contains(err.Error(), "SECRETKEY") || strings.Contains(err.Error(), "123456") {
			t.Errorf("error carries the content: %v", err)
		}
	}
	if err := tpl.Validate([]byte(`{"title":"a","text":"x"} {}`)); err == nil {
		t.Error("trailing content accepted")
	}
}

// 不认识的关键字不能被悄悄忽略，否则模板以为校验了、其实没有。
func TestRejectsWhatItCannotEnforce(t *testing.T) {
	for _, bad := range []string{
		`[]`, `{}`, `{"":{"type":"object"}}`,
		`{"notice":{"properties":{}}}`,
		`{"notice":{"type":"string"}}`,
		`{"notice":{"type":"object","oneOf":[]}}`,
		`{"notice":{"type":"object","properties":{"a":{"type":"string","format":"email"}}}}`,
		`{"notice":{"type":"object","properties":{"a":{"type":"strng"}}}}`,
		`{"notice":{"type":"object","properties":{"a":{"type":"string","pattern":"("}}}}`,
		`{"notice":{"type":"object","properties":{"a":{"type":"string","enum":[{}]}}}}`,
		`{"` + strings.Repeat("x", 65) + `":{"type":"object"}}`,
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	var nilSet *Set
	if nilSet.Get("x") != nil || nilSet.List() != nil {
		t.Error("nil set")
	}
}

// 部署示例要能加载，type 要和 im-server 调用方的 pushTypes 示例对得上（im-mvp/deploy）。
func TestDeployExampleLoads(t *testing.T) {
	s, err := Load("../../deploy/push-templates.example.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, typ := range []string{"notice", "activity"} {
		if s.Get(typ) == nil {
			t.Errorf("no template %s", typ)
		}
	}
	raw, _ := os.ReadFile("../../deploy/push-templates.example.json")
	if !json.Valid(raw) {
		t.Error("invalid JSON")
	}
}
