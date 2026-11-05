// Package pushtpl 是系统通知的模板（PRD-admin F-ADM-50 规则 2）：type → data 的 JSON Schema。
//
// 只实现模板用得到的 JSON Schema 子集。文件里出现不认识的关键字时启动失败，不会悄悄不校验。
// 错误信息只有字段路径和规则名，不带字段值：通知内容不进日志。
package pushtpl

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"regexp"
	"slices"
	"sort"
	"unicode/utf8"
)

const maxTypeLen = 64 // 和 im-server 的 type、pushTypes 上限一致（PRD-live F-PUSH-02 规则 2）

// Template 是一个模板。
type Template struct {
	Type   string
	Title  string
	Schema json.RawMessage // 原样给前端渲染表单
	root   *node
}

// Set 是全部模板。nil 表示没有配置。
type Set struct {
	list []*Template
}

// Load 读模板文件。
func Load(path string) (*Set, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- 路径来自部署配置 CON_PUSH_TEMPLATES
	if err != nil {
		return nil, fmt.Errorf("read templates: %w", err)
	}
	return Parse(raw)
}

// Parse 解析 {type: schema}。
func Parse(raw []byte) (*Set, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, errors.New("templates must be a JSON object of type to schema")
	}
	if len(top) == 0 {
		return nil, errors.New("templates are empty")
	}
	s := &Set{}
	for typ, schema := range top {
		if n := utf8.RuneCountInString(typ); n < 1 || n > maxTypeLen {
			return nil, fmt.Errorf("template type must be 1..%d characters", maxTypeLen)
		}
		root, err := compile(schema, typ)
		if err != nil {
			return nil, err
		}
		if !slices.Equal(root.types, []string{"object"}) {
			return nil, fmt.Errorf("%s: the root schema must have type object", typ)
		}
		s.list = append(s.list, &Template{Type: typ, Title: root.title, Schema: schema, root: root})
	}
	sort.Slice(s.list, func(i, j int) bool { return s.list[i].Type < s.list[j].Type })
	return s, nil
}

// List 返回全部模板，按 type 排序。
func (s *Set) List() []*Template {
	if s == nil {
		return nil
	}
	return s.list
}

// Get 按 type 取模板，没有时返回 nil。
func (s *Set) Get(typ string) *Template {
	if s == nil {
		return nil
	}
	for _, t := range s.list {
		if t.Type == typ {
			return t
		}
	}
	return nil
}

// Validate 校验 data。错误信息不带值。
func (t *Template) Validate(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber() // 超过 2^53 的整数不能丢精度
	var v any
	if err := dec.Decode(&v); err != nil {
		return errors.New("data is not valid JSON")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("data has trailing content")
	}
	return t.root.check(v, "data")
}

type node struct {
	title      string
	types      []string
	properties map[string]*node
	required   []string
	noExtra    bool // additionalProperties: false
	extra      *node
	items      *node
	enum       []any
	minLength  *int
	maxLength  *int
	pattern    *regexp.Regexp
	minimum    *big.Rat
	maximum    *big.Rat
	minItems   *int
	maxItems   *int
}

var validTypes = []string{"object", "array", "string", "number", "integer", "boolean", "null"}

func compile(raw json.RawMessage, path string) (*node, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var kw map[string]json.RawMessage
	if err := dec.Decode(&kw); err != nil {
		return nil, fmt.Errorf("%s: a schema must be a JSON object", path)
	}
	n := &node{}
	for key, val := range kw {
		if err := n.apply(key, val, path); err != nil {
			return nil, err
		}
	}
	if len(n.types) == 0 {
		return nil, fmt.Errorf("%s: type is required", path)
	}
	return n, nil
}

func (n *node) apply(key string, val json.RawMessage, path string) error {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%s: %s: %s", path, key, fmt.Sprintf(format, args...))
	}
	nonNegative := func() (*int, error) {
		var v int
		if err := json.Unmarshal(val, &v); err != nil || v < 0 {
			return nil, bad("must be a non-negative integer")
		}
		return &v, nil
	}
	var err error
	switch key {
	case "$schema", "$comment", "description", "default", "examples":
	case "title":
		if json.Unmarshal(val, &n.title) != nil {
			return bad("must be a string")
		}
	case "type":
		var one string
		if json.Unmarshal(val, &one) == nil {
			n.types = []string{one}
		} else if json.Unmarshal(val, &n.types) != nil {
			return bad("must be a string or a list of strings")
		}
		for _, t := range n.types {
			if !slices.Contains(validTypes, t) {
				return bad("unknown type")
			}
		}
	case "properties":
		var props map[string]json.RawMessage
		if json.Unmarshal(val, &props) != nil {
			return bad("must be an object")
		}
		n.properties = make(map[string]*node, len(props))
		for name, schema := range props {
			if n.properties[name], err = compile(schema, path+"."+name); err != nil {
				return err
			}
		}
	case "required":
		if json.Unmarshal(val, &n.required) != nil {
			return bad("must be a list of strings")
		}
	case "additionalProperties":
		var allowed bool
		if json.Unmarshal(val, &allowed) == nil {
			n.noExtra = !allowed
		} else if n.extra, err = compile(val, path+".*"); err != nil {
			return err
		}
	case "items":
		if n.items, err = compile(val, path+"[]"); err != nil {
			return err
		}
	case "enum":
		dec := json.NewDecoder(bytes.NewReader(val))
		dec.UseNumber()
		if dec.Decode(&n.enum) != nil || len(n.enum) == 0 {
			return bad("must be a non-empty list")
		}
		for _, v := range n.enum {
			switch v.(type) {
			case string, json.Number, bool, nil:
			default:
				return bad("only scalar values are supported")
			}
		}
	case "minLength":
		n.minLength, err = nonNegative()
	case "maxLength":
		n.maxLength, err = nonNegative()
	case "minItems":
		n.minItems, err = nonNegative()
	case "maxItems":
		n.maxItems, err = nonNegative()
	case "pattern":
		var p string
		if json.Unmarshal(val, &p) != nil {
			return bad("must be a string")
		}
		if n.pattern, err = regexp.Compile(p); err != nil {
			return bad("is not a valid regular expression")
		}
	case "minimum", "maximum":
		r, ok := new(big.Rat).SetString(string(bytes.TrimSpace(val)))
		if !ok {
			return bad("must be a number")
		}
		if key == "minimum" {
			n.minimum = r
		} else {
			n.maximum = r
		}
	default:
		return bad("this keyword is not supported")
	}
	return err
}

func typeOf(v any) string {
	switch v.(type) {
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case json.Number:
		return "number"
	case bool:
		return "boolean"
	}
	return "null"
}

func (n *node) matchesType(v any) bool {
	got := typeOf(v)
	if slices.Contains(n.types, got) {
		return true
	}
	if num, ok := v.(json.Number); ok && slices.Contains(n.types, "integer") {
		r, ok := new(big.Rat).SetString(num.String())
		return ok && r.IsInt()
	}
	return false
}

func scalarEqual(a, b any) bool {
	x, xok := a.(json.Number)
	y, yok := b.(json.Number)
	if xok && yok {
		rx, ok1 := new(big.Rat).SetString(x.String())
		ry, ok2 := new(big.Rat).SetString(y.String())
		return ok1 && ok2 && rx.Cmp(ry) == 0
	}
	return a == b
}

func (n *node) check(v any, path string) error {
	bad := func(rule string) error { return &FieldError{Path: path, Rule: rule} }
	if !n.matchesType(v) {
		return bad("type")
	}
	if n.enum != nil && !slices.ContainsFunc(n.enum, func(e any) bool {
		switch v.(type) {
		case map[string]any, []any:
			return false
		}
		return scalarEqual(e, v)
	}) {
		return bad("enum")
	}
	switch x := v.(type) {
	case string:
		count := utf8.RuneCountInString(x)
		if n.minLength != nil && count < *n.minLength {
			return bad("minLength")
		}
		if n.maxLength != nil && count > *n.maxLength {
			return bad("maxLength")
		}
		if n.pattern != nil && !n.pattern.MatchString(x) {
			return bad("pattern")
		}
	case json.Number:
		r, ok := new(big.Rat).SetString(x.String())
		if !ok {
			return bad("type")
		}
		if n.minimum != nil && r.Cmp(n.minimum) < 0 {
			return bad("minimum")
		}
		if n.maximum != nil && r.Cmp(n.maximum) > 0 {
			return bad("maximum")
		}
	case []any:
		if n.minItems != nil && len(x) < *n.minItems {
			return bad("minItems")
		}
		if n.maxItems != nil && len(x) > *n.maxItems {
			return bad("maxItems")
		}
		if n.items != nil {
			for i, item := range x {
				if err := n.items.check(item, fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
		}
	case map[string]any:
		for _, name := range n.required {
			if _, ok := x[name]; !ok {
				return &FieldError{Path: path + "." + name, Rule: "required"}
			}
		}
		for name, val := range x {
			if p, ok := n.properties[name]; ok {
				if err := p.check(val, path+"."+name); err != nil {
					return err
				}
				continue
			}
			if n.noExtra {
				return &FieldError{Path: path + ".*", Rule: "additionalProperties"} // 键名也是调用方写的内容，不放进错误
			}
			if n.extra != nil {
				if err := n.extra.check(val, path+".*"); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// FieldError 是一处校验失败。Path 是模板里声明过的字段路径。
type FieldError struct {
	Path, Rule string
}

func (e *FieldError) Error() string { return e.Path + " does not satisfy " + e.Rule }
