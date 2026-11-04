package apierr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"testing"
)

// console-server 产生的每个码都在 errors.json 的 console 通道里，名称和 HTTP 状态一致；反过来也一样。
func TestConsoleCodesMatchErrorsJSON(t *testing.T) {
	raw, err := os.ReadFile("../../protocol/errors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Errors []struct {
			Code  int      `json:"code"`
			Name  string   `json:"name"`
			HTTP  *int     `json:"http"`
			Scope []string `json:"scope"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	seen := map[int]bool{}
	for _, e := range f.Errors {
		if !slices.Contains(e.Scope, "console") {
			continue
		}
		seen[e.Code] = true
		got, ok := codes[e.Code]
		if !ok {
			t.Errorf("errors.json has console code %d %s, Go does not", e.Code, e.Name)
			continue
		}
		if e.HTTP == nil || got.name != e.Name || got.http != *e.HTTP {
			t.Errorf("%d: Go %+v, errors.json %s %v", e.Code, got, e.Name, e.HTTP)
		}
	}
	for code, i := range codes {
		if !seen[code] {
			t.Errorf("Go defines %d %s, errors.json console scope does not", code, i.name)
		}
	}
}

func TestWrite(t *testing.T) {
	w := httptest.NewRecorder()
	Write(w, New(StepUpRequired, "need %s", "totp"))
	if w.Code != http.StatusForbidden || w.Body.String() != "{\"code\":4038,\"msg\":\"need totp\"}\n" {
		t.Errorf("%d %s", w.Code, w.Body)
	}
	if HTTPStatus(4043) != 404 || HTTPStatus(4135) != 413 {
		t.Errorf("fallback: %d %d", HTTPStatus(4043), HTTPStatus(4135))
	}
}
