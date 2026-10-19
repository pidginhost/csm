package learn

import (
	"encoding/json"
	"strings"
	"testing"
)

func digest(c byte) Digest { return Digest(strings.Repeat(string(c), 128)) }

func hit(queried, stored Digest, prob float64, value int64) map[string]any {
	return map[string]any{"queried": queried, "found": true, "digest": stored, "prob": prob, "value": value, "flag": 1, "confirmed": true}
}

func miss(queried Digest) map[string]any {
	return map[string]any{"queried": queried, "found": false, "prob": 0, "value": 0, "flag": 0, "confirmed": false}
}

func reply(t testing.TB, results ...map[string]any) []byte {
	t.Helper()
	list := any(results)
	if len(results) == 0 {
		list = map[string]any{} // rspamd encodes an empty Lua table as {}
	}
	data, err := json.Marshal(map[string]any{"results": list, "errors": map[string]any{}, "complete": true, "distinct": len(results)})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseDigest(t *testing.T) {
	if d, err := ParseDigest(string(digest('a'))); err != nil || d != digest('a') {
		t.Fatalf("valid digest rejected: %v", err)
	}
	for _, s := range []string{"", "abc", strings.Repeat("A", 128), strings.Repeat("a", 127), strings.Repeat("a", 129), strings.Repeat("g", 128)} {
		if _, err := ParseDigest(s); err == nil {
			t.Fatalf("accepted %q", s)
		}
	}
}

func TestParseInspectionHitMiss(t *testing.T) {
	a, b, c := digest('a'), digest('b'), digest('c')
	insp, err := ParseInspection(reply(t, hit(a, c, 0.8, 4), miss(b)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if insp.Distinct != 2 || len(insp.Results) != 2 {
		t.Fatalf("got %+v", insp)
	}
	h, m := insp.Results[0], insp.Results[1]
	if h.Queried != a || h.Stored != c || !h.Found || !h.Confirmed || h.Prob != 0.8 || h.Value != 4 || h.Flag != 1 {
		t.Fatalf("hit %+v", h)
	}
	if m.Queried != b || m.Found || m.Value != 0 || m.Prob != 0 || m.Stored != "" {
		t.Fatalf("miss %+v", m)
	}
	empty, err := ParseInspection(reply(t), nil)
	if err != nil || empty.Distinct != 0 || len(empty.Results) != 0 {
		t.Fatalf("empty reply: %+v %v", empty, err)
	}
	exact, err := ParseInspection(reply(t, hit(a, a, 1, 6), miss(b)), []Digest{a, b, a})
	if err != nil {
		t.Fatal(err)
	}
	if v, present, err := exact.ExactValue(a); err != nil || !present || v != 6 {
		t.Fatalf("exact hit: %d %v %v", v, present, err)
	}
	if v, present, err := exact.ExactValue(b); err != nil || present || v != 0 {
		t.Fatalf("exact miss: %d %v %v", v, present, err)
	}
	if _, _, err := exact.ExactValue(c); err == nil {
		t.Fatal("unqueried digest returned a value")
	}
	if _, _, err := insp.ExactValue(a); err == nil {
		t.Fatal("near match read as an exact value")
	}
}

func TestParseInspectionRejects(t *testing.T) {
	a, b := digest('a'), digest('b')
	mutate := func(r map[string]any, k string, v any) map[string]any {
		out := map[string]any{}
		for key, val := range r {
			out[key] = val
		}
		if v == nil {
			delete(out, k)
		} else {
			out[k] = v
		}
		return out
	}
	valid := string(reply(t, hit(a, a, 1, 2)))
	cases := map[string]struct {
		body     string
		explicit []Digest
	}{
		"incomplete":           {strings.Replace(valid, `"complete":true`, `"complete":false`, 1), nil},
		"errors":               {strings.Replace(valid, `"errors":{}`, `"errors":["timeout"]`, 1), nil},
		"duplicate queried":    {string(reply(t, hit(a, a, 1, 2), hit(a, a, 1, 2))), nil},
		"missing result":       {strings.Replace(valid, `"distinct":1`, `"distinct":2`, 1), nil},
		"unconfirmed hit":      {string(reply(t, mutate(hit(a, a, 1, 2), "confirmed", false))), nil},
		"flag 2":               {string(reply(t, mutate(hit(a, a, 1, 2), "flag", 2))), nil},
		"negative prob":        {string(reply(t, hit(a, a, -0.1, 2))), nil},
		"prob above one":       {string(reply(t, hit(a, a, 1.1, 2))), nil},
		"nan prob":             {strings.Replace(valid, `"prob":1`, `"prob":NaN`, 1), nil},
		"miss with value":      {string(reply(t, mutate(miss(a), "value", 3))), nil},
		"miss with prob":       {string(reply(t, mutate(miss(a), "prob", 0.5))), nil},
		"short digest":         {string(reply(t, hit("abc", a, 1, 2))), nil},
		"uppercase digest":     {string(reply(t, hit(Digest(strings.ToUpper(string(a))), a, 1, 2))), nil},
		"short stored":         {string(reply(t, hit(a, "abc", 1, 2))), nil},
		"fractional value":     {strings.Replace(valid, `"value":2`, `"value":2.5`, 1), nil},
		"negative value":       {string(reply(t, hit(a, a, 1, -1))), nil},
		"trailing json":        {valid + `{}`, nil},
		"duplicate key":        {strings.Replace(valid, `"complete":true`, `"complete":true,"complete":true`, 1), nil},
		"unknown field":        {strings.Replace(valid, `"complete":true`, `"complete":true,"extra":1`, 1), nil},
		"missing found":        {string(reply(t, mutate(hit(a, a, 1, 2), "found", nil))), nil},
		"null":                 {`null`, nil},
		"explicit near match":  {string(reply(t, hit(a, b, 0.9, 2))), []Digest{a}},
		"explicit unqueried":   {string(reply(t, hit(b, b, 1, 2))), []Digest{a}},
		"explicit count":       {valid, []Digest{a, b}},
		"explicit bad request": {valid, []Digest{"abc"}},
	}
	for name, tc := range cases {
		if _, err := ParseInspection([]byte(tc.body), tc.explicit); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
