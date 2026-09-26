package checks

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/crawlid"
)

const prTime = "[26/Sep/2026:10:00:00 +0300]"

func TestParsePatternRecordCombined(t *testing.T) {
	line := `192.0.2.1 - - ` + prTime + ` "GET /category/?filter_color=red HTTP/1.1" 200 512 "https://example.com/category/" "Mozilla/5.0"`
	r, ok := parsePatternRecord(line)
	if !ok {
		t.Fatal("rejected a combined line")
	}
	if r.RemoteIP != "192.0.2.1" || r.Method != "GET" || r.Target != "/category/?filter_color=red" || r.Status != 200 || !r.TimeOK {
		t.Fatalf("record = %+v", r)
	}
	if r.Referer != refererValid || r.RefererHost != "example.com" || r.UserAgent != "Mozilla/5.0" {
		t.Fatalf("referer/ua = %v %q %q", r.Referer, r.RefererHost, r.UserAgent)
	}
}

func TestParsePatternRecordEscapes(t *testing.T) {
	cases := []struct {
		name, line, target, ua string
	}{
		{"escaped quote in ua", `192.0.2.1 - - ` + prTime + ` "GET / HTTP/1.1" 200 1 "-" "Mozilla \"quoted\" UA"`, "/", `Mozilla "quoted" UA`},
		{"escaped quote in target", `192.0.2.1 - - ` + prTime + ` "GET /a?x=\"1 HTTP/1.1" 200 1 "-" "UA"`, `/a?x="1`, "UA"},
		{"hex escape in target", `192.0.2.1 - - ` + prTime + ` "GET /a\x22b HTTP/1.1" 200 1 "-" "UA"`, `/a"b`, "UA"},
		{"escaped backslash", `192.0.2.1 - - ` + prTime + ` "GET /a\\b HTTP/1.1" 200 1 "-" "UA\\"`, `/a\b`, `UA\`},
	}
	for _, c := range cases {
		r, ok := parsePatternRecord(c.line)
		if !ok {
			t.Fatalf("%s: rejected", c.name)
		}
		if r.Target != c.target || r.UserAgent != c.ua {
			t.Errorf("%s: target %q ua %q, want %q %q", c.name, r.Target, r.UserAgent, c.target, c.ua)
		}
	}
}

func TestParsePatternRecordRefererStates(t *testing.T) {
	cases := []struct {
		ref   string
		state refererState
		host  string
	}{
		{`"-"`, refererDash, ""},
		{`""`, refererEmpty, ""},
		{`"not a url"`, refererMalformed, ""},
		{`"android-app://com.example/"`, refererMalformed, ""},
		{`"https://WWW.Example.COM.:8443/x"`, refererValid, "www.example.com"},
		{`"http://[2001:db8::1]:8080/"`, refererValid, "2001:db8::1"},
		{`"https://user@example.com/"`, refererValid, "example.com"},
		{`"HTTPS://EXAMPLE.COM"`, refererValid, "example.com"},
		{`"https://example.com:99999999/"`, refererMalformed, ""},
		{`"https://exa mple.com/"`, refererMalformed, ""},
	}
	for _, c := range cases {
		line := `192.0.2.1 - - ` + prTime + ` "GET / HTTP/1.1" 200 1 ` + c.ref + ` "UA"`
		r, ok := parsePatternRecord(line)
		if !ok {
			t.Fatalf("%s: rejected", c.ref)
		}
		if r.Referer != c.state || r.RefererHost != c.host {
			t.Errorf("%s: state %v host %q, want %v %q", c.ref, r.Referer, r.RefererHost, c.state, c.host)
		}
	}
}

func TestParsePatternRecordBounds(t *testing.T) {
	longTarget := "/a/?x=" + strings.Repeat("b", patternMaxTarget)
	r, ok := parsePatternRecord(`192.0.2.1 - - ` + prTime + ` "GET ` + longTarget + ` HTTP/1.1" 414 0 "-" "UA"`)
	if !ok || !r.TargetOverflow || r.Target != "" {
		t.Fatalf("oversized target: ok=%v overflow=%v target len %d", ok, r.TargetOverflow, len(r.Target))
	}
	if r.UserAgent != "UA" {
		t.Errorf("fields after an oversized target lost: ua %q", r.UserAgent)
	}

	longUA := strings.Repeat("A", 600)
	r, ok = parsePatternRecord(`192.0.2.1 - - ` + prTime + ` "GET /a?x=1 HTTP/1.1" 200 1 "-" "` + longUA + `"`)
	if !ok || !r.UAOverflow || len(r.UserAgent) != patternMaxUA || r.Target != "/a?x=1" {
		t.Fatalf("oversized ua: ok=%v overflow=%v len=%d target=%q", ok, r.UAOverflow, len(r.UserAgent), r.Target)
	}

	longRef := "https://example.com/" + strings.Repeat("p", 3000)
	r, ok = parsePatternRecord(`192.0.2.1 - - ` + prTime + ` "GET /a?x=1 HTTP/1.1" 200 1 "` + longRef + `" "UA"`)
	if !ok || r.Referer != refererValid || r.RefererHost != "example.com" || r.UserAgent != "UA" {
		t.Fatalf("oversized referer: ok=%v state=%v host=%q ua=%q", ok, r.Referer, r.RefererHost, r.UserAgent)
	}

	cutHost := "https://" + strings.Repeat("h", 3000)
	r, ok = parsePatternRecord(`192.0.2.1 - - ` + prTime + ` "GET / HTTP/1.1" 200 1 "` + cutHost + `" "UA"`)
	if !ok || r.Referer != refererMalformed {
		t.Fatalf("referer host cut by the bound must be malformed, got %v", r.Referer)
	}
}

func TestParsePatternRecordShapes(t *testing.T) {
	r, ok := parsePatternRecord(`192.0.2.1 - - ` + prTime + ` "GET / HTTP/1.1" 200 5`)
	if !ok || r.Referer != refererMissing || r.Target != "/" {
		t.Fatalf("common log format: ok=%v %+v", ok, r)
	}
	r, ok = parsePatternRecord(`192.0.2.1 - - ` + prTime + ` "-" 400 0 "-" "-"`)
	if !ok || r.Target != "" || r.TargetOverflow {
		t.Fatalf("no request target: ok=%v %+v", ok, r)
	}
	r, ok = parsePatternRecord(`192.0.2.1 - - ` + prTime + ` "\x16\x03\x01" 400 0 "-" "-"`)
	if !ok || r.Target != "" {
		t.Fatalf("tls garbage: ok=%v %+v", ok, r)
	}
	r, ok = parsePatternRecord(`198.51.100.9 - - ` + prTime + ` "GET / HTTP/1.1" 200 1 "-" "UA" "203.0.113.7"`)
	if !ok || r.XFF != "203.0.113.7" {
		t.Fatalf("xff extension: ok=%v xff=%q", ok, r.XFF)
	}
	for _, bad := range []string{
		"",
		"192.0.2.1 - -",
		`192.0.2.1 - - [26/Sep/2026:10:00:00 +0300 "GET / HTTP/1.1" 200 1 "-" "-"`,
		`192.0.2.1 - - ` + prTime + ` "GET / HTTP/1.1 200 1 "-" "-`,
	} {
		if _, ok := parsePatternRecord(bad); ok {
			t.Errorf("accepted malformed line %q", bad)
		}
	}
}

func TestClassifyReferer(t *testing.T) {
	site := func(h string) bool { return h == "example.com" || h == "www.example.com" }
	cases := []struct {
		r    patternRecord
		want refererClass
	}{
		{patternRecord{Referer: refererMissing}, refClassNone},
		{patternRecord{Referer: refererDash}, refClassNone},
		{patternRecord{Referer: refererEmpty}, refClassNone},
		{patternRecord{Referer: refererMalformed}, refClassMalformed},
		{patternRecord{Referer: refererValid, RefererHost: "www.example.com"}, refClassSameSite},
		{patternRecord{Referer: refererValid, RefererHost: "other.example"}, refClassCrossSite},
	}
	for _, c := range cases {
		if got := classifyReferer(c.r, site); got != c.want {
			t.Errorf("classifyReferer(%+v) = %v, want %v", c.r, got, c.want)
		}
	}
}

func TestParsePatternRecordRequestFraming(t *testing.T) {
	for _, tc := range []struct {
		request, target string
		invalid         bool
	}{
		{`GET /a\x20b?x=1 HTTP/1.1`, "/a b?x=1", false},
		{`GET /a\tb?x=1 HTTP/1.1`, "/a\tb?x=1", false},
		{`GET /a%2Fb?x=%41 HTTP/1.1`, "/a%2Fb?x=%41", false},
		{`GET /a\q\xZ1 HTTP/1.1`, `/a\q\xZ1`, false},
		{`GET /a b HTTP/1.1`, "", true},
		{`GET / HTTP/1.1 extra`, "", true},
		{`GET /`, "", true},
		{`GET http://example.com/a HTTP/1.1`, "", true},
		{`OPTIONS * HTTP/1.1`, "", true},
	} {
		r, ok := parsePatternRecord(`192.0.2.1 - - ` + prTime + ` "` + tc.request + `" 200 1 "-" "UA"`)
		if !ok || r.Target != tc.target || r.TargetInvalid != tc.invalid || r.TargetOverflow {
			t.Errorf("%q: ok=%v %+v", tc.request, ok, r)
		}
		if !tc.invalid {
			got, err := crawlid.ParseTarget(r.Target, patternMaxTarget)
			want, wantErr := crawlid.ParseTarget(tc.target, patternMaxTarget)
			if err != nil || wantErr != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("record identity changed: %+v %v", got, err)
			}
		}
	}
}

func TestParsePatternRecordExactBounds(t *testing.T) {
	for _, n := range []int{patternMaxTarget - 1, patternMaxTarget, patternMaxTarget + 1} {
		for _, encoded := range []bool{false, true} {
			target := "/" + strings.Repeat("a", n-1)
			logged := target
			if encoded {
				logged = `\x2f` + strings.Repeat(`\x61`, n-1)
			}
			r, ok := parsePatternRecord(`192.0.2.1 - - ` + prTime + ` "GET ` + logged + ` HTTP/1.1" 200 1 "-" "UA"`)
			want := target
			if n > patternMaxTarget {
				want = ""
			}
			if !ok || r.Target != want || r.TargetOverflow != (n > patternMaxTarget) || r.UserAgent != "UA" {
				t.Fatalf("bound %d encoded=%v: ok=%v target bytes=%d overflow=%v", n, encoded, ok, len(r.Target), r.TargetOverflow)
			}
		}
	}
	for _, n := range []int{patternMaxUA, patternMaxUA + 1} {
		ua := strings.Repeat("A", n)
		r, ok := parsePatternRecord(`192.0.2.1 - - ` + prTime + ` "GET /a?x=1 HTTP/1.1" 200 1 "-" "` + ua + `"`)
		if !ok || r.UAOverflow != (n > patternMaxUA) || r.UserAgent != ua[:patternMaxUA] || r.Target != "/a?x=1" {
			t.Fatal("UA boundary changed target or overflow")
		}
	}
	for _, n := range []int{patternMaxReferer, patternMaxReferer + 1} {
		ref := "https://example.com/" + strings.Repeat("p", n-len("https://example.com/"))
		r, ok := parsePatternRecord(`192.0.2.1 - - ` + prTime + ` "GET /a?x=1 HTTP/1.1" 200 1 "` + ref + `" "UA"`)
		if !ok || r.Target != "/a?x=1" || r.Referer != refererValid || r.RefererHost != "example.com" || r.UserAgent != "UA" {
			t.Fatal("Referer boundary lost target/host/UA")
		}
	}
}

func TestParsePatternRecordProxyExtensions(t *testing.T) {
	for _, tc := range []struct {
		extra, xff string
		unusable   bool
	}{
		{`"example.com:443"`, "", false},
		{`"example.com:443" "192.0.2.50, 203.0.113.7"`, "192.0.2.50, 203.0.113.7", false},
		{`"192.0.2.50, 203.0.113.7" "example.com:443"`, "192.0.2.50, 203.0.113.7", false},
		{`"192.0.2.50, invalid"`, "", true},
		{`"192.0.2.50" "203.0.113.7"`, "", true},
		{`"192.0.2.50` + strings.Repeat(" ", patternMaxExtension) + `, 203.0.113.7"`, "", true},
	} {
		r, ok := parsePatternRecord(`198.51.100.9 - - ` + prTime + ` "GET /a?x=1 HTTP/1.1" 200 1 "-" "UA" ` + tc.extra)
		if !ok || r.Target != "/a?x=1" || r.XFF != tc.xff || r.XFFUnusable != tc.unusable {
			t.Errorf("extension %q: ok=%v %+v", tc.extra, ok, r)
		}
	}
	for _, n := range []int{patternMaxExtension, patternMaxExtension + 1} {
		xff := "203.0.113.7" + strings.Repeat(" ", n-len("203.0.113.7"))
		r, ok := parsePatternRecord(`198.51.100.9 - - ` + prTime + ` "GET / HTTP/1.1" 200 1 "-" "UA" "` + xff + `"`)
		if !ok || r.XFFUnusable != (n > patternMaxExtension) {
			t.Fatal("extension boundary flag")
		}
		if n <= patternMaxExtension && r.XFF != xff {
			t.Fatal("complete extension changed")
		}
		if n > patternMaxExtension && r.XFF != "" {
			t.Fatal("extension prefix retained")
		}
	}
}

func TestParsePatternRecordMalformedAncillaryFields(t *testing.T) {
	for _, ref := range []string{
		`https://example..com/`, `https://-example.com/`, `https://example.com../`,
		`https://` + strings.Repeat("a", 64) + `.example/`,
		`https://example.com:\x31\x32x/`, `https://[2001:db8::1%25zone]/`,
		`https://example.com/a\"b`, `https://example.com/a\nb`,
		`https://example.com/` + strings.Repeat("a", patternMaxReferer) + `\x20`,
		`https://example.com/%zz`,
	} {
		r, ok := parsePatternRecord(`192.0.2.1 - - ` + prTime + ` "GET /a?x=1 HTTP/1.1" 200 1 "` + ref + `" "UA"`)
		if !ok || r.Referer != refererMalformed || r.RefererHost != "" || r.UserAgent != "UA" || r.Target != "/a?x=1" {
			t.Errorf("%q: ok=%v %+v", ref, ok, r)
		}
	}
	for _, suffix := range []string{`200`, `200 x`, `200 1 junk "-" "UA"`, `999999999999999999999 1`, `200 1 "-" "UA"junk`, `200 1 "-" "UA`} {
		if _, ok := parsePatternRecord(`192.0.2.1 - - ` + prTime + ` "GET / HTTP/1.1" ` + suffix); ok {
			t.Errorf("accepted malformed suffix %q", suffix)
		}
	}
	r, ok := parsePatternRecord(`192.0.2.1 - - [not-a-time] "GET / HTTP/1.1" 200 1`)
	if !ok || r.TimeOK || !r.Time.IsZero() || r.Target != "/" {
		t.Fatal("invalid timestamp not explicit")
	}
	r, ok = parsePatternRecord(`192.0.2.1 - - ` + prTime + ` "GET / HTTP/1.1" 200 1`)
	want := time.Date(2026, 9, 26, 7, 0, 0, 0, time.UTC)
	if !ok || !r.TimeOK || !r.Time.Equal(want) {
		t.Fatalf("timestamp offset lost: %v", r.Time)
	}
}
