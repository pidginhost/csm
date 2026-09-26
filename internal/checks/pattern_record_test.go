package checks

import (
	"fmt"
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
		{`GET http://example.com/a HTTP/1.1`, "http://example.com/a", false},
		{`GET HTTPS://example.com?x=1 HTTP/1.1`, "HTTPS://example.com?x=1", false},
		{`GET http:/a?x=1 HTTP/1.1`, "http:/a?x=1", false},
		{`GET ftp://example.com/a HTTP/1.1`, "", true},
		{`GET http:a/b HTTP/1.1`, "", true},
		{`CONNECT example.com:443 HTTP/1.1`, "", true},
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

func TestParsePatternRecordAbsoluteIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, logged, target string
		identity             crawlid.Target
		class                crawlid.Class
	}{
		{
			name:   "escaped scheme and delimiters",
			logged: `\x48TTPS\x3a\x2f\x2f192.0.2.2/Category%2FPart/\x3fB%5B0%5D=\"%26ignored=1&A+B=%zz&a+b=2`,
			target: `HTTPS://192.0.2.2/Category%2FPart/?B%5B0%5D="%26ignored=1&A+B=%zz&a+b=2`,
			identity: crawlid.Target{
				Segment: []byte("Category/Part"), HasQuery: true,
				Names: [][]byte{[]byte("a b"), []byte("b[]")},
			},
			class: crawlid.Class{Dynamic: true, Expensive: true},
		},
		{
			name:   "authority only",
			logged: `http://192.0.2.2`, target: "http://192.0.2.2",
			identity: crawlid.Target{Segment: []byte{}},
			class:    crawlid.Class{Dynamic: true},
		},
		{
			name:   "query slash is not a path",
			logged: `http://192.0.2.2\x3f/a.css`, target: "http://192.0.2.2?/a.css",
			identity: crawlid.Target{Segment: []byte{}, HasQuery: true, Names: [][]byte{[]byte("/a.css")}},
			class:    crawlid.Class{Dynamic: true, Expensive: true},
		},
		{
			name:   "static path",
			logged: `https://[2001:db8::1]/a.CSS?X=1`, target: "https://[2001:db8::1]/a.CSS?X=1",
			identity: crawlid.Target{Segment: []byte("a.CSS"), HasQuery: true, Names: [][]byte{[]byte("x")}, Ext: "css"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := `192.0.2.1 - - ` + prTime + ` "GET ` + tc.logged + ` HTTP/1.1" 200 1 "-" "UA" "203.0.113.7"`
			r, ok := parsePatternRecord(line)
			if !ok || r.TargetInvalid || r.TargetOverflow || r.Target != tc.target ||
				r.Method != "GET" || r.Status != 200 || r.Referer != refererDash || r.UserAgent != "UA" || r.XFF != "203.0.113.7" {
				t.Fatalf("absolute target changed record: ok=%v record=%+v", ok, r)
			}
			identity, err := crawlid.ParseTarget(r.Target, patternMaxTarget)
			if err != nil || !reflect.DeepEqual(identity, tc.identity) {
				t.Fatalf("identity = %+v, err = %v; want %+v", identity, err, tc.identity)
			}
			if class := crawlid.Classify(r.Method, identity); class != tc.class {
				t.Fatalf("class = %+v, want %+v", class, tc.class)
			}
		})
	}
}

func TestParsePatternRecordAbsoluteBounds(t *testing.T) {
	for _, prefix := range []string{"http:/", "HTTPS://192.0.2.2/", "http://"} {
		for _, n := range []int{patternMaxTarget - 1, patternMaxTarget, patternMaxTarget + 1} {
			for _, escaped := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%d/escaped=%t", prefix, n, escaped), func(t *testing.T) {
					target := prefix + strings.Repeat("a", n-len(prefix))
					logged := target
					if escaped {
						logged = strings.NewReplacer(":", `\x3a`, "/", `\x2f`, "a", `\x61`).Replace(target)
					}
					r, ok := parsePatternRecord(`192.0.2.1 - - ` + prTime + ` "GET ` + logged + ` HTTP/1.1" 200 1 "-" "UA"`)
					want := target
					if n > patternMaxTarget {
						want = ""
					}
					if !ok || r.Target != want || r.TargetInvalid || r.TargetOverflow != (n > patternMaxTarget) ||
						r.Status != 200 || r.Referer != refererDash || r.UserAgent != "UA" {
						t.Fatalf("absolute bound: ok=%v target bytes=%d invalid=%v overflow=%v", ok, len(r.Target), r.TargetInvalid, r.TargetOverflow)
					}
				})
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
		{`"192.0.2.50` + strings.Repeat(" ", patternMaxExtension) + `, 203.0.113.7"`, "203.0.113.7", false},
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

func TestParsePatternRecordHeaderFields(t *testing.T) {
	// Apache escapes only quotes, backslashes and non-printable bytes in the
	// remote user and logs an empty user as "". Basic-auth usernames are
	// logged even when authentication fails, so a client chooses them.
	for _, prefix := range []string{
		`192.0.2.1 ident[0] user[1] `,
		`192.0.2.1 - [user] `,
		`192.0.2.1 - a b `,
		`192.0.2.1 - - extra `,
		`192.0.2.1 - "" `,
		`192.0.2.1 - x] [26/Sep/2026 `,
		`192.0.2.1 - x] [26/Sep/2026:09:00:00 +0000] `,
		`192.0.2.1 - q\"q `,
		`192.0.2.1 - bs\\s `,
	} {
		r, ok := parsePatternRecord(prefix + prTime + ` "GET /a?x=1 HTTP/1.1" 200 1 "-" "UA"`)
		want := time.Date(2026, 9, 26, 7, 0, 0, 0, time.UTC)
		if !ok || !r.TimeOK || !r.Time.Equal(want) || r.RemoteIP != "192.0.2.1" || r.Target != "/a?x=1" || r.UserAgent != "UA" {
			t.Errorf("header %q: ok=%v record=%+v", prefix, ok, r)
		}
	}
	for _, prefix := range []string{
		`192.0.2.1 `, `192.0.2.1 - `,
	} {
		if _, ok := parsePatternRecord(prefix + prTime + ` "GET / HTTP/1.1" 200 1`); ok {
			t.Errorf("accepted unsupported header %q", prefix)
		}
	}
}

func TestParsePatternRecordHeaderUserBoundaries(t *testing.T) {
	for _, ident := range []string{"-", "ident[0]", "ident]"} {
		for _, user := range []string{`""`, " ", "   ", " leading", "trailing ", `x] [26/Sep/2026`} {
			for _, stamp := range []string{prTime, "[not-a-time]"} {
				t.Run(fmt.Sprintf("%s/%q/%s", ident, user, stamp), func(t *testing.T) {
					line := "192.0.2.1 " + ident + " " + user + " " + stamp +
						` "GET /a?x=1 HTTP/1.1" 401 1 "-" "UA" "203.0.113.7"`
					r, ok := parsePatternRecord(line)
					wantTime := time.Date(2026, 9, 26, 7, 0, 0, 0, time.UTC)
					wantTimeOK := stamp == prTime
					if !wantTimeOK {
						wantTime = time.Time{}
					}
					if !ok || r.TimeOK != wantTimeOK || !r.Time.Equal(wantTime) ||
						r.RemoteIP != "192.0.2.1" || r.Method != "GET" || r.Target != "/a?x=1" ||
						r.TargetInvalid || r.TargetOverflow || r.Status != 401 ||
						r.Referer != refererDash || r.UserAgent != "UA" || r.XFF != "203.0.113.7" || r.XFFUnusable {
						t.Fatalf("header changed record: ok=%v record=%+v", ok, r)
					}
				})
			}
		}
	}
}

func TestParsePatternRecordHeaderMissingSeparator(t *testing.T) {
	for _, header := range []string{"- user", "ident[0] user", "- ", "-  "} {
		if _, ok := parsePatternRecord("192.0.2.1 " + header + prTime + ` "GET / HTTP/1.1" 200 1`); ok {
			t.Errorf("accepted incomplete header %q", header)
		}
	}
}

func TestParsePatternRecordBareHTTPVersions(t *testing.T) {
	for major := 0; major <= 9; major++ {
		for _, version := range []string{fmt.Sprintf("HTTP/%d", major), fmt.Sprintf(`\x48TTP/\x3%d`, major)} {
			r, ok := parsePatternRecord(`192.0.2.1 - - ` + prTime + ` "GET /a ` + version + `" 200 1 "-" "UA"`)
			wantTarget := "/a"
			if major < 2 {
				wantTarget = ""
			}
			if !ok || r.TargetInvalid != (major < 2) || r.Target != wantTarget || r.TargetOverflow || r.UserAgent != "UA" {
				t.Errorf("version %q: ok=%v record=%+v", version, ok, r)
			}
		}
	}
}

func TestParsePatternRecordRequestSyntax(t *testing.T) {
	for _, request := range []string{
		`GET /a HTTP/1`, `GET /a HTTP/12.1`, `GET /a HTTP/1.12`,
		`GET /a HTTP/`, `GET /a HTTP/1.`, `GET /a HTTP/.1`,
		`GET /a HTTP/1.1.0`, `GET /a http/1.1`,
		"GE\tT /a HTTP/1.1", `GE\x20T /a HTTP/1.1`,
		`GE\x00T /a HTTP/1.1`, `G(E)T /a HTTP/1.1`,
		"GET /a\tb HTTP/1.1", "GET /a\rb HTTP/1.1", "GET /a\nb HTTP/1.1",
		strings.Repeat("M", patternMaxMethod+1) + ` /a HTTP/1.1`,
		strings.Repeat(`\x4d`, patternMaxMethod+1) + ` /a HTTP/1.1`,
	} {
		r, ok := parsePatternRecord(`192.0.2.1 - - ` + prTime + ` "` + request + `" 200 1 "-" "UA" "203.0.113.7"`)
		if !ok || !r.TargetInvalid || r.Target != "" || r.TargetOverflow || r.UserAgent != "UA" || r.XFF != "203.0.113.7" {
			t.Errorf("request %q: ok=%v record=%+v", request, ok, r)
		}
	}
	for _, tc := range []struct{ request, method string }{
		{`GET /a HTTP/0.9`, "GET"}, {`GET /a HTTP/1.0`, "GET"},
		{`GET /a HTTP/2.0`, "GET"}, {`GET /a HTTP/3.0`, "GET"},
		{`GET /a HTTP/2`, "GET"}, {`GET /a HTTP/3`, "GET"},
		{`\x47ET /a \x48TTP/1.1`, "GET"},
		{strings.Repeat("M", patternMaxMethod) + ` /a HTTP/1.1`, strings.Repeat("M", patternMaxMethod)},
		{`M!#$%&'*+-.^_` + "`" + `|~ /a HTTP/1.1`, "M!#$%&'*+-.^_`|~"},
	} {
		r, ok := parsePatternRecord(`192.0.2.1 - - ` + prTime + ` "` + tc.request + `" 200 1`)
		if !ok || r.TargetInvalid || r.TargetOverflow || r.Target != "/a" || r.Method != tc.method {
			t.Errorf("request %q: ok=%v record=%+v", tc.request, ok, r)
		}
	}
}

func TestParsePatternRecordUnusableExtensions(t *testing.T) {
	for _, extension := range []string{
		`unknown, invalid`, `unknown`, `203.0.113.999`, `2001:db8::1%zone`,
		`,`, `example.com:bad`, `example.com:443/path`, `user@example.com:443`,
	} {
		for _, extra := range []string{
			`"` + extension + `"`,
			`"203.0.113.7" "` + extension + `"`,
			`"` + extension + `" "203.0.113.7"`,
		} {
			r, ok := parsePatternRecord(`198.51.100.9 - - ` + prTime + ` "GET /a HTTP/1.1" 200 1 "-" "UA" ` + extra)
			if !ok || !r.XFFUnusable || r.XFF != "" || r.Target != "/a" || r.UserAgent != "UA" {
				t.Errorf("extension %q: ok=%v record=%+v", extra, ok, r)
			}
		}
	}
	for _, extension := range []string{`example.com:443`, `192.0.2.1:80`, `[2001:db8::1]:443`, `-`, ``} {
		for _, extra := range []string{
			`"203.0.113.7" "` + extension + `"`,
			`"` + extension + `" "203.0.113.7"`,
		} {
			r, ok := parsePatternRecord(`198.51.100.9 - - ` + prTime + ` "GET /a HTTP/1.1" 200 1 "-" "UA" ` + extra)
			if !ok || r.XFFUnusable || r.XFF != "203.0.113.7" || r.Target != "/a" {
				t.Errorf("extension %q: ok=%v record=%+v", extra, ok, r)
			}
		}
	}
}

func BenchmarkParsePatternRecordExtensions(b *testing.B) {
	for _, n := range []int{128, 1024, 8192} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			line := `192.0.2.1 - - ` + prTime + ` "GET /a HTTP/1.1" 200 1 "-" "UA" ` +
				strings.Repeat(`"" `, n) + strings.Repeat(" ", n)
			b.SetBytes(int64(len(line)))
			b.ResetTimer()
			for b.Loop() {
				r, ok := parsePatternRecord(line)
				if !ok || r.Target != "/a" || r.XFF != "" || r.XFFUnusable {
					b.Fatalf("extensions lost record: ok=%v record=%+v", ok, r)
				}
			}
		})
	}
}

// A trusted proxy appends the address it saw at the right end of
// X-Forwarded-For; everything to its left is client-supplied. Garbage or
// padding there must not discard the proxy's own entries.
func TestParsePatternRecordXFFClientPrefix(t *testing.T) {
	long := strings.Repeat("192.0.2.50, ", 30) + "203.0.113.7"
	for _, tc := range []struct {
		name, ext, xff string
		partial        bool
	}{
		{"complete list", `"192.0.2.50, 203.0.113.7"`, "192.0.2.50, 203.0.113.7", false},
		{"client garbage", `"garbage, 203.0.113.7"`, "203.0.113.7", true},
		{"client unknown", `"unknown, 198.51.100.20, 203.0.113.7"`, "198.51.100.20, 203.0.113.7", true},
		{"client padding", `"192.0.2.50` + strings.Repeat(" ", patternMaxExtension) + `, 203.0.113.7"`, "203.0.113.7", true},
		{"list over the bound", `"` + long + `"`, strings.Repeat("192.0.2.50, ", 20) + "203.0.113.7", true},
		{"after vhost", `"example.com:443" "garbage, 203.0.113.7"`, "203.0.113.7", true},
	} {
		r, ok := parsePatternRecord(`198.51.100.9 - - ` + prTime + ` "GET /a?x=1 HTTP/1.1" 200 1 "-" "UA" ` + tc.ext)
		if !ok || r.XFFUnusable || r.XFF != tc.xff || r.XFFPartial != tc.partial || r.Target != "/a?x=1" {
			t.Errorf("%s: ok=%v xff=%q partial=%v unusable=%v", tc.name, ok, r.XFF, r.XFFPartial, r.XFFUnusable)
		}
	}
	for _, ext := range []string{
		`"203.0.113.7, garbage"`,
		`"garbage, 203.0.113.7" "198.51.100.20"`,
		`"192.0.2.50, ` + strings.Repeat("a", patternMaxExtension) + `"`,
	} {
		r, ok := parsePatternRecord(`198.51.100.9 - - ` + prTime + ` "GET /a?x=1 HTTP/1.1" 200 1 "-" "UA" ` + ext)
		if !ok || !r.XFFUnusable || r.XFF != "" || r.XFFPartial {
			t.Errorf("%s: ok=%v xff=%q partial=%v unusable=%v", ext, ok, r.XFF, r.XFFPartial, r.XFFUnusable)
		}
	}
}

func TestParsePatternRecordXFFSuffixBounds(t *testing.T) {
	for _, n := range []int{patternMaxExtension - 1, patternMaxExtension, patternMaxExtension + 1} {
		suffix := "192.0.2.50" + strings.Repeat(" ", n-len("192.0.2.50, 203.0.113.7")) + ", 203.0.113.7"
		for _, prefix := range []string{"", "unknown, "} {
			for _, escaped := range []bool{false, true} {
				t.Run(fmt.Sprintf("%d/prefix=%t/escaped=%t", n, prefix != "", escaped), func(t *testing.T) {
					value := prefix + suffix
					if escaped {
						value = strings.NewReplacer(" ", `\x20`, ",", `\x2c`).Replace(value)
					}
					r, ok := parsePatternRecord(`198.51.100.9 - - ` + prTime +
						` "GET /a HTTP/1.1" 200 1 "-" "UA" "` + value + `" "example.com:443"`)
					want := suffix
					if n > patternMaxExtension {
						want = "203.0.113.7"
					}
					if !ok || r.Target != "/a" || r.XFF != want || r.XFFUnusable ||
						r.XFFPartial != (prefix != "" || n > patternMaxExtension) {
						t.Fatalf("suffix boundary changed evidence: ok=%v record=%+v", ok, r)
					}
				})
			}
		}
	}
}

func TestParsePatternRecordXFFSuffixEscapes(t *testing.T) {
	for _, tc := range []struct {
		name, extension, xff string
		partial, unusable    bool
	}{
		{"escaped separators", `"garbage\x2c 2001:db8::7\x2c\t203.0.113.7"`, "2001:db8::7,\t203.0.113.7", true, false},
		{"escaped address", `"unknown, \x32\x30\x33.0.113.7"`, "203.0.113.7", true, false},
		{"escaped whitespace", `"garbage,\xe2\x80\x832001:db8::7"`, "2001:db8::7", true, false},
		{"decode once", `"192.0.2.50\\x2c203.0.113.7"`, "", false, true},
		{"literal percent", `"192.0.2.50%2c203.0.113.7"`, "", false, true},
		{"invalid escaped client entry", `"192.0.2.50\"x, 203.0.113.7"`, "203.0.113.7", true, false},
		{"invalid escaped proxy entry", `"192.0.2.50, 203.0.113.7\"x"`, "", false, true},
		{"zoned client entry", `"2001:db8::1%zone, 203.0.113.7"`, "203.0.113.7", true, false},
		{"zoned proxy entry", `"203.0.113.7, 2001:db8::1%zone"`, "", false, true},
		{"empty client entry", `", 203.0.113.7"`, "203.0.113.7", true, false},
		{"empty proxy entry", `"203.0.113.7,"`, "", false, true},
		{"mapped proxy entry", `"unknown, ::ffff:203.0.113.7"`, "::ffff:203.0.113.7", true, false},
		{"second partial list", `"203.0.113.7" "garbage, 198.51.100.20"`, "", false, true},
		{"two partial lists", `"garbage, 203.0.113.7" "unknown, 198.51.100.20"`, "", false, true},
		{"malformed extension after suffix", `"garbage, 203.0.113.7" "unknown"`, "", false, true},
		{"malformed extension before suffix", `"unknown" "garbage, 203.0.113.7"`, "", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, ok := parsePatternRecord(`198.51.100.9 - - ` + prTime +
				` "GET /a HTTP/1.1" 200 1 "-" "UA" ` + tc.extension)
			if !ok || r.Target != "/a" || r.XFF != tc.xff || r.XFFPartial != tc.partial || r.XFFUnusable != tc.unusable {
				t.Fatalf("extension changed evidence: ok=%v record=%+v", ok, r)
			}
		})
	}
}

func BenchmarkParsePatternRecordXFFPrefix(b *testing.B) {
	for _, n := range []int{128, 1024, 8192, 65536} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			line := `198.51.100.9 - - ` + prTime + ` "GET /a HTTP/1.1" 200 1 "-" "UA" "` +
				strings.Repeat("garbage, ", n) + `203.0.113.7"`
			b.SetBytes(int64(len(line)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				r, ok := parsePatternRecord(line)
				if !ok || r.Target != "/a" || r.XFF != "203.0.113.7" || !r.XFFPartial || r.XFFUnusable {
					b.Fatalf("client prefix changed evidence: ok=%v record=%+v", ok, r)
				}
			}
		})
	}
}
