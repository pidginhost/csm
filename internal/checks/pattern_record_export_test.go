package checks

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseCrawlLogLineMatchesRecordParser(t *testing.T) {
	site := []string{"example.com"}
	for _, line := range []string{
		`192.0.2.1 - - ` + prTime + ` "GET /category/?filter_color=red HTTP/1.1" 200 512 "https://example.com/c/" "Mozilla/5.0"`,
		`198.51.100.9 - - ` + prTime + ` "GET http://example.com/a?x=1 HTTP/2" 503 1 "https://other.example/" "UA" "garbage, 203.0.113.7"`,
		`192.0.2.1 - - ` + prTime + ` "GET /a HTTP/1.1" 200 1 "not a url" "UA"`,
		`192.0.2.1 - - [not-a-time] "-" 400 0`,
		`192.0.2.1 - - ` + prTime + ` "GET / HTTP/1.1" 200 1`,
		`192.0.2.1 - - ` + prTime + ` "GET /` + strings.Repeat(`\x41`, patternMaxTarget) + ` HTTP/1.1" 414 0 "-" "UA"`,
		`192.0.2.1 - - ` + prTime + ` "GET / HTTP/1.1" 200 1 "-" "` + strings.Repeat("A", patternMaxUA+1) + `"`,
		`192.0.2.1 - - ` + prTime + ` "GET / HTTP/1.1" 200 1 "-" "UA" "203.0.113.7" "198.51.100.9"`,
		`192.0.2.1 - - ` + prTime + ` "GET / HTTP/1.1" 200 1 "-" "UA" "unknown, invalid"`,
	} {
		want, wantOK := parsePatternRecord(line)
		got, ok := ParseCrawlLogLine(line, site)
		if ok != wantOK || !ok {
			t.Fatalf("%q: ok=%v want %v", line, ok, wantOK)
		}
		class := map[refererClass]string{
			refClassNone: CrawlRefererNone, refClassMalformed: CrawlRefererMalformed,
			refClassCrossSite: CrawlRefererCrossSite, refClassSameSite: CrawlRefererSameSite,
		}[classifyReferer(want, func(h string) bool { return h == "example.com" })]
		mirror := CrawlLogRecord{
			RemoteIP: want.RemoteIP, Time: want.Time, TimeOK: want.TimeOK, Method: want.Method, Target: want.Target,
			TargetOverflow: want.TargetOverflow, TargetInvalid: want.TargetInvalid, Status: want.Status,
			RefererClass: class, UserAgent: want.UserAgent, UAOverflow: want.UAOverflow,
			XFF: want.XFF, XFFUnusable: want.XFFUnusable, XFFPartial: want.XFFPartial,
		}
		if !reflect.DeepEqual(got, mirror) {
			t.Fatalf("%q: exported record %+v differs from parser %+v", line, got, want)
		}
	}
	if _, ok := ParseCrawlLogLine("", site); ok {
		t.Fatal("accepted an empty line")
	}
}

func TestParseCrawlLogLineRefererClasses(t *testing.T) {
	site := []string{"example.com", "www.example.com", "2001:db8::1"}
	for ref, want := range map[string]string{
		`"-"`:                            CrawlRefererNone,
		`""`:                             CrawlRefererNone,
		`"not a url"`:                    CrawlRefererMalformed,
		`"https://www.example.com/a"`:    CrawlRefererSameSite,
		`"https://other.example/"`:       CrawlRefererCrossSite,
		`"https://EXAMPLE.COM./x?y=1"`:   CrawlRefererSameSite,
		`"http://example.com:8080/"`:     CrawlRefererSameSite,
		`"http://[2001:db8::1]/"`:        CrawlRefererSameSite,
		`"https://example.com.example/"`: CrawlRefererCrossSite,
		`"https://sub.example.com/"`:     CrawlRefererCrossSite,
	} {
		r, ok := ParseCrawlLogLine(`192.0.2.1 - - `+prTime+` "GET / HTTP/1.1" 200 1 `+ref+` "UA"`, site)
		if !ok || r.RefererClass != want {
			t.Errorf("%s: ok=%v class %q, want %q", ref, ok, r.RefererClass, want)
		}
	}
	if CrawlTargetLimit != patternMaxTarget {
		t.Fatal("exported target bound differs from the parser's")
	}
}

func TestParseCrawlLogLineTargetLimit(t *testing.T) {
	for _, tc := range []struct {
		name, target, want string
		overflow           bool
	}{
		{"literal at limit", "/" + strings.Repeat("a", CrawlTargetLimit-1), "/" + strings.Repeat("a", CrawlTargetLimit-1), false},
		{"escaped at limit", "/" + strings.Repeat(`\x61`, CrawlTargetLimit-1), "/" + strings.Repeat("a", CrawlTargetLimit-1), false},
		{"literal overflow", "/" + strings.Repeat("a", CrawlTargetLimit), "", true},
		{"escaped overflow", "/" + strings.Repeat(`\x61`, CrawlTargetLimit), "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, ok := ParseCrawlLogLine(`192.0.2.1 - - `+prTime+` "GET `+tc.target+` HTTP/1.1" 200 1 "-" "UA"`, nil)
			if !ok || r.Target != tc.want || r.TargetOverflow != tc.overflow || r.TargetInvalid || r.UserAgent != "UA" {
				t.Fatalf("ok=%v target length=%d overflow=%v invalid=%v ua=%q", ok, len(r.Target), r.TargetOverflow, r.TargetInvalid, r.UserAgent)
			}
		})
	}
}

func TestParseCrawlLogLineRejectsPartialRecords(t *testing.T) {
	for _, line := range []string{
		"",
		`192.0.2.1 - - ` + prTime + ` "GET / HTTP/1.1" invalid 1`,
		`192.0.2.1 - - ` + prTime + ` "GET / HTTP/1.1" 200 invalid`,
		`192.0.2.1 - - ` + prTime + ` "GET / HTTP/1.1" 200 1 "https://example.com/" "unterminated`,
		`192.0.2.1 - - ` + prTime + ` "GET / HTTP/1.1" 200 1 "https://example.com/" "UA" unquoted`,
	} {
		if r, ok := ParseCrawlLogLine(line, []string{"example.com"}); ok || !reflect.DeepEqual(r, CrawlLogRecord{}) {
			t.Fatalf("rejected record must be empty: ok=%v record=%+v", ok, r)
		}
	}
}

func TestParseCrawlLogLineWithoutSiteHosts(t *testing.T) {
	for _, tc := range []struct {
		name, tail, class string
	}{
		{"valid referer", ` "https://example.com/" "UA"`, CrawlRefererCrossSite},
		{"malformed referer", ` "not a url" "UA"`, CrawlRefererMalformed},
		{"dash referer", ` "-" "UA"`, CrawlRefererNone},
		{"empty referer", ` "" "UA"`, CrawlRefererNone},
		{"missing referer", "", CrawlRefererNone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, ok := ParseCrawlLogLine(`192.0.2.1 - - `+prTime+` "GET / HTTP/1.1" 200 1`+tc.tail, nil)
			if !ok || r.RefererClass != tc.class {
				t.Fatalf("ok=%v class=%q, want %q", ok, r.RefererClass, tc.class)
			}
		})
	}
}
