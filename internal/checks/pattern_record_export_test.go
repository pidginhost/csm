package checks

import (
	"reflect"
	"testing"
)

func TestParseCrawlLogLineMatchesRecordParser(t *testing.T) {
	site := func(h string) bool { return h == "example.com" }
	for _, line := range []string{
		`192.0.2.1 - - ` + prTime + ` "GET /category/?filter_color=red HTTP/1.1" 200 512 "https://example.com/c/" "Mozilla/5.0"`,
		`198.51.100.9 - - ` + prTime + ` "GET http://example.com/a?x=1 HTTP/2" 503 1 "https://other.example/" "UA" "garbage, 203.0.113.7"`,
		`192.0.2.1 - - ` + prTime + ` "GET /a HTTP/1.1" 200 1 "not a url" "UA"`,
		`192.0.2.1 - - [not-a-time] "-" 400 0`,
	} {
		want, wantOK := parsePatternRecord(line)
		got, ok := ParseCrawlLogLine(line, site)
		if ok != wantOK || !ok {
			t.Fatalf("%q: ok=%v want %v", line, ok, wantOK)
		}
		mirror := CrawlLogRecord{
			RemoteIP: want.RemoteIP, Time: want.Time, TimeOK: want.TimeOK, Method: want.Method, Target: want.Target,
			TargetOverflow: want.TargetOverflow, TargetInvalid: want.TargetInvalid, Status: want.Status,
			RefererClass: got.RefererClass, UserAgent: want.UserAgent, UAOverflow: want.UAOverflow,
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
	site := func(h string) bool { return h == "example.com" || h == "www.example.com" }
	for ref, want := range map[string]string{
		`"-"`:                          CrawlRefererNone,
		`""`:                           CrawlRefererNone,
		`"not a url"`:                  CrawlRefererMalformed,
		`"https://www.example.com/a"`:  CrawlRefererSameSite,
		`"https://other.example/"`:     CrawlRefererCrossSite,
		`"https://EXAMPLE.COM./x?y=1"`: CrawlRefererSameSite,
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
