package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/crawlreplay"
)

// Whatever a client puts in a logged request, the converted row stays in
// the closed stream format: nothing from the line can reach the output
// except through a pseudonym or a closed label.
func FuzzConvertLine(f *testing.F) {
	f.Add(`192.0.2.10 - - ` + ts + ` "GET /category/?filter_color=red HTTP/1.1" 200 5 "https://www.example.com/" "Googlebot"`)
	f.Add(`198.51.100.9 - a b ` + ts + ` "GET http://example.com?x=1 HTTP/2" 503 5 "-" "UA" "garbage, 203.0.113.7"`)
	f.Add(`192.0.2.10 - - ` + ts + ` "GET ?s=a HTTP/1.1" 200 5 "-" "UA"`)
	f.Add(`192.0.2.13 - - [bad-time] "GET / HTTP/1.1" 200 5`)
	inv, err := parseInventory([]byte(period + `"sites":[{"name":"example.com","account":"acct1","aliases":["example.com"],"logs":["x"]}],
	  "trusted_proxies":["198.51.100.9"],"infrastructure":["192.0.2.200"]}`))
	if err != nil {
		f.Fatal(err)
	}
	labels, err := parseLabels([]byte(`{"labels":[{"site":"example.com","from":"2000-01-01T00:00:00Z","to":"2100-01-01T00:00:00Z","label":"attack","episode":"e1","name_prefixes":["filter_"]}]}`), inv)
	if err != nil {
		f.Fatal(err)
	}
	evidence, err := parseBotEvidence([]byte(strings.Replace(googlebotEvidence, "203.0.113.0/24", "192.0.2.0/24", 1)))
	if err != nil {
		f.Fatal(err)
	}
	c := newConverter(inv, labels, newPseudonyms(bytes.Repeat([]byte{7}, 32), nil), testNow)
	c.bots = evidence
	site := inv.Sites[0]
	f.Fuzz(func(t *testing.T, line string) {
		rec, ok := checks.ParseCrawlLogLine(line, []string{"example.com"})
		if !ok || !rec.TimeOK || rec.Time.Unix() <= 0 {
			return
		}
		sm := crawlreplay.SiteManifest{Site: "dom-000000.example", Account: "acct-000000", Labels: map[string]int64{}}
		row, _, err := c.row(site, &sm, rec, 0, 1)
		if err != nil {
			t.Fatalf("pseudonym collision under HMAC-SHA256: %v", err)
		}
		var out bytes.Buffer
		if err := crawlreplay.WriteRow(&out, row); err != nil {
			t.Fatalf("converted row breaks the stream format: %v", err)
		}
		for _, raw := range []string{"example.com", "filter_", "garbage"} {
			if strings.Contains(out.String(), raw) {
				t.Fatalf("row leaks %q", raw)
			}
		}
	})
}
