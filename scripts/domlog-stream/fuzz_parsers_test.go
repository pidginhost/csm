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
	inv, err := parseInventory([]byte(`{"sites":[{"name":"example.com","account":"acct1","aliases":["example.com"],"logs":["x"]}],
	  "trusted_proxies":["198.51.100.9"],"infrastructure":["192.0.2.200"],"bot_ranges":{"googlebot":["192.0.2.0/24"]}}`))
	if err != nil {
		f.Fatal(err)
	}
	labels, err := parseLabels([]byte(`{"labels":[{"site":"example.com","from":"2000-01-01T00:00:00Z","to":"2100-01-01T00:00:00Z","label":"attack","episode":"e1","name_prefixes":["filter_"]}]}`), inv)
	if err != nil {
		f.Fatal(err)
	}
	c := &converter{inv: inv, labels: labels, ps: pseudonyms{salt: bytes.Repeat([]byte{7}, 32)}}
	site := inv.Sites[0]
	f.Fuzz(func(t *testing.T, line string) {
		rec, ok := checks.ParseCrawlLogLine(line, []string{"example.com"})
		if !ok || !rec.TimeOK || rec.Time.Unix() <= 0 {
			return
		}
		cov := siteCoverage{Site: c.ps.site(site.Name), Account: c.ps.account(site.Account), Labels: map[string]int64{}}
		row := c.row(site, &cov, rec, 0, 1)
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
