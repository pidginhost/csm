package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

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
	site := inv.Sites[0]
	f.Fuzz(func(t *testing.T, line string) {
		rec, ok := checks.ParseCrawlLogLine(line, []string{"example.com"})
		if !ok || !rec.TimeOK || rec.Time.Unix() <= 0 {
			return
		}
		// Each input is a new conversion; collision state must not accumulate
		// every identity from earlier fuzz inputs for the worker's lifetime.
		c := newConverter(osFS{}, inv, labels, newPseudonyms(bytes.Repeat([]byte{7}, 32), nil), testNow)
		c.bots = evidence
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

func FuzzParseBotEvidence(f *testing.F) {
	f.Add([]byte(periodEvidence))
	f.Add([]byte(`{"format_version":1,"d2_revision":"` + d2Revision + `","config_sha256":"` + d2Config + `"}`))
	f.Add([]byte(`{"format_version":1,"d2_revision":"` + d2Revision + `","config_sha256":"` + d2Config + `","proofs":[]}`))
	f.Add([]byte(`{"format_version":1,"proofs":null}`))
	f.Add([]byte(`{"format_version":1,"format_version":1}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		e, err := parseBotEvidence(raw)
		if err != nil {
			if !errors.Is(err, errBotEvidence) {
				t.Fatalf("evidence refusal is not private: %v", err)
			}
			return
		}
		encoded, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = parseBotEvidence(encoded); err != nil {
			t.Fatalf("accepted evidence cannot round trip: %v", err)
		}
		if len(e.Proofs) == 0 {
			return
		}
		from, to := e.Proofs[0].From, e.Proofs[0].To
		for _, p := range e.Proofs {
			if p.From.Before(from) {
				from = p.From
			}
			if p.To.After(to) {
				to = p.To
			}
		}
		check := func(bot string, addr netip.Addr) {
			if e.proof(bot, addr, from.Add(-time.Nanosecond)) != "" || e.proof(bot, addr, to) != "" {
				t.Fatal("evidence produced a proof outside every validity interval")
			}
		}
		for bot, proofs := range e.ranges {
			for _, p := range proofs {
				check(bot, p.prefix.Addr())
			}
		}
		for bot, proofs := range e.dns {
			for _, p := range proofs {
				check(bot, p.addr)
			}
		}
	})
}
