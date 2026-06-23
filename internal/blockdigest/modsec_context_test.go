package blockdigest

import (
	"strings"
	"testing"
	"time"
)

func TestObserveEnrichesModSecRecord(t *testing.T) {
	var gotIP string
	c := New(Options{
		SendOn: "any", Interval: time.Hour, MinBlock: 1,
		Now:       func() time.Time { return time.Unix(0, 0) },
		CountryOf: func(string) string { return "RO" },
		EnrichModSec: func(ip string) ([]string, []string) {
			gotIP = ip
			return []string{"shop.example.ro"},
				[]string{"GET /vendor/phpunit/eval-stdin.php", "POST /cgi-bin/.%2e/bin/sh"}
		},
	})
	c.Observe("203.0.113.40", "CSM rule escalation: 20+ denies from 203.0.113.40 within 4h0m0s", time.Unix(0, 0))

	if gotIP != "203.0.113.40" {
		t.Errorf("EnrichModSec called with ip %q, want 203.0.113.40", gotIP)
	}
	d := c.Drain()
	if len(d.Records) != 1 {
		t.Fatalf("records = %d, want 1", len(d.Records))
	}
	r := d.Records[0]
	if len(r.Domains) != 1 || r.Domains[0] != "shop.example.ro" {
		t.Errorf("record domains = %v, want [shop.example.ro]", r.Domains)
	}
	if len(r.URIs) != 2 || r.URIs[0] != "GET /vendor/phpunit/eval-stdin.php" {
		t.Errorf("record uris = %v", r.URIs)
	}
}

func TestObserveSkipsEnrichForNonModSec(t *testing.T) {
	called := false
	c := New(Options{
		SendOn: "any", Interval: time.Hour, MinBlock: 1,
		Now:          func() time.Time { return time.Unix(0, 0) },
		CountryOf:    func(string) string { return "RO" },
		EnrichModSec: func(string) ([]string, []string) { called = true; return nil, nil },
	})
	c.Observe("203.0.113.41", "Mail auth brute force from 203.0.113.41: 5 failed auths in 10m0s", time.Unix(0, 0))
	if called {
		t.Errorf("EnrichModSec called for non-modsec category block")
	}
}

func TestObserveWithoutEnricherLeavesContextEmpty(t *testing.T) {
	c := New(Options{
		SendOn: "any", Interval: time.Hour, MinBlock: 1,
		Now:       func() time.Time { return time.Unix(0, 0) },
		CountryOf: func(string) string { return "RO" },
	})
	c.Observe("203.0.113.42", "CSM rule escalation: 20+ denies", time.Unix(0, 0))
	d := c.Drain()
	if len(d.Records) != 1 {
		t.Fatalf("records = %d, want 1", len(d.Records))
	}
	if len(d.Records[0].Domains) != 0 || len(d.Records[0].URIs) != 0 {
		t.Errorf("expected empty context with nil enricher, got domains=%v uris=%v",
			d.Records[0].Domains, d.Records[0].URIs)
	}
}

func TestRenderBodyShowsModSecTargets(t *testing.T) {
	c := sampleCollector()
	d := Digest{
		Window: time.Hour, Countries: []string{"RO"}, Total: 2, AttackerCount: 2,
		ByCountry:  map[string]int{"RO": 2},
		ByReason:   map[string]int{"CSM rule escalation": 2},
		ByCategory: map[string]int{"modsec": 2},
		Records: []Record{
			{IP: "203.0.113.40", Country: "RO", Reason: "CSM rule escalation: 20+ denies",
				Bucket: BucketAttacker, Category: "modsec",
				Domains: []string{"shop.example.ro"},
				URIs:    []string{"GET /vendor/phpunit/eval-stdin.php"}, TS: time.Unix(10, 0).UTC()},
			{IP: "203.0.113.50", Country: "RO", Reason: "CSM rule escalation: 30+ denies",
				Bucket: BucketAttacker, Category: "modsec",
				URIs: []string{"POST /cgi-bin/.%2e/bin/sh"}, TS: time.Unix(20, 0).UTC()},
		},
	}
	b := c.renderBody(d)
	if !strings.Contains(b, "shop.example.ro") {
		t.Errorf("body missing target domain:\n%s", b)
	}
	if !strings.Contains(b, "/vendor/phpunit/eval-stdin.php") {
		t.Errorf("body missing top URI:\n%s", b)
	}
	if !strings.Contains(b, "/cgi-bin/.%2e/bin/sh") {
		t.Errorf("body missing second IP's URI:\n%s", b)
	}
	if !strings.Contains(b, "no customer domain") {
		t.Errorf("body missing IP-scan hint for domain-less record:\n%s", b)
	}
}

func TestBuildPayloadIncludesModSecTargets(t *testing.T) {
	c := sampleCollector()
	d := Digest{
		Window: time.Hour, Countries: []string{"RO"}, Total: 1, AttackerCount: 1,
		ByCountry:  map[string]int{"RO": 1},
		ByReason:   map[string]int{"CSM rule escalation": 1},
		ByCategory: map[string]int{"modsec": 1},
		Records: []Record{
			{IP: "203.0.113.40", Country: "RO", Reason: "CSM rule escalation: 20+ denies",
				Bucket: BucketAttacker, Category: "modsec",
				Domains: []string{"shop.example.ro"},
				URIs:    []string{"GET /vendor/phpunit/eval-stdin.php"}, TS: time.Unix(10, 0).UTC()},
		},
	}
	p := c.buildPayload("block_digest", d)
	if len(p.CSM.Blocks) != 1 {
		t.Fatalf("blocks = %d, want 1", len(p.CSM.Blocks))
	}
	if len(p.CSM.Blocks[0].Domains) != 1 || p.CSM.Blocks[0].Domains[0] != "shop.example.ro" {
		t.Errorf("block domains = %v", p.CSM.Blocks[0].Domains)
	}
	if len(p.CSM.Blocks[0].URIs) != 1 || p.CSM.Blocks[0].URIs[0] != "GET /vendor/phpunit/eval-stdin.php" {
		t.Errorf("block uris = %v", p.CSM.Blocks[0].URIs)
	}
}
