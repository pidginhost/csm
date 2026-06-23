package blockdigest

import (
	"strings"
	"testing"
	"time"
)

func TestCategoryOf(t *testing.T) {
	cases := []struct {
		reason string
		want   string
	}{
		{"ModSecurity escalation: 5+ denies from 1.2.3.4 within 4h0m0s", "modsec"},
		{"CSM rule escalation: 5+ denies from 1.2.3.4 within 4h0m0s", "modsec"},
		{"rule escalation: 5+ denies from 1.2.3.4 within 4h0m0s", "modsec"},
		{"WAF blocking high-volume attacker: 203.0.113.55 (42 blocked requests)", "modsec"},
		{"XML-RPC abuse from 1.2.3.4: 70 requests", "xmlrpc"},
		{"WordPress login brute force from 1.2.3.4: 40 attempts", "wp-bruteforce"},
		{"Admin panel brute force from 1.2.3.4: 10 POSTs in 5m0s (real-time)", "admin-bruteforce"},
		{"Mail auth brute force from 1.2.3.4: 5 failed auths in 10m0s", "mail-bruteforce"},
		{"SMTP brute force from 1.2.3.4: 5 failed auths in 10m0s", "mail-bruteforce"},
		{"SMTP probe abuse from 1.2.3.4: 50 connections in 10m0s", "smtp-probe"},
		{"Mail account compromise: successful login for x", "mail-compromise"},
		{"Compromised email account user@example.com authenticated from bulk mail service sendblaster.", "mail-compromise"},
		{"Email account user@example.com sent from cloud IPs - credentials compromised", "mail-compromise"},
		{"FTP brute force from 1.2.3.4: 12 failed attempts in 5m", "ftp-bruteforce"},
		{"URL scanner profile from 1.2.3.4: 50 of 50 requests", "http-scanner"},
		{"HTTP request flood from 1.2.3.4: 250 requests", "http-flood"},
		{"Unverified claimed bot from 1.2.3.4: request flood", "ua-spoof"},
		{"User-Agent spoof from 1.2.3.4: claimed bot failed rDNS", "ua-spoof"},
		{"High local threat score: 1.2.3.4 (score 80/100, 10 attacks)", "local-threat"},
		{"Known malicious IP accessing server: 1.2.3.4 (Abuseipdb score: 90/100)", "threat-intel"},
		{"known command-and-control server", "threat-intel"},
		{"Connection to known C2 IP: 1.2.3.4:443", "threat-intel"},
		{"something totally unrecognized", "other"},
	}
	for _, tc := range cases {
		if got := categoryOf(tc.reason); got != tc.want {
			t.Errorf("categoryOf(%q) = %q, want %q", tc.reason, got, tc.want)
		}
	}
}

func TestDrainByCategory(t *testing.T) {
	c := New(Options{
		Countries: nil, SendOn: "any", Interval: time.Hour, MinBlock: 1,
		Now:       func() time.Time { return time.Unix(0, 0) },
		CountryOf: func(string) string { return "RO" },
	})
	ts := time.Unix(0, 0)
	c.Observe("203.0.113.10", "ModSecurity escalation: x", ts)
	c.Observe("203.0.113.11", "XML-RPC abuse from 203.0.113.11: 70 requests", ts)
	c.Observe("203.0.113.12", "Mail auth brute force from 203.0.113.12: 5 failed auths in 10m0s", ts)
	c.Observe("203.0.113.13", "WAF blocking high-volume attacker: 203.0.113.13 (42 blocked requests)", ts)
	c.Observe("203.0.113.14", "SMTP brute force from 203.0.113.14: 5 failed auths in 10m0s", ts)
	c.Observe("203.0.113.15", "HTTP request flood from 203.0.113.15: 250 requests", ts)
	c.Observe("203.0.113.16", "URL scanner profile from 203.0.113.16: 50 of 50 requests", ts)

	d := c.Drain()
	if d.ByCategory["modsec"] != 2 {
		t.Errorf("ByCategory[modsec] = %d, want 2", d.ByCategory["modsec"])
	}
	if d.ByCategory["xmlrpc"] != 1 {
		t.Errorf("ByCategory[xmlrpc] = %d, want 1", d.ByCategory["xmlrpc"])
	}
	if d.ByCategory["mail-bruteforce"] != 2 {
		t.Errorf("ByCategory[mail-bruteforce] = %d, want 2", d.ByCategory["mail-bruteforce"])
	}
	if d.ByCategory["http-flood"] != 1 {
		t.Errorf("ByCategory[http-flood] = %d, want 1", d.ByCategory["http-flood"])
	}
	if d.ByCategory["http-scanner"] != 1 {
		t.Errorf("ByCategory[http-scanner] = %d, want 1", d.ByCategory["http-scanner"])
	}
	for _, r := range d.Records {
		if r.Category == "" {
			t.Errorf("Record %s has empty Category", r.IP)
		}
	}
}

func TestRenderBodyHasModSecSection(t *testing.T) {
	c := sampleCollector()
	d := Digest{
		Window: time.Hour, Countries: []string{"RO"}, Total: 2,
		CustomerCount: 0, AttackerCount: 2,
		ByCountry:  map[string]int{"RO": 2},
		ByReason:   map[string]int{"ModSecurity escalation": 1, "XML-RPC abuse from 203.0.113.50": 1},
		ByCategory: map[string]int{"modsec": 1, "xmlrpc": 1},
		Records: []Record{
			{IP: "203.0.113.40", Country: "RO", Reason: "ModSecurity escalation: 5+ denies", Bucket: BucketAttacker, Category: "modsec", TS: time.Unix(10, 0).UTC()},
			{IP: "203.0.113.50", Country: "RO", Reason: "XML-RPC abuse from 203.0.113.50: 70 requests", Bucket: BucketAttacker, Category: "xmlrpc", TS: time.Unix(20, 0).UTC()},
		},
	}
	b := c.renderBody(d)
	if !strings.Contains(b, "ModSecurity blocks") {
		t.Errorf("body missing ModSecurity section header:\n%s", b)
	}
	if !strings.Contains(b, "203.0.113.40") {
		t.Errorf("body missing modsec block IP in section:\n%s", b)
	}
	if !strings.Contains(b, "By category:") {
		t.Errorf("body missing by-category breakdown:\n%s", b)
	}
}

func TestBuildPayloadByCategory(t *testing.T) {
	c := sampleCollector()
	d := Digest{
		Window: time.Hour, Countries: []string{"RO"}, Total: 1, AttackerCount: 1,
		ByCountry:  map[string]int{"RO": 1},
		ByReason:   map[string]int{"ModSecurity escalation": 1},
		ByCategory: map[string]int{"modsec": 1},
		Records: []Record{
			{IP: "203.0.113.40", Country: "RO", Reason: "ModSecurity escalation: 5+ denies", Bucket: BucketAttacker, Category: "modsec", TS: time.Unix(10, 0).UTC()},
		},
	}
	p := c.buildPayload("block_digest", d)
	if p.CSM.Counts.ByCategory["modsec"] != 1 {
		t.Errorf("counts.by_category[modsec] = %d, want 1", p.CSM.Counts.ByCategory["modsec"])
	}
	if len(p.CSM.Blocks) != 1 || p.CSM.Blocks[0].Category != "modsec" {
		t.Errorf("block category wrong: %+v", p.CSM.Blocks)
	}
}
