package blockdigest

import (
	"testing"
	"time"
)

func TestResolveCountriesFallback(t *testing.T) {
	if got := ResolveCountries([]string{"ro", "DE"}, []string{"us"}); !eq(got, []string{"RO", "DE"}) {
		t.Errorf("configured wins: %v", got)
	}
	if got := ResolveCountries([]string{" ", ""}, []string{"us", "gb"}); !eq(got, []string{"US", "GB"}) {
		t.Errorf("blank configured falls back: %v", got)
	}
	if got := ResolveCountries(nil, []string{"us", "gb"}); !eq(got, []string{"US", "GB"}) {
		t.Errorf("trusted fallback: %v", got)
	}
	if got := ResolveCountries(nil, nil); len(got) != 0 {
		t.Errorf("empty means all: %v", got)
	}
}

func TestClassifyBucket(t *testing.T) {
	cust := []string{
		"ModSecurity escalation: 5+ denies from 1.2.3.4 within 4h0m0s",
		"XML-RPC abuse from 1.2.3.4: 70 requests",
		"something totally unrecognized",
		"Outbound mail governor tripped but no outbound spam volume observed",
		"Credential backend degraded while checking customer login",
		"local service bound to port c2f0",
	}
	for _, r := range cust {
		if got := classifyBucket(r); got != BucketCustomer {
			t.Errorf("classifyBucket(%q) = %s, want customer", r, got)
		}
	}
	atk := []string{
		"rule escalation: 5+ denies from 1.2.3.4 within 4h0m0s",
		"Mail auth brute force from 1.2.3.4: 5 failed auths in 10m0s",
		"incident web_attack CRITICAL (incident opened)",
		"Mail account compromise: successful login for x",
		"User-Agent spoof from 1.2.3.4: claimed bot failed rDNS",
		"known command-and-control server",
		"Connection to known C2 IP: 198.51.100.7:443",
		"Credential stuffing: 203.0.113.5 failed logins against 12 accounts",
		"Email account user@example.com sent from cloud IPs - credentials compromised",
	}
	for _, r := range atk {
		if got := classifyBucket(r); got != BucketAttacker {
			t.Errorf("classifyBucket(%q) = %s, want attacker", r, got)
		}
	}
}

func TestObserveFiltersByCountryAndDedups(t *testing.T) {
	geo := map[string]string{
		"5.13.0.1": "RO",
		"8.8.8.8":  "US",
		"9.9.9.9":  "",
	}
	c := New(Options{
		Countries: []string{"RO"},
		SendOn:    "any",
		Interval:  time.Hour,
		MinBlock:  1,
		Now:       func() time.Time { return time.Unix(1000, 0) },
		CountryOf: func(ip string) string { return geo[ip] },
	})
	now := time.Unix(1000, 0)
	c.Observe("5.13.0.1", "ModSecurity escalation: x", now)
	c.Observe("5.13.0.1", "ModSecurity escalation: x", now) // dup IP
	c.Observe("8.8.8.8", "rule escalation: y", now)         // US, not watched
	c.Observe("9.9.9.9", "rule escalation: z", now)         // unknown country, watched-set non-empty -> drop
	d := c.Drain()
	if d.Total != 1 {
		t.Fatalf("Total = %d, want 1 (RO deduped)", d.Total)
	}
	if d.CustomerCount != 1 || d.AttackerCount != 0 {
		t.Errorf("customer=%d attacker=%d, want 1/0", d.CustomerCount, d.AttackerCount)
	}
	if d.ByCountry["RO"] != 1 {
		t.Errorf("ByCountry[RO] = %d", d.ByCountry["RO"])
	}
}

func TestObserveAllCountriesWhenSetEmpty(t *testing.T) {
	c := New(Options{
		Countries: nil, // all
		SendOn:    "any",
		Interval:  time.Hour,
		MinBlock:  1,
		Now:       func() time.Time { return time.Unix(0, 0) },
		CountryOf: func(ip string) string { return "" }, // unknown still counts in all-mode
	})
	c.Observe("203.0.113.7", "rule escalation: x", time.Unix(0, 0))
	if d := c.Drain(); d.Total != 1 {
		t.Fatalf("all-mode Total = %d, want 1", d.Total)
	}
}

func TestDrainResetsBuffer(t *testing.T) {
	c := New(Options{Countries: nil, SendOn: "any", Interval: time.Hour, MinBlock: 1,
		Now: func() time.Time { return time.Unix(0, 0) }, CountryOf: func(string) string { return "RO" }})
	c.Observe("1.1.1.1", "x", time.Unix(0, 0))
	c.Drain()
	if d := c.Drain(); d.Total != 0 {
		t.Errorf("second drain Total = %d, want 0", d.Total)
	}
}

func TestDrainDedupPrefersCustomerRiskRecord(t *testing.T) {
	c := New(Options{Countries: nil, SendOn: "any", Interval: time.Hour, MinBlock: 1,
		Now: func() time.Time { return time.Unix(0, 0) }, CountryOf: func(string) string { return "RO" }})
	ts := time.Unix(0, 0)
	c.Observe("203.0.113.9", "rule escalation: x", ts)
	c.Observe("203.0.113.9", "ModSecurity escalation: y", ts.Add(time.Second))

	d := c.Drain()
	if d.Total != 1 {
		t.Fatalf("Total = %d, want 1", d.Total)
	}
	if d.CustomerCount != 1 || d.AttackerCount != 0 {
		t.Fatalf("customer=%d attacker=%d, want 1/0", d.CustomerCount, d.AttackerCount)
	}
	if got := d.ByReason["ModSecurity escalation"]; got != 1 {
		t.Fatalf("ByReason[ModSecurity escalation] = %d, want 1", got)
	}
	if len(d.Records) != 1 || d.Records[0].Bucket != BucketCustomer {
		t.Fatalf("Records = %+v, want one customer record", d.Records)
	}
}

func TestDrainCountriesCannotMutateCollectorOptions(t *testing.T) {
	c := New(Options{Countries: []string{"RO"}, SendOn: "any", Interval: time.Hour, MinBlock: 1,
		Now: func() time.Time { return time.Unix(0, 0) }, CountryOf: func(string) string { return "RO" }})
	c.Observe("203.0.113.7", "rule escalation: x", time.Unix(0, 0))
	d := c.Drain()
	d.Countries[0] = "US"

	c.Observe("203.0.113.8", "rule escalation: y", time.Unix(1, 0))
	if d := c.Drain(); d.Total != 1 {
		t.Fatalf("Total = %d, want 1 after mutating drained Countries", d.Total)
	}
}

func TestObserveWithoutCountryLookupDoesNotPanic(t *testing.T) {
	c := New(Options{Countries: nil, SendOn: "any", Interval: time.Hour, MinBlock: 1})
	c.Observe("203.0.113.7", "rule escalation: x", time.Unix(0, 0))
	if d := c.Drain(); d.Total != 1 {
		t.Fatalf("Total = %d, want 1", d.Total)
	}
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
