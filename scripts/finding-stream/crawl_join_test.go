package main

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// scripts/domlog-stream derives site and account pseudonyms exactly as
// this anonymizer does, so a converted domlog stream joins finding streams
// on account and UTC minute. Its round-trip test pins the same vectors.
func TestCrawlStreamPseudonymVectors(t *testing.T) {
	a := NewAnonymizer(testSalt())
	out := a.Event(alert.AuditEvent{V: 1, Timestamp: time.Date(2026, 9, 26, 19, 12, 30, 0, time.UTC), Severity: "high",
		Check: "lve_limit", Message: "limit reached", Hostname: "host.example", TenantID: "acct1", Domain: "example.com"})
	if out.TenantID != "acct-7044eb" || out.Domain != "dom-a01dff.example" {
		t.Fatalf("pseudonyms tenant %q domain %q", out.TenantID, out.Domain)
	}
	if got := a.Domain("shop.example"); got != "dom-dcef08.example" {
		t.Fatalf("second site pseudonym %q", got)
	}
	if !out.Timestamp.Equal(time.Date(2026, 9, 26, 19, 12, 30, 0, time.UTC)) {
		t.Fatal("the join minute changed")
	}
}
