package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

func TestAnonymizerScrubsAuditCIDRs(t *testing.T) {
	input := alert.AuditEvent{
		Check:   "http_asn_crawl",
		Message: "Subnets: 203.0.113.0/24, 2001:db8:1234::/48",
		CIDRs:   []string{"203.0.113.0/24", "2001:db8:1234::/48"},
	}
	a := NewAnonymizer(testSalt())
	a.Learn([]alert.AuditEvent{input})
	// Only the structured field contains the address in this row. A
	// bypassed transform must be caught before the output is published.
	if len(a.Verify([]alert.AuditEvent{{CIDRs: []string{"203.0.113.0/24"}}})) == 0 {
		t.Error("leak check ignored a raw structured subnet")
	}
	out := a.Event(input)
	if len(out.CIDRs) != 2 {
		t.Fatalf("anonymized subnets = %v, want both", out.CIDRs)
	}
	for i, suffix := range []string{"/24", "/48"} {
		if out.CIDRs[i] == input.CIDRs[i] || !strings.HasSuffix(out.CIDRs[i], suffix) || !strings.Contains(out.Message, out.CIDRs[i]) {
			t.Errorf("subnet %d = %q, want anonymized identity matching the message with prefix %q", i, out.CIDRs[i], suffix)
		}
	}
	if !reflect.DeepEqual(input.CIDRs, []string{"203.0.113.0/24", "2001:db8:1234::/48"}) {
		t.Errorf("anonymization changed the input subnets: %v", input.CIDRs)
	}
	if leaks := a.Verify([]alert.AuditEvent{out}); len(leaks) != 0 {
		t.Errorf("anonymized subnet row still leaks: %v", leaks)
	}
}
