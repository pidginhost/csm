package alert

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// Audit sinks must keep the public subnets when sprays no longer put them
// in SourceIP. Internal response evidence must stay out of the wire record.
func TestAuditJSONLRetainsFindingCIDRs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink := mustNewJSONLSink(t, path)
	for _, check := range []string{"mail_subnet_spray", "smtp_subnet_spray", "http_asn_crawl", "mail_bruteforce"} {
		f := Finding{Check: check, Timestamp: time.Unix(1_700_000_000, 0)}
		if check != "mail_bruteforce" {
			f.CIDRs = []string{"203.0.113.0/24", "198.51.100.0/24"}
			if check != "http_asn_crawl" {
				f.CIDRs = f.CIDRs[:1]
			}
			f.SprayConstituents = []SprayConstituent{{Address: "203.0.113.1"}}
		}
		if err := sink.Emit(NewAuditEvent("host.example", f)); err != nil {
			t.Fatal(err)
		}
	}
	rows := readJSONLines(t, path)
	if len(rows) != 4 {
		t.Fatalf("audit rows = %d, want 4", len(rows))
	}
	for i, want := range [][]any{
		{"203.0.113.0/24"},
		{"203.0.113.0/24"},
		{"203.0.113.0/24", "198.51.100.0/24"},
		nil,
	} {
		got, present := rows[i]["cidrs"]
		if want == nil {
			if present {
				t.Errorf("audit for an address-only finding includes cidrs: %v", got)
			}
		} else if !reflect.DeepEqual(got, want) {
			t.Errorf("audit row %d cidrs = %v, want %v", i, got, want)
		}
		if _, present := rows[i]["spray_constituents"]; present {
			t.Errorf("audit row %d exposes internal constituents", i)
		}
	}
}
