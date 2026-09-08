package main

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/geoip"
)

// `csm firewall lookup` opened the ASN database on every call and then
// printed only the country, so the operator most likely to run it -- someone
// identifying an attacking address -- had to go elsewhere for the network it
// belongs to. Loading a database and discarding its answer is the part worth
// fixing; the loader's own "geoip: loaded ..." lines already go to stderr, so
// stdout was never polluted.
func TestGeoIPReportLinesIncludeNetworkWhenKnown(t *testing.T) {
	lines := geoIPReportLines([]string{"US"}, geoip.Info{
		Country: "US", City: "Mountain View", ASN: 15169, ASOrg: "Google LLC",
	})

	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "COUNTRY  US") {
		t.Errorf("country line missing: %q", joined)
	}
	if !strings.Contains(joined, "15169") || !strings.Contains(joined, "Google LLC") {
		t.Errorf("ASN and organisation not reported: %q", joined)
	}
	if !strings.Contains(joined, "Mountain View") {
		t.Errorf("city not reported though the City database supplied one: %q", joined)
	}
}

// A country-block store answers with a country and nothing else. Printing
// empty "ASN" or "CITY" labels for it would suggest the lookup failed rather
// than that the data was never there.
func TestGeoIPReportLinesOmitUnknownFields(t *testing.T) {
	lines := geoIPReportLines([]string{"RO"}, geoip.Info{})

	if len(lines) != 1 {
		t.Fatalf("got %d lines for a country-only result, want 1: %q", len(lines), lines)
	}
	if !strings.Contains(lines[0], "RO") {
		t.Errorf("country line = %q, want it to name RO", lines[0])
	}
	for _, label := range []string{"ASN", "CITY", "NETWORK"} {
		if strings.Contains(lines[0], label) {
			t.Errorf("emitted an empty %s field: %q", label, lines[0])
		}
	}
}

// Multiple countries come back from the country-block store as a list; the
// ASN belongs to the address, not to any one of them, so it stays a separate
// line rather than being appended to the country list.
func TestGeoIPReportLinesKeepMultipleCountriesOnOneLine(t *testing.T) {
	lines := geoIPReportLines([]string{"US", "CA"}, geoip.Info{ASN: 15169, ASOrg: "Google LLC"})

	if !strings.Contains(lines[0], "US, CA") {
		t.Errorf("first line = %q, want both countries", lines[0])
	}
	if strings.Contains(lines[0], "15169") {
		t.Errorf("ASN was folded into the country line: %q", lines[0])
	}
	if len(lines) < 2 {
		t.Fatal("ASN line missing when countries are present")
	}
}
