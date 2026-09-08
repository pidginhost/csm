package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/geoip"
)

func TestGeoIPReportLinesWithoutCountry(t *testing.T) {
	want := []string{"ASN      AS64512 (Example Network)"}
	if got := geoIPReportLines(nil, geoip.Info{ASN: 64512, ASOrg: "Example Network"}); !slices.Equal(got, want) {
		t.Fatalf("ASN-only result = %q, want %q", got, want)
	}
	if got := geoIPReportLines(nil, geoip.Info{}); len(got) != 0 {
		t.Fatalf("empty result printed fields: %q", got)
	}
}

func TestFirewallLookupReportsPartialGeoIP(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		countryStore, cityDB bool
	}{
		{"ASN only", false, false},
		{"country store and ASN", true, false},
		{"country store and full GeoIP", true, true},
		{"full GeoIP", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			geoDir := filepath.Join(dir, "geoip")
			countryDir := filepath.Join(dir, "country")
			for _, p := range []string{geoDir, countryDir, filepath.Join(dir, "conf.d")} {
				if err := os.Mkdir(p, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			files := []string{"GeoLite2-ASN.mmdb"}
			if tc.cityDB {
				files = append(files, "GeoLite2-City.mmdb")
			}
			for _, name := range files {
				body, err := os.ReadFile(filepath.Join("testdata", "geoip", name))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(geoDir, name), body, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.countryStore {
				for _, code := range []string{"CA", "US"} {
					if err := os.WriteFile(filepath.Join(countryDir, code+".cidr"), []byte("192.0.2.0/24\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			cfgPath := filepath.Join(dir, "csm.yaml")
			cfg := fmt.Sprintf("state_path: %q\nfirewall:\n  country_db_path: %q\n  country_block: [CA]\n", dir, countryDir)
			if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
				t.Fatal(err)
			}
			prev := os.Args
			os.Args = []string{"csm", "firewall", "lookup", "192.0.2.1", "--config", cfgPath, "--config-dir", filepath.Join(dir, "conf.d")}
			t.Cleanup(func() { os.Args = prev })
			got := captureStdout(t, fwLookup)
			if !strings.Contains(got, "ASN      AS64512 (Example Network)\n") {
				t.Errorf("resolved ASN missing: %q", got)
			}
			if tc.countryStore && (!strings.Contains(got, "COUNTRY  CA, US\n") || !strings.Contains(got, "CA is in country_block list")) {
				t.Errorf("country-store results changed: %q", got)
			}
			if tc.cityDB && (!strings.Contains(got, "CITY     Example City\n") || !strings.Contains(got, "NETWORK  192.0.2.0/24\n")) {
				t.Errorf("resolved city/network missing: %q", got)
			}
		})
	}
}

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
