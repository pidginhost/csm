package firewall

import "testing"

// The engine built the country sets only when country_db_path was set,
// while `csm firewall update-geoip` and `csm firewall lookup` fell back to
// <state_path>/geoip on their own and reported success. With the documented
// default of an empty path, country blocking was silently inert. One
// resolver serves every consumer.
func TestCountryDBDirDefaultsUnderStatePath(t *testing.T) {
	cfg := &FirewallConfig{CountryBlock: []string{"CN"}}
	if got := CountryDBDir(cfg, "/var/lib/csm/state"); got != "/var/lib/csm/state/geoip" {
		t.Fatalf("CountryDBDir = %q, want the geoip directory under the state path", got)
	}
	cfg.CountryDBPath = "/srv/geo"
	if got := CountryDBDir(cfg, "/var/lib/csm/state"); got != "/srv/geo" {
		t.Fatalf("explicit country_db_path overridden: %q", got)
	}
	cfg.CountryDBPath = "custom/geo"
	if got := CountryDBDir(cfg, "/var/lib/csm/state"); got != "custom/geo" {
		t.Fatalf("relative country_db_path re-rooted: %q", got)
	}
}

func TestCountryBlockingActiveDoesNotRequireExplicitPath(t *testing.T) {
	if !countryBlockingActive(&FirewallConfig{CountryBlock: []string{"CN"}}) {
		t.Fatal("country_block with an empty country_db_path must still arm the country sets")
	}
	if countryBlockingActive(&FirewallConfig{CountryDBPath: "/srv/geo"}) {
		t.Fatal("a path without any country codes must not arm the sets")
	}
}
