package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// `csm firewall lookup` read only the country-block database store, which is
// populated by `csm firewall update-geoip` for the country_block feature. The
// GeoLite2 databases the daemon actually uses live elsewhere, downloaded by
// the top-level `csm update-geoip`. So on a host where GeoIP demonstrably
// worked -- the daemon logging "geoip: loaded .../GeoLite2-City.mmdb" and the
// API resolving 8.8.8.8 to US/Google -- the CLI still reported:
//
//	COUNTRY  unknown (no GeoIP data - run 'csm firewall update-geoip')
//
// The advice compounded it: that command only fills the country-block store
// and refuses outright without firewall.country_block codes configured, so
// following it could never resolve the message.
func TestGeoIPLookupDirsPrefersCountryBlockThenDaemonStore(t *testing.T) {
	countryDir := "/opt/csm/country"
	statePath := "/var/lib/csm/state"

	dirs := geoIPLookupDirs(countryDir, statePath)

	if len(dirs) != 2 {
		t.Fatalf("geoIPLookupDirs returned %d dirs, want 2: %v", len(dirs), dirs)
	}
	if dirs[0] != countryDir {
		t.Errorf("first dir = %q, want the country-block store %q", dirs[0], countryDir)
	}
	want := filepath.Join(statePath, "geoip")
	if dirs[1] != want {
		t.Errorf("second dir = %q, want the daemon store %q", dirs[1], want)
	}
}

// An empty state path must not produce a bare "geoip" relative directory.
func TestGeoIPLookupDirsSkipsEmptyPaths(t *testing.T) {
	if dirs := geoIPLookupDirs("", ""); len(dirs) != 0 {
		t.Errorf("geoIPLookupDirs with no paths = %v, want empty", dirs)
	}
	if dirs := geoIPLookupDirs("", "/var/lib/csm/state"); len(dirs) != 1 {
		t.Errorf("geoIPLookupDirs with only a state path = %v, want one entry", dirs)
	}
}

// The remediation must name the command that actually downloads the databases
// the lookup reads, not the country-block one that cannot help.
func TestGeoIPUnavailableAdviceNamesTheRightCommand(t *testing.T) {
	msg := geoIPUnavailableAdvice()

	if !strings.Contains(msg, "csm update-geoip") {
		t.Errorf("advice does not name `csm update-geoip`: %q", msg)
	}
	if strings.Contains(msg, "firewall update-geoip") {
		t.Errorf("advice still points at the country-block command: %q", msg)
	}
}
