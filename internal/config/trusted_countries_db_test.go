package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFakeGeoIPDB(t *testing.T, statePath, edition string) {
	t.Helper()
	dir := filepath.Join(statePath, "geoip")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, edition+".mmdb"), []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
}

// Credentials only authorize a download. They say nothing about whether a
// database is present, so validating them is not the same as validating that
// trusted_countries can work.
//
// This was demonstrated in production: an AbuseIPDB key was pasted into
// geoip.license_key, MaxMind returned 401, no database was ever downloaded --
// and `csm validate` reported "Validation passed" while `csm doctor` reported
// "Overall: OK". A wrong-but-present credential looked more configured than an
// empty one did, and only `csm update-geoip` surfaced the failure.
func TestValidateWarnsTrustedCountriesWithoutDatabase(t *testing.T) {
	cfg := baseValidationConfig()
	cfg.Suppressions.TrustedCountries = []string{"RO"}
	cfg.StatePath = t.TempDir()
	// Credentials look complete; the database is absent.
	cfg.GeoIP.AccountID = "123456"
	cfg.GeoIP.LicenseKey = strings.Repeat("k", 40)

	results := Validate(cfg)

	if !hasResult(results, "warn", "suppressions.trusted_countries") {
		t.Fatal("no warning when credentials are set but no database exists")
	}
	msg := trustedCountriesMessage(results)
	if !strings.Contains(strings.ToLower(msg), "database") {
		t.Errorf("warning does not mention the missing database: %q", msg)
	}
}

// A database provisioned by any means satisfies the requirement, whether or
// not download credentials are configured. Distribution packages and images
// ship one without ever calling MaxMind.
func TestValidateAcceptsProvisionedDatabaseWithoutCredentials(t *testing.T) {
	cfg := baseValidationConfig()
	cfg.Suppressions.TrustedCountries = []string{"RO"}
	cfg.StatePath = t.TempDir()
	cfg.GeoIP.AccountID = ""
	cfg.GeoIP.LicenseKey = ""
	writeFakeGeoIPDB(t, cfg.StatePath, "GeoLite2-City")

	if hasResult(Validate(cfg), "warn", "suppressions.trusted_countries") {
		t.Error("warned despite a City database being present on disk")
	}
}

// No trusted countries means nothing here depends on GeoIP at all.
func TestValidateSilentWithoutTrustedCountriesOrDatabase(t *testing.T) {
	cfg := baseValidationConfig()
	cfg.Suppressions.TrustedCountries = nil
	cfg.StatePath = t.TempDir()

	if hasResult(Validate(cfg), "warn", "suppressions.trusted_countries") {
		t.Error("warned when no trusted countries are configured")
	}
}
