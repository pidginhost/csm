package config

import (
	"strings"
	"testing"
)

func trustedCountriesMessage(results []ValidationResult) string {
	for _, r := range results {
		if r.Field == "suppressions.trusted_countries" {
			return r.Message
		}
	}
	return ""
}

// trusted_countries is resolved by looking the address up in the GeoIP
// database. With no database configured the lookup returns nothing and every
// address is untrusted, so the setting silently does nothing.
//
// This matters because operators set it as a lockout safety net -- keep your
// own country here so a misclick from the office never blocks you -- and a
// safety net that is quietly inert is worse than none, because it is believed.
func TestValidateWarnsTrustedCountriesWithoutGeoIP(t *testing.T) {
	cfg := baseValidationConfig()
	cfg.Suppressions.TrustedCountries = []string{"RO"}
	cfg.GeoIP.AccountID = ""
	cfg.GeoIP.LicenseKey = ""

	results := Validate(cfg)

	if !hasResult(results, "warn", "suppressions.trusted_countries") {
		t.Fatal("no warning for trusted_countries configured without GeoIP credentials")
	}
	if msg := trustedCountriesMessage(results); !strings.Contains(strings.ToLower(msg), "geoip") {
		t.Errorf("warning does not name GeoIP, so it does not tell the operator what to fix: %q", msg)
	}
	if msg := trustedCountriesMessage(results); !strings.Contains(msg, "locally installed") {
		t.Errorf("missing download credentials do not prevent using a locally installed database: %q", msg)
	}
}

// With credentials present the database can be fetched, so there is nothing to
// warn about.
func TestValidateAcceptsTrustedCountriesWithGeoIP(t *testing.T) {
	cfg := baseValidationConfig()
	cfg.Suppressions.TrustedCountries = []string{"RO"}
	cfg.GeoIP.AccountID = "123456"
	cfg.GeoIP.LicenseKey = "not-a-real-key"

	if hasResult(Validate(cfg), "warn", "suppressions.trusted_countries") {
		t.Error("warned about trusted_countries even though GeoIP credentials are configured")
	}
}

// No trusted countries means nothing here depends on GeoIP.
func TestValidateSilentWhenNoTrustedCountries(t *testing.T) {
	cfg := baseValidationConfig()
	cfg.Suppressions.TrustedCountries = nil
	cfg.GeoIP.AccountID = ""
	cfg.GeoIP.LicenseKey = ""

	if hasResult(Validate(cfg), "warn", "suppressions.trusted_countries") {
		t.Error("warned about trusted_countries when none are configured")
	}
}

// An invalid code must still be an error, not downgraded by the new warning.
func TestValidateStillRejectsMalformedCountryCode(t *testing.T) {
	cfg := baseValidationConfig()
	cfg.Suppressions.TrustedCountries = []string{"ROU"}
	cfg.GeoIP.AccountID = "123456"
	cfg.GeoIP.LicenseKey = "not-a-real-key"

	if !hasResult(Validate(cfg), "error", "suppressions.trusted_countries") {
		t.Error("malformed country code no longer reported as an error")
	}
}
