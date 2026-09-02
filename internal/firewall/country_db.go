package firewall

import "path/filepath"

// CountryDBDir returns the directory holding the per-country CIDR files:
// country_db_path when set, otherwise the geoip directory under the state
// path, which is where `csm firewall update-geoip` writes. Every consumer
// (engine, CLI update and lookup) resolves through here so an empty setting
// cannot leave country blocking armed on one surface and inert on another.
func CountryDBDir(cfg *FirewallConfig, statePath string) string {
	if cfg != nil && cfg.CountryDBPath != "" {
		return cfg.CountryDBPath
	}
	return filepath.Join(statePath, "geoip")
}

// countryBlockingActive reports whether the operator asked for country
// blocking. The DB directory always resolves, so the code list alone decides.
func countryBlockingActive(cfg *FirewallConfig) bool {
	return cfg != nil && len(cfg.CountryBlock) > 0
}
