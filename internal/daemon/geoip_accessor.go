package daemon

import (
	"strings"
	"sync/atomic"

	"github.com/pidginhost/csm/internal/geoip"
)

// daemonGeoIPDB is a package-level pointer to the GeoIP database, set once
// during daemon init and read by log watcher handlers for country filtering.
var daemonGeoIPDB atomic.Pointer[geoip.DB]

// setGeoIPDB stores the GeoIP database for daemon-wide use.
func setGeoIPDB(db *geoip.DB) {
	daemonGeoIPDB.Store(db)
}

// getGeoIPDB returns the daemon's GeoIP database, or nil.
func getGeoIPDB() *geoip.DB {
	return daemonGeoIPDB.Load()
}

// isTrustedCountry checks if an IP's country is in the trusted list.
// Returns false if GeoIP is unavailable or country can't be resolved.
func isTrustedCountry(ip string, trustedCountries []string) bool {
	if len(trustedCountries) == 0 {
		return false
	}
	db := getGeoIPDB()
	if db == nil {
		return false
	}
	info := db.Lookup(ip)
	if info.Country == "" {
		return false
	}
	for _, tc := range trustedCountries {
		if strings.EqualFold(info.Country, tc) {
			return true
		}
	}
	return false
}
