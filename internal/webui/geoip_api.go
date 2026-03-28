package webui

import (
	"net"
	"net/http"

	"github.com/pidginhost/cpanel-security-monitor/internal/geoip"
)

// geoIPDB is set by the daemon when MaxMind databases are available.
var geoIPDB *geoip.DB

// SetGeoIPDB sets the GeoIP database for IP lookups.
func SetGeoIPDB(db *geoip.DB) {
	geoIPDB = db
}

// apiGeoIPLookup returns geolocation info for an IP.
// GET /api/v1/geoip?ip=1.2.3.4          — fast local lookup (country + ASN)
// GET /api/v1/geoip?ip=1.2.3.4&detail=1 — includes RDAP org/ISP (may take 1-3s)
func (s *Server) apiGeoIPLookup(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		writeJSONError(w, "ip parameter required", http.StatusBadRequest)
		return
	}
	if net.ParseIP(ip) == nil {
		writeJSONError(w, "invalid IP address", http.StatusBadRequest)
		return
	}

	if geoIPDB == nil {
		writeJSONError(w, "GeoIP databases not loaded (place GeoLite2-City.mmdb and GeoLite2-ASN.mmdb in /opt/csm/geoip/)", http.StatusServiceUnavailable)
		return
	}

	var info geoip.Info
	if r.URL.Query().Get("detail") == "1" {
		info = geoIPDB.LookupWithRDAP(ip)
	} else {
		info = geoIPDB.Lookup(ip)
	}

	writeJSON(w, info)
}
