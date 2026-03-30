package webui

import (
	"encoding/json"
	"net"
	"net/http"

	"github.com/pidginhost/cpanel-security-monitor/internal/geoip"
)

// SetGeoIPDB sets the GeoIP database for IP lookups.
func (s *Server) SetGeoIPDB(db *geoip.DB) {
	s.geoIPDB.Store(db)
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

	db := s.geoIPDB.Load()
	if db == nil {
		writeJSONError(w, "GeoIP databases not loaded (place GeoLite2-City.mmdb and GeoLite2-ASN.mmdb in /opt/csm/geoip/)", http.StatusServiceUnavailable)
		return
	}

	var info geoip.Info
	if r.URL.Query().Get("detail") == "1" {
		info = db.LookupWithRDAP(ip)
	} else {
		info = db.Lookup(ip)
	}

	writeJSON(w, info)
}

// apiGeoIPBatch returns geolocation info for multiple IPs.
// POST /api/v1/geoip/batch  body: {"ips": ["1.2.3.4", "5.6.7.8"]}
func (s *Server) apiGeoIPBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IPs []string `json:"ips"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if len(req.IPs) > 500 {
		writeJSONError(w, "maximum 500 IPs per request", http.StatusBadRequest)
		return
	}

	type geoResult struct {
		Country     string `json:"country"`
		CountryName string `json:"country_name"`
		City        string `json:"city"`
		ASOrg       string `json:"as_org"`
		Error       string `json:"error,omitempty"`
	}

	db := s.geoIPDB.Load()
	results := make(map[string]geoResult, len(req.IPs))
	for _, ip := range req.IPs {
		if net.ParseIP(ip) == nil {
			results[ip] = geoResult{Error: "invalid IP format"}
			continue
		}
		if db == nil {
			results[ip] = geoResult{Error: "GeoIP database not loaded"}
			continue
		}
		info := db.Lookup(ip)
		results[ip] = geoResult{
			Country:     info.Country,
			CountryName: info.CountryName,
			City:        info.City,
			ASOrg:       info.ASOrg,
		}
	}

	writeJSON(w, map[string]interface{}{"results": results})
}
