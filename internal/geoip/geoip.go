// Package geoip provides IP geolocation via MaxMind GeoLite2 databases
// and on-demand RDAP lookups for detailed ISP/org information.
package geoip

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

// Info contains geolocation and network information for an IP.
type Info struct {
	IP          string `json:"ip"`
	Country     string `json:"country"`      // ISO 3166-1 alpha-2 (e.g. "US")
	CountryName string `json:"country_name"` // Full name (e.g. "United States")
	City        string `json:"city,omitempty"`
	ASN         uint   `json:"asn,omitempty"`          // Autonomous System Number
	ASOrg       string `json:"as_org,omitempty"`       // AS Organization (ISP)
	Network     string `json:"network,omitempty"`      // CIDR range
	RDAPOrg     string `json:"rdap_org,omitempty"`     // Detailed org from RDAP (on-demand)
	RDAPName    string `json:"rdap_name,omitempty"`    // Network name from RDAP
	RDAPCountry string `json:"rdap_country,omitempty"` // Country from RDAP
}

// DB holds the MaxMind database readers.
type DB struct {
	mu      sync.RWMutex
	cityDB  *maxminddb.Reader
	asnDB   *maxminddb.Reader
	dbDir   string
	rdapMu  sync.Mutex
	rdapTTL map[string]rdapCacheEntry
}

type rdapCacheEntry struct {
	info    Info
	fetched time.Time
}

// MaxMind GeoLite2 record structures
type cityRecord struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
}

type asnRecord struct {
	ASN uint   `maxminddb:"autonomous_system_number"`
	Org string `maxminddb:"autonomous_system_organization"`
}

// Open loads MaxMind databases from the given directory.
// Expects GeoLite2-City.mmdb and/or GeoLite2-ASN.mmdb.
// Returns nil if no databases found (graceful degradation).
func Open(dbDir string) *DB {
	if dbDir == "" {
		return nil
	}

	db := &DB{
		dbDir:   dbDir,
		rdapTTL: make(map[string]rdapCacheEntry),
	}

	cityPath := filepath.Join(dbDir, "GeoLite2-City.mmdb")
	if r, err := maxminddb.Open(cityPath); err == nil {
		db.cityDB = r
		fmt.Fprintf(os.Stderr, "geoip: loaded %s\n", cityPath)
	}

	asnPath := filepath.Join(dbDir, "GeoLite2-ASN.mmdb")
	if r, err := maxminddb.Open(asnPath); err == nil {
		db.asnDB = r
		fmt.Fprintf(os.Stderr, "geoip: loaded %s\n", asnPath)
	}

	if db.cityDB == nil && db.asnDB == nil {
		fmt.Fprintf(os.Stderr, "geoip: no databases found in %s (download GeoLite2-City.mmdb and GeoLite2-ASN.mmdb)\n", dbDir)
		return nil
	}

	return db
}

// Close releases database resources.
func (db *DB) Close() {
	if db == nil {
		return
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.cityDB != nil {
		db.cityDB.Close()
	}
	if db.asnDB != nil {
		db.asnDB.Close()
	}
}

// Lookup returns geolocation info for an IP from local MaxMind databases.
// Fast (microseconds), no network calls.
func (db *DB) Lookup(ip string) Info {
	info := Info{IP: ip}
	if db == nil {
		return info
	}

	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return info
	}

	db.mu.RLock()
	defer db.mu.RUnlock()

	if db.cityDB != nil {
		var record cityRecord
		result := db.cityDB.Lookup(addr)
		if err := result.Decode(&record); err == nil {
			info.Country = record.Country.ISOCode
			info.CountryName = record.Country.Names["en"]
			info.City = record.City.Names["en"]
			if prefix := result.Prefix(); prefix.IsValid() {
				info.Network = prefix.String()
			}
		}
	}

	if db.asnDB != nil {
		var record asnRecord
		result := db.asnDB.Lookup(addr)
		if err := result.Decode(&record); err == nil {
			info.ASN = record.ASN
			info.ASOrg = record.Org
		}
	}

	return info
}

// LookupWithRDAP returns geolocation info plus on-demand RDAP details.
// The RDAP lookup is cached for 24 hours.
func (db *DB) LookupWithRDAP(ip string) Info {
	info := db.Lookup(ip)

	// Check RDAP cache
	db.rdapMu.Lock()
	if cached, ok := db.rdapTTL[ip]; ok && time.Since(cached.fetched) < 24*time.Hour {
		db.rdapMu.Unlock()
		info.RDAPOrg = cached.info.RDAPOrg
		info.RDAPName = cached.info.RDAPName
		info.RDAPCountry = cached.info.RDAPCountry
		return info
	}
	db.rdapMu.Unlock()

	// Fetch from RDAP
	rdapInfo := fetchRDAP(ip)
	info.RDAPOrg = rdapInfo.RDAPOrg
	info.RDAPName = rdapInfo.RDAPName
	info.RDAPCountry = rdapInfo.RDAPCountry

	// Cache
	db.rdapMu.Lock()
	db.rdapTTL[ip] = rdapCacheEntry{info: rdapInfo, fetched: time.Now()}
	// Evict old entries
	if len(db.rdapTTL) > 10000 {
		for k, v := range db.rdapTTL {
			if time.Since(v.fetched) > 24*time.Hour {
				delete(db.rdapTTL, k)
			}
		}
	}
	db.rdapMu.Unlock()

	return info
}

// RDAP lookup — fetches from the appropriate RIR
func fetchRDAP(ip string) Info {
	var info Info
	url := fmt.Sprintf("https://rdap.org/ip/%s", ip)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return info
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return info
	}

	var rdap struct {
		Name     string `json:"name"`
		Country  string `json:"country"`
		Handle   string `json:"handle"`
		Entities []struct {
			VCardArray []interface{} `json:"vcardArray"`
			Roles      []string      `json:"roles"`
		} `json:"entities"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&rdap); err != nil {
		return info
	}

	info.RDAPName = rdap.Name
	info.RDAPCountry = rdap.Country

	// Extract org name from entities
	for _, entity := range rdap.Entities {
		for _, role := range entity.Roles {
			if role == "registrant" || role == "abuse" {
				if len(entity.VCardArray) >= 2 {
					if props, ok := entity.VCardArray[1].([]interface{}); ok {
						for _, prop := range props {
							if arr, ok := prop.([]interface{}); ok && len(arr) >= 4 {
								if name, ok := arr[0].(string); ok && name == "fn" {
									if val, ok := arr[3].(string); ok {
										info.RDAPOrg = val
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return info
}
