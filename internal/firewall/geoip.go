package firewall

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	geoIPBaseURL   = "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/"
	geoIPBaseURLv6 = "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv6/"
)

// UpdateGeoIPDB downloads country CIDR lists from a public source.
// Creates one file per country code per family: {dbPath}/{CC}.cidr (IPv4)
// and {dbPath}/{CC}.cidr6 (IPv6). A country is counted as updated if either
// family downloaded; the IPv6 list is best-effort so a country with no v6
// allocation does not fail the update.
func UpdateGeoIPDB(dbPath string, countryCodes []string) (int, error) {
	if err := os.MkdirAll(dbPath, 0700); err != nil {
		return 0, fmt.Errorf("creating geoip directory: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	updated := 0

	for _, code := range countryCodes {
		code = strings.ToLower(strings.TrimSpace(code))
		if len(code) != 2 {
			continue
		}

		cc := strings.ToUpper(code)
		v4 := downloadCIDRFile(client, geoIPBaseURL+code+".cidr", filepath.Join(dbPath, cc+".cidr"))
		v6 := downloadCIDRFile(client, geoIPBaseURLv6+code+".cidr", filepath.Join(dbPath, cc+".cidr6"))
		if v4 || v6 {
			updated++
		}
	}

	return updated, nil
}

// downloadCIDRFile fetches url into outPath atomically. Returns false (and
// logs) on any HTTP, write, or too-small-payload condition so the caller can
// treat each family independently.
func downloadCIDRFile(client *http.Client, url, outPath string) bool {
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "geoip: error downloading %s: %v\n", url, err)
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "geoip: %s returned HTTP %d\n", url, resp.StatusCode)
		return false
	}

	tmpPath := outPath + ".tmp"
	// #nosec G304 -- filepath.Join under operator-configured dbPath; code from fixed list.
	f, err := os.Create(tmpPath)
	if err != nil {
		return false
	}
	n, _ := io.Copy(f, resp.Body)
	f.Close()
	if n < 10 {
		os.Remove(tmpPath)
		fmt.Fprintf(os.Stderr, "geoip: %s too small (%d bytes), skipping\n", url, n)
		return false
	}
	_ = os.Rename(tmpPath, outPath)
	fmt.Fprintf(os.Stderr, "geoip: updated %s (%d bytes)\n", outPath, n)
	return true
}

// LookupIP finds which country CIDR files contain the given IP.
// Returns matching country codes.
func LookupIP(dbPath string, ip string) []string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil
	}

	// IPv4 (incl. v4-mapped) matches against .cidr files; IPv6 against .cidr6.
	var suffix string
	var needle net.IP
	if ip4 := parsed.To4(); ip4 != nil {
		suffix = ".cidr"
		needle = ip4
	} else {
		suffix = ".cidr6"
		needle = parsed.To16()
	}
	if needle == nil {
		return nil
	}

	entries, err := os.ReadDir(dbPath)
	if err != nil {
		return nil
	}

	var matches []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), suffix) {
			continue
		}
		code := strings.TrimSuffix(entry.Name(), suffix)
		if containsIP(filepath.Join(dbPath, entry.Name()), needle) {
			matches = append(matches, code)
		}
	}
	return matches
}

func containsIP(cidrFile string, ip net.IP) bool {
	// #nosec G304 -- cidrFile is filepath.Join under operator-configured dbPath.
	f, err := os.Open(cidrFile)
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, network, err := net.ParseCIDR(line)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
