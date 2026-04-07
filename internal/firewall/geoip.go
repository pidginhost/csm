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

const geoIPBaseURL = "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/"

// UpdateGeoIPDB downloads country CIDR lists from a public source.
// Creates one file per country code: {dbPath}/{CC}.cidr
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

		url := geoIPBaseURL + code + ".cidr"
		resp, err := client.Get(url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "geoip: error downloading %s: %v\n", code, err)
			continue
		}

		if resp.StatusCode != 200 {
			resp.Body.Close()
			fmt.Fprintf(os.Stderr, "geoip: %s returned HTTP %d\n", code, resp.StatusCode)
			continue
		}

		outPath := filepath.Join(dbPath, strings.ToUpper(code)+".cidr")
		tmpPath := outPath + ".tmp"
		f, err := os.Create(tmpPath)
		if err != nil {
			resp.Body.Close()
			continue
		}

		n, _ := io.Copy(f, resp.Body)
		f.Close()
		resp.Body.Close()

		if n < 10 {
			os.Remove(tmpPath)
			fmt.Fprintf(os.Stderr, "geoip: %s too small (%d bytes), skipping\n", code, n)
			continue
		}

		_ = os.Rename(tmpPath, outPath)
		updated++
		fmt.Fprintf(os.Stderr, "geoip: updated %s (%d bytes)\n", strings.ToUpper(code), n)
	}

	return updated, nil
}

// LookupIP finds which country CIDR files contain the given IP.
// Returns matching country codes.
func LookupIP(dbPath string, ip string) []string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil
	}
	ip4 := parsed.To4()
	if ip4 == nil {
		return nil
	}

	entries, err := os.ReadDir(dbPath)
	if err != nil {
		return nil
	}

	var matches []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".cidr") {
			continue
		}

		code := strings.TrimSuffix(entry.Name(), ".cidr")
		if containsIP(filepath.Join(dbPath, entry.Name()), ip4) {
			matches = append(matches, code)
		}
	}
	return matches
}

func containsIP(cidrFile string, ip net.IP) bool {
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
