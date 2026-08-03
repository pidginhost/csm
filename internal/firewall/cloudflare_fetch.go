package firewall

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	cfIPv4URL = "https://www.cloudflare.com/ips-v4"
	cfIPv6URL = "https://www.cloudflare.com/ips-v6"
)

// FetchCloudflareIPs downloads the current Cloudflare IP ranges.
func FetchCloudflareIPs() (ipv4, ipv6 []string, err error) {
	client := &http.Client{Timeout: 30 * time.Second}

	ipv4, err = fetchCIDRList(client, cfIPv4URL)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching CF IPv4: %w", err)
	}

	ipv6, err = fetchCIDRList(client, cfIPv6URL)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching CF IPv6: %w", err)
	}

	return ipv4, ipv6, nil
}

// fetchCIDRList fetches a URL and parses one CIDR per line.
func fetchCIDRList(client *http.Client, url string) ([]string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	return parseCloudflareResponse(bufio.NewScanner(resp.Body)), nil
}

// parseCloudflareResponse parses lines from a scanner, returning valid CIDRs.
// Skips blank lines, comments, and invalid entries.
func parseCloudflareResponse(scanner *bufio.Scanner) []string {
	var cidrs []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, _, err := net.ParseCIDR(line)
		if err != nil {
			continue
		}
		cidrs = append(cidrs, line)
	}
	return cidrs
}

// SaveCFState persists the Cloudflare CIDRs for status display.
func SaveCFState(statePath string, ipv4, ipv6 []string, refreshed time.Time) {
	path := statePath
	if !strings.HasSuffix(path, "/firewall") {
		path += "/firewall"
	}
	_ = os.MkdirAll(path, 0700)

	var sb strings.Builder
	fmt.Fprintf(&sb, "# refreshed: %s\n", refreshed.Format(time.RFC3339))
	sb.WriteString("# ipv4\n")
	for _, cidr := range ipv4 {
		sb.WriteString(cidr)
		sb.WriteByte('\n')
	}
	sb.WriteString("# ipv6\n")
	for _, cidr := range ipv6 {
		sb.WriteString(cidr)
		sb.WriteByte('\n')
	}

	file := path + "/cf_whitelist.txt"
	_ = os.WriteFile(file, []byte(sb.String()), 0600)
}

// CloudflareRangesCover reports whether ip falls inside any of the given
// Cloudflare CIDR ranges. The input chain accepts Cloudflare edges on TCP
// 80/443 before the blocked-IP drop, so blocking a covered IP does not stop
// its web traffic; callers use this to warn the operator at block time.
// Malformed CIDRs are skipped so one bad cache line cannot hide coverage.
func CloudflareRangesCover(v4, v6 []string, ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	ranges := v4
	if parsed.To4() == nil {
		ranges = v6
	}
	for _, cidr := range ranges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}

// LoadCFState reads the cached Cloudflare CIDRs.
func LoadCFState(statePath string) (ipv4, ipv6 []string) {
	path := statePath
	if !strings.HasSuffix(path, "/firewall") {
		path += "/firewall"
	}
	file := path + "/cf_whitelist.txt"

	// #nosec G304 -- fixed filename under operator-configured statePath.
	f, err := os.Open(file)
	if err != nil {
		return nil, nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	section := "ipv4"
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "# ipv4" {
			section = "ipv4"
			continue
		}
		if line == "# ipv6" {
			section = "ipv6"
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch section {
		case "ipv4":
			ipv4 = append(ipv4, line)
		case "ipv6":
			ipv6 = append(ipv6, line)
		}
	}
	return ipv4, ipv6
}

// LoadCFRefreshTime reads the last CF refresh time from state.
func LoadCFRefreshTime(statePath string) time.Time {
	path := statePath
	if !strings.HasSuffix(path, "/firewall") {
		path += "/firewall"
	}
	file := path + "/cf_whitelist.txt"

	// #nosec G304 -- fixed filename under operator-configured statePath.
	f, err := os.Open(file)
	if err != nil {
		return time.Time{}
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "# refreshed: ") {
			ts := strings.TrimPrefix(line, "# refreshed: ")
			if t, err := time.Parse(time.RFC3339, ts); err == nil {
				return t
			}
		}
	}
	return time.Time{}
}
