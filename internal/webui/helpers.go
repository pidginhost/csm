package webui

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// validateAccountName checks that name is a valid cPanel account name:
// 1-64 characters, alphanumeric and underscore only.
func validateAccountName(name string) error {
	if name == "" {
		return fmt.Errorf("account name is required")
	}
	if len(name) > 64 {
		return fmt.Errorf("account name too long (%d chars, max 64)", len(name))
	}
	if (name[0] < 'a' || name[0] > 'z') && (name[0] < 'A' || name[0] > 'Z') {
		return fmt.Errorf("account name must start with a letter")
	}
	for _, c := range name {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' {
			return fmt.Errorf("account name contains invalid character: %c", c)
		}
	}
	return nil
}

// parseAndValidateIP parses an IP string and rejects non-routable addresses
// (loopback, private RFC 1918, link-local, multicast, unspecified, broadcast).
// RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
// are intentionally allowed.
func parseAndValidateIP(s string) (net.IP, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("IP address is required")
	}

	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", s)
	}

	if ip.IsLoopback() {
		return nil, fmt.Errorf("loopback address not allowed: %s", s)
	}
	if ip.IsPrivate() {
		return nil, fmt.Errorf("private address not allowed: %s", s)
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return nil, fmt.Errorf("link-local address not allowed: %s", s)
	}
	if ip.IsMulticast() {
		return nil, fmt.Errorf("multicast address not allowed: %s", s)
	}
	if ip.IsUnspecified() {
		return nil, fmt.Errorf("unspecified address not allowed: %s", s)
	}
	// Broadcast: 255.255.255.255
	if ip.Equal(net.IPv4bcast) {
		return nil, fmt.Errorf("broadcast address not allowed: %s", s)
	}

	return ip, nil
}

// validateCIDR parses a CIDR string and rejects overly broad prefixes
// (/0 through /7; minimum allowed is /8).
func validateCIDR(s string) (*net.IPNet, error) {
	if s == "" {
		return nil, fmt.Errorf("CIDR is required")
	}

	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	ones, bits := ipNet.Mask.Size()
	minPrefix := 8
	if bits == 128 { // IPv6
		minPrefix = 32
	}
	if ones < minPrefix {
		return nil, fmt.Errorf("CIDR prefix /%d is too broad (minimum /%d)", ones, minPrefix)
	}

	return ipNet, nil
}

// isPathUnder returns true if the cleaned path is strictly under the base
// directory. It prevents path traversal via ".." and prefix tricks
// (e.g., /home/username is not under /home/user).
func isPathUnder(path, base string) bool {
	cleanPath := filepath.Clean(path)
	cleanBase := filepath.Clean(base)

	// Ensure base ends with separator so "/home/user" doesn't match "/home/username"
	prefix := cleanBase + string(filepath.Separator)
	return strings.HasPrefix(cleanPath, prefix)
}

// quarantineMeta represents the JSON sidecar metadata for a quarantined file.
// Must match checks.QuarantineMeta on-disk format.
type quarantineMeta struct {
	OriginalPath string    `json:"original_path"`
	Owner        int       `json:"owner_uid"`
	Group        int       `json:"group_gid"`
	Mode         string    `json:"mode"`
	Size         int64     `json:"size"`
	QuarantineAt time.Time `json:"quarantined_at"`
	Reason       string    `json:"reason"`
}

// readQuarantineMeta reads and parses a quarantine .meta JSON file.
func readQuarantineMeta(metaPath string) (*quarantineMeta, error) {
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, fmt.Errorf("read quarantine meta: %w", err)
	}

	var meta quarantineMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("parse quarantine meta: %w", err)
	}

	return &meta, nil
}

// listMetaFiles returns the full paths of all .meta files in dir (non-recursive).
// Returns nil on any error (e.g., directory does not exist).
func listMetaFiles(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var metas []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(e.Name(), ".meta") {
			metas = append(metas, filepath.Join(dir, e.Name()))
		}
	}
	return metas
}
