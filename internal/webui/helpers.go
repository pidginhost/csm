package webui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/integrity"
)

// jsonForScript marshals v to JSON and returns it as template.JS suitable
// for direct substitution into a <script> block. json.Marshal already
// escapes < > & U+2028 U+2029 to \uXXXX form, so the output cannot break
// out of the surrounding <script> tag or trigger JS line-terminator
// parsing quirks. On marshal failure the fallback is the JS literal
// "null" so the enclosing template still parses.
func jsonForScript(v interface{}) template.JS {
	b, err := json.Marshal(v)
	if err != nil {
		return template.JS("null")
	}
	// Defense-in-depth: Go's json.Marshal has historically escaped these
	// by default, but an explicit pass guarantees the contract even if
	// that default ever changes or the input arrived pre-encoded.
	b = bytes.ReplaceAll(b, []byte("<"), []byte(`\u003c`))
	b = bytes.ReplaceAll(b, []byte(">"), []byte(`\u003e`))
	b = bytes.ReplaceAll(b, []byte("&"), []byte(`\u0026`))
	b = bytes.ReplaceAll(b, []byte("\u2028"), []byte(`\u2028`))
	b = bytes.ReplaceAll(b, []byte("\u2029"), []byte(`\u2029`))
	// #nosec G203 -- Output is JSON bytes with HTML/JS-dangerous codepoints
	// escaped above; safe to hand to html/template as JS.
	return template.JS(b)
}

func decodeJSONBodyLimited(w http.ResponseWriter, r *http.Request, limit int64, dst interface{}) error {
	if limit <= 0 {
		limit = 64 * 1024
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("request body must contain a single JSON value")
	}
	return nil
}

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

// parseDuration parses a human-friendly duration string from the web UI.
// Supported formats: "24h", "7d", "30d", "0" (permanent), "" (permanent).
func parseDuration(s string) time.Duration {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return 0
	}
	if strings.HasSuffix(s, "d") {
		s = strings.TrimSuffix(s, "d")
		days := 0
		for _, c := range s {
			if c < '0' || c > '9' {
				return 0
			}
			days = days*10 + int(c-'0')
		}
		return time.Duration(days) * 24 * time.Hour
	}
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	return 0
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

func isPathWithin(path, base string) bool {
	cleanPath := filepath.Clean(path)
	cleanBase := filepath.Clean(base)
	return cleanPath == cleanBase || strings.HasPrefix(cleanPath, cleanBase+string(filepath.Separator))
}

// archiveMatchesOriginal reports whether the archived file and the original
// path hold byte-identical contents. Used by the quarantine listing to hide
// entries whose original has been restored (the archive is a redundant
// duplicate). Any I/O failure, size mismatch, non-regular target, or hash
// divergence returns false so the UI keeps showing the entry for operator
// review. Size check short-circuits before hashing so the listing stays
// cheap when a site is reattacked with a larger payload.
func archiveMatchesOriginal(archivePath, originalPath string) bool {
	origInfo, err := os.Stat(originalPath)
	if err != nil || !origInfo.Mode().IsRegular() {
		return false
	}
	archInfo, err := os.Stat(archivePath)
	if err != nil || !archInfo.Mode().IsRegular() {
		return false
	}
	if origInfo.Size() != archInfo.Size() {
		return false
	}
	origHash, err := integrity.HashFile(originalPath)
	if err != nil {
		return false
	}
	archHash, err := integrity.HashFile(archivePath)
	if err != nil {
		return false
	}
	return origHash == archHash
}

const preCleanQuarantineIDPrefix = "pre_clean:"

type quarantineEntryRef struct {
	ID       string
	ItemPath string
	MetaPath string
}

func quarantineEntryID(metaPath string) string {
	id := strings.TrimSuffix(filepath.Base(metaPath), ".meta")
	if filepath.Clean(filepath.Dir(metaPath)) == filepath.Join(quarantineDir, "pre_clean") {
		return preCleanQuarantineIDPrefix + id
	}
	return id
}

func resolveQuarantineEntry(id string) (quarantineEntryRef, error) {
	rawID := strings.TrimSpace(id)
	if rawID == "" {
		return quarantineEntryRef{}, fmt.Errorf("quarantine ID is required")
	}

	baseDir := quarantineDir
	name := rawID
	if strings.HasPrefix(rawID, preCleanQuarantineIDPrefix) {
		baseDir = filepath.Join(quarantineDir, "pre_clean")
		name = strings.TrimPrefix(rawID, preCleanQuarantineIDPrefix)
	}
	name = filepath.Base(name)
	if name == "" || name == "." || name == ".." {
		return quarantineEntryRef{}, fmt.Errorf("invalid quarantine ID")
	}

	itemPath := filepath.Join(baseDir, name)
	if !isPathWithin(itemPath, baseDir) {
		return quarantineEntryRef{}, fmt.Errorf("invalid quarantine ID")
	}

	return quarantineEntryRef{
		ID:       rawID,
		ItemPath: itemPath,
		MetaPath: itemPath + ".meta",
	}, nil
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
	// #nosec G304 -- metaPath is constructed by resolveQuarantineEntry under
	// the quarantine base dir with filepath.Base applied to the ID.
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

var quarantineRestoreRoots = []string{"/home", "/tmp", "/dev/shm", "/var/tmp"}

func validateQuarantineRestorePath(path string) (string, error) {
	cleanPath := filepath.Clean(strings.TrimSpace(path))
	if cleanPath == "" {
		return "", fmt.Errorf("restore path is required")
	}
	if !filepath.IsAbs(cleanPath) {
		return "", fmt.Errorf("restore path must be absolute")
	}
	if !pathWithinAny(cleanPath, quarantineRestoreRoots) {
		return "", fmt.Errorf("restore path is outside the allowed restore roots: %s", cleanPath)
	}

	ancestor, err := nearestExistingAncestor(cleanPath)
	if err != nil {
		return "", err
	}
	resolvedAncestor, err := filepath.EvalSymlinks(ancestor)
	if err != nil {
		return "", fmt.Errorf("cannot validate restore path: %w", err)
	}
	if !pathWithinAny(resolvedAncestor, quarantineRestoreRoots) {
		return "", fmt.Errorf("restore path escapes the allowed restore roots: %s", cleanPath)
	}
	if accountRoot := homeAccountRoot(cleanPath); accountRoot != "" && !isPathWithin(resolvedAncestor, accountRoot) {
		return "", fmt.Errorf("restore path escapes the account boundary: %s", cleanPath)
	}

	return cleanPath, nil
}

func pathWithinAny(path string, bases []string) bool {
	for _, base := range bases {
		if isPathWithin(path, base) {
			return true
		}
		if resolvedBase, err := filepath.EvalSymlinks(base); err == nil && isPathWithin(path, resolvedBase) {
			return true
		}
	}
	return false
}

func nearestExistingAncestor(path string) (string, error) {
	current := filepath.Clean(path)
	for {
		if _, err := os.Lstat(current); err == nil {
			return current, nil
		} else if !os.IsNotExist(err) {
			return "", fmt.Errorf("cannot stat restore path: %w", err)
		}

		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("restore path has no existing ancestor: %s", path)
		}
		current = parent
	}
}

func homeAccountRoot(path string) string {
	cleanPath := filepath.Clean(path)
	if !strings.HasPrefix(cleanPath, "/home/") {
		return ""
	}
	parts := strings.Split(cleanPath, string(filepath.Separator))
	if len(parts) < 4 {
		return ""
	}
	return filepath.Join("/home", parts[2])
}
