package webui

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- validateAccountName ---

func TestValidateAccountName_Valid(t *testing.T) {
	cases := []string{
		"admin",
		"user1",
		"test_user",
		"A",
		"a1_b2_c3",
		"ALLCAPS",
		strings.Repeat("a", 64), // exactly 64 chars
	}
	for _, name := range cases {
		if err := validateAccountName(name); err != nil {
			t.Errorf("validateAccountName(%q) = %v; want nil", name, err)
		}
	}
}

func TestValidateAccountName_Empty(t *testing.T) {
	if err := validateAccountName(""); err == nil {
		t.Error("validateAccountName(\"\") = nil; want error")
	}
}

func TestValidateAccountName_TooLong(t *testing.T) {
	name := strings.Repeat("a", 65)
	if err := validateAccountName(name); err == nil {
		t.Errorf("validateAccountName(%d chars) = nil; want error", len(name))
	}
}

func TestValidateAccountName_MustStartWithLetter(t *testing.T) {
	cases := []string{
		"1admin",
		"_user",
		"9test",
		"0abc",
	}
	for _, name := range cases {
		if err := validateAccountName(name); err == nil {
			t.Errorf("validateAccountName(%q) = nil; want error (must start with letter)", name)
		}
	}
}

func TestValidateAccountName_SpecialChars(t *testing.T) {
	cases := []string{
		"user-name",
		"user.name",
		"user name",
		"user@host",
		"user/path",
		"../etc",
		"user;rm",
		"user'sql",
		"<script>",
	}
	for _, name := range cases {
		if err := validateAccountName(name); err == nil {
			t.Errorf("validateAccountName(%q) = nil; want error", name)
		}
	}
}

func TestValidateAccountName_PathTraversal(t *testing.T) {
	cases := []string{
		"../../../etc/passwd",
		"..%2f..%2f",
		"foo/../bar",
	}
	for _, name := range cases {
		if err := validateAccountName(name); err == nil {
			t.Errorf("validateAccountName(%q) = nil; want error (path traversal)", name)
		}
	}
}

// --- parseAndValidateIP ---

func TestParseAndValidateIP_ValidPublic(t *testing.T) {
	cases := []string{
		"8.8.8.8",
		"1.1.1.1",
		"93.184.216.34",
	}
	for _, s := range cases {
		ip, err := parseAndValidateIP(s)
		if err != nil {
			t.Errorf("parseAndValidateIP(%q) error = %v; want nil", s, err)
		}
		if ip == nil {
			t.Errorf("parseAndValidateIP(%q) returned nil IP", s)
		}
	}
}

func TestParseAndValidateIP_ValidIPv6(t *testing.T) {
	cases := []string{
		"2001:db8::1",
		"2607:f8b0:4004:800::200e",
	}
	for _, s := range cases {
		ip, err := parseAndValidateIP(s)
		if err != nil {
			t.Errorf("parseAndValidateIP(%q) error = %v; want nil", s, err)
		}
		if ip == nil {
			t.Errorf("parseAndValidateIP(%q) returned nil IP", s)
		}
	}
}

func TestParseAndValidateIP_RFC5737Allowed(t *testing.T) {
	// RFC 5737 documentation ranges MUST be allowed
	cases := []string{
		"203.0.113.1",
		"203.0.113.254",
		"198.51.100.1",
		"198.51.100.100",
		"192.0.2.1",
	}
	for _, s := range cases {
		ip, err := parseAndValidateIP(s)
		if err != nil {
			t.Errorf("parseAndValidateIP(%q) error = %v; RFC 5737 documentation IPs must be allowed", s, err)
		}
		if ip == nil {
			t.Errorf("parseAndValidateIP(%q) returned nil IP", s)
		}
	}
}

func TestParseAndValidateIP_Empty(t *testing.T) {
	_, err := parseAndValidateIP("")
	if err == nil {
		t.Error("parseAndValidateIP(\"\") = nil; want error")
	}
}

func TestParseAndValidateIP_Invalid(t *testing.T) {
	cases := []string{
		"not-an-ip",
		"256.256.256.256",
		"1.2.3.4.5",
		"abc",
	}
	for _, s := range cases {
		_, err := parseAndValidateIP(s)
		if err == nil {
			t.Errorf("parseAndValidateIP(%q) = nil; want error", s)
		}
	}
}

func TestParseAndValidateIP_Loopback(t *testing.T) {
	cases := []string{
		"127.0.0.1",
		"127.0.0.2",
		"::1",
	}
	for _, s := range cases {
		_, err := parseAndValidateIP(s)
		if err == nil {
			t.Errorf("parseAndValidateIP(%q) = nil; want error (loopback)", s)
		}
	}
}

func TestParseAndValidateIP_Private(t *testing.T) {
	cases := []string{
		"10.0.0.1",
		"10.255.255.255",
		"192.168.1.1",
		"192.168.0.100",
		"172.16.0.1",
		"172.31.255.255",
	}
	for _, s := range cases {
		_, err := parseAndValidateIP(s)
		if err == nil {
			t.Errorf("parseAndValidateIP(%q) = nil; want error (private)", s)
		}
	}
}

func TestParseAndValidateIP_Unspecified(t *testing.T) {
	cases := []string{
		"0.0.0.0",
		"::",
	}
	for _, s := range cases {
		_, err := parseAndValidateIP(s)
		if err == nil {
			t.Errorf("parseAndValidateIP(%q) = nil; want error (unspecified)", s)
		}
	}
}

func TestParseAndValidateIP_Broadcast(t *testing.T) {
	_, err := parseAndValidateIP("255.255.255.255")
	if err == nil {
		t.Error("parseAndValidateIP(\"255.255.255.255\") = nil; want error (broadcast)")
	}
}

func TestParseAndValidateIP_LinkLocal(t *testing.T) {
	cases := []string{
		"169.254.1.1",
		"169.254.169.254",
		"fe80::1",
	}
	for _, s := range cases {
		_, err := parseAndValidateIP(s)
		if err == nil {
			t.Errorf("parseAndValidateIP(%q) = nil; want error (link-local)", s)
		}
	}
}

func TestParseAndValidateIP_Multicast(t *testing.T) {
	cases := []string{
		"224.0.0.1",
		"239.255.255.255",
		"ff02::1",
	}
	for _, s := range cases {
		_, err := parseAndValidateIP(s)
		if err == nil {
			t.Errorf("parseAndValidateIP(%q) = nil; want error (multicast)", s)
		}
	}
}

// --- validateCIDR ---

func TestValidateCIDR_Valid(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"192.168.1.0/24", "192.168.1.0/24"},
		{"10.0.0.0/8", "10.0.0.0/8"},
		{"8.8.8.0/24", "8.8.8.0/24"},
		{"2001:db8::/32", "2001:db8::/32"},
	}
	for _, tc := range cases {
		ipNet, err := validateCIDR(tc.input)
		if err != nil {
			t.Errorf("validateCIDR(%q) error = %v; want nil", tc.input, err)
			continue
		}
		if ipNet == nil {
			t.Errorf("validateCIDR(%q) returned nil", tc.input)
		}
	}
}

func TestValidateCIDR_TooWide(t *testing.T) {
	cases := []string{
		"0.0.0.0/0",
		"0.0.0.0/1",
		"0.0.0.0/2",
		"0.0.0.0/3",
		"0.0.0.0/4",
		"0.0.0.0/5",
		"0.0.0.0/6",
		"0.0.0.0/7",
	}
	for _, s := range cases {
		_, err := validateCIDR(s)
		if err == nil {
			t.Errorf("validateCIDR(%q) = nil; want error (too wide)", s)
		}
	}
}

func TestValidateCIDR_Slash8Allowed(t *testing.T) {
	ipNet, err := validateCIDR("10.0.0.0/8")
	if err != nil {
		t.Errorf("validateCIDR(\"10.0.0.0/8\") error = %v; want nil", err)
	}
	if ipNet == nil {
		t.Error("validateCIDR(\"10.0.0.0/8\") returned nil")
	}
}

func TestValidateCIDR_Invalid(t *testing.T) {
	cases := []string{
		"not-a-cidr",
		"192.168.1.1",
		"abc/24",
	}
	for _, s := range cases {
		_, err := validateCIDR(s)
		if err == nil {
			t.Errorf("validateCIDR(%q) = nil; want error", s)
		}
	}
}

func TestValidateCIDR_Empty(t *testing.T) {
	_, err := validateCIDR("")
	if err == nil {
		t.Error("validateCIDR(\"\") = nil; want error")
	}
}

// --- isPathUnder ---

func TestIsPathUnder_Under(t *testing.T) {
	cases := []struct {
		path, base string
	}{
		{"/home/user/file.txt", "/home/user"},
		{"/home/user/sub/dir/file", "/home/user"},
		{"/opt/csm/quarantine/abc", "/opt/csm/quarantine"},
	}
	for _, tc := range cases {
		if !isPathUnder(tc.path, tc.base) {
			t.Errorf("isPathUnder(%q, %q) = false; want true", tc.path, tc.base)
		}
	}
}

func TestIsPathUnder_Traversal(t *testing.T) {
	cases := []struct {
		path, base string
	}{
		{"/home/user/../etc/passwd", "/home/user"},
		{"/home/user/../../etc/shadow", "/home/user"},
		{"/opt/csm/quarantine/../../../etc/passwd", "/opt/csm/quarantine"},
	}
	for _, tc := range cases {
		if isPathUnder(tc.path, tc.base) {
			t.Errorf("isPathUnder(%q, %q) = true; want false (traversal)", tc.path, tc.base)
		}
	}
}

func TestIsPathUnder_Outside(t *testing.T) {
	cases := []struct {
		path, base string
	}{
		{"/etc/passwd", "/home/user"},
		{"/home/otheruser/file", "/home/user"},
		{"/tmp/file", "/opt/csm"},
	}
	for _, tc := range cases {
		if isPathUnder(tc.path, tc.base) {
			t.Errorf("isPathUnder(%q, %q) = true; want false", tc.path, tc.base)
		}
	}
}

func TestIsPathUnder_ExactBase(t *testing.T) {
	// The base path itself should not be "under" itself
	if isPathUnder("/home/user", "/home/user") {
		t.Error("isPathUnder(\"/home/user\", \"/home/user\") = true; want false (exact match, not under)")
	}
}

func TestIsPathUnder_Subdirectory(t *testing.T) {
	if !isPathUnder("/home/user/subdir/file.txt", "/home/user") {
		t.Error("isPathUnder(\"/home/user/subdir/file.txt\", \"/home/user\") = false; want true")
	}
}

// --- readQuarantineMeta ---

func TestReadQuarantineMeta_Valid(t *testing.T) {
	dir := t.TempDir()
	metaPath := filepath.Join(dir, "test.meta")

	ts := time.Date(2026, 4, 5, 10, 0, 0, 0, time.UTC)
	meta := quarantineMeta{
		OriginalPath: "/home/user/public_html/malware.php",
		Owner:        1001,
		Group:        1001,
		Mode:         "-rwxr-xr-x",
		Size:         1234,
		QuarantineAt: ts,
		Reason:       "webshell detected",
	}
	data, _ := json.Marshal(meta)
	if err := os.WriteFile(metaPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	got, err := readQuarantineMeta(metaPath)
	if err != nil {
		t.Fatalf("readQuarantineMeta() error = %v", err)
	}
	if got.OriginalPath != meta.OriginalPath {
		t.Errorf("OriginalPath = %q; want %q", got.OriginalPath, meta.OriginalPath)
	}
	if got.Reason != meta.Reason {
		t.Errorf("Reason = %q; want %q", got.Reason, meta.Reason)
	}
	if got.Owner != meta.Owner {
		t.Errorf("Owner = %d; want %d", got.Owner, meta.Owner)
	}
	if got.Group != meta.Group {
		t.Errorf("Group = %d; want %d", got.Group, meta.Group)
	}
	if got.Mode != meta.Mode {
		t.Errorf("Mode = %q; want %q", got.Mode, meta.Mode)
	}
	if !got.QuarantineAt.Equal(meta.QuarantineAt) {
		t.Errorf("QuarantineAt = %v; want %v", got.QuarantineAt, meta.QuarantineAt)
	}
	if got.Size != meta.Size {
		t.Errorf("Size = %d; want %d", got.Size, meta.Size)
	}
}

func TestReadQuarantineMeta_Missing(t *testing.T) {
	_, err := readQuarantineMeta("/nonexistent/path.meta")
	if err == nil {
		t.Error("readQuarantineMeta(nonexistent) = nil; want error")
	}
}

func TestReadQuarantineMeta_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	metaPath := filepath.Join(dir, "bad.meta")
	if err := os.WriteFile(metaPath, []byte("not json{{{"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := readQuarantineMeta(metaPath)
	if err == nil {
		t.Error("readQuarantineMeta(bad JSON) = nil; want error")
	}
}

// --- listMetaFiles ---

func TestListMetaFiles(t *testing.T) {
	dir := t.TempDir()

	// Create some .meta files and some non-meta files
	for _, name := range []string{"a.meta", "b.meta", "c.meta"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"d.txt", "e.json", "f.meta.bak"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	// Create a subdirectory with .meta files (should NOT be included - non-recursive)
	subdir := filepath.Join(dir, "subdir")
	if err := os.Mkdir(subdir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subdir, "g.meta"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}

	got := listMetaFiles(dir)
	if len(got) != 3 {
		t.Errorf("listMetaFiles() returned %d files; want 3", len(got))
	}
	for _, f := range got {
		if !strings.HasSuffix(f, ".meta") {
			t.Errorf("listMetaFiles() returned non-.meta file: %s", f)
		}
	}
}

func TestListMetaFiles_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	got := listMetaFiles(dir)
	if len(got) != 0 {
		t.Errorf("listMetaFiles(empty) returned %d files; want 0", len(got))
	}
}

func TestListMetaFiles_NonexistentDir(t *testing.T) {
	got := listMetaFiles("/nonexistent/dir/path")
	if len(got) != 0 {
		t.Errorf("listMetaFiles(nonexistent) returned %d files; want 0", len(got))
	}
}

// --- parseAndValidateIP edge case: 172.16-31 private range boundary ---

func TestParseAndValidateIP_PrivateBoundary(t *testing.T) {
	// 172.15.x.x should be public
	ip, err := parseAndValidateIP("172.15.255.255")
	if err != nil {
		t.Errorf("parseAndValidateIP(\"172.15.255.255\") error = %v; want nil (public)", err)
	}
	if ip == nil {
		t.Error("parseAndValidateIP(\"172.15.255.255\") returned nil IP")
	}

	// 172.32.x.x should be public
	ip, err = parseAndValidateIP("172.32.0.1")
	if err != nil {
		t.Errorf("parseAndValidateIP(\"172.32.0.1\") error = %v; want nil (public)", err)
	}
	if ip == nil {
		t.Error("parseAndValidateIP(\"172.32.0.1\") returned nil IP")
	}

	// 172.16.0.1 should be private
	_, err = parseAndValidateIP("172.16.0.1")
	if err == nil {
		t.Error("parseAndValidateIP(\"172.16.0.1\") = nil; want error (private)")
	}
}

// --- validateCIDR: IPv6 too wide ---

func TestValidateCIDR_IPv6TooWide(t *testing.T) {
	cases := []string{
		"::/0",
		"::/4",
		"::/7",
		"::/8",
		"::/16",
		"::/31",
	}
	for _, s := range cases {
		_, err := validateCIDR(s)
		if err == nil {
			t.Errorf("validateCIDR(%q) = nil; want error (too wide)", s)
		}
	}
}

func TestValidateCIDR_IPv6Slash32Allowed(t *testing.T) {
	ipNet, err := validateCIDR("2001:db8::/32")
	if err != nil {
		t.Errorf("validateCIDR(\"2001:db8::/32\") error = %v; want nil", err)
	}
	if ipNet == nil {
		t.Error("validateCIDR(\"2001:db8::/32\") returned nil")
	}
}

// --- isPathUnder: prefix trick (e.g., /home/username vs /home/user) ---

func TestIsPathUnder_PrefixTrick(t *testing.T) {
	// "/home/username/file" should NOT be under "/home/user"
	if isPathUnder("/home/username/file", "/home/user") {
		t.Error("isPathUnder(\"/home/username/file\", \"/home/user\") = true; want false (prefix trick)")
	}
}

// --- parseAndValidateIP: whitespace trimming ---

func TestParseAndValidateIP_Whitespace(t *testing.T) {
	ip, err := parseAndValidateIP("  8.8.8.8  ")
	if err != nil {
		t.Errorf("parseAndValidateIP(\"  8.8.8.8  \") error = %v; want nil", err)
	}
	if !ip.Equal(net.ParseIP("8.8.8.8")) {
		t.Errorf("parseAndValidateIP trimmed IP = %v; want 8.8.8.8", ip)
	}
}
