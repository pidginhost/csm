package webui

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/emailav"
)

func TestSafeLogStringQuotesControlBytes(t *testing.T) {
	got := safeLogString("/tmp/restored\nname\r.php")
	if strings.ContainsAny(got, "\n\r") {
		t.Fatalf("safeLogString left raw control bytes in %q", got)
	}
	if !strings.Contains(got, `\n`) || !strings.Contains(got, `\r`) {
		t.Fatalf("safeLogString(%q) = %q, want escaped controls", "/tmp/restored\nname\r.php", got)
	}
}

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

func TestQuarantineEntryID_PreClean(t *testing.T) {
	metaPath := filepath.Join(quarantineDir, "pre_clean", "sample.meta")
	got := quarantineEntryID(metaPath)
	if got != preCleanQuarantineIDPrefix+"sample" {
		t.Fatalf("quarantineEntryID() = %q", got)
	}
}

func TestResolveQuarantineEntry_PreClean(t *testing.T) {
	entry, err := resolveQuarantineEntry(preCleanQuarantineIDPrefix + "sample")
	if err != nil {
		t.Fatalf("resolveQuarantineEntry() error = %v", err)
	}
	wantPath := filepath.Join(quarantineDir, "pre_clean", "sample")
	if entry.ItemPath != wantPath {
		t.Fatalf("ItemPath = %q, want %q", entry.ItemPath, wantPath)
	}
}

func TestValidateQuarantineRestorePath_AllowedTempPath(t *testing.T) {
	restorePath := filepath.Join("/tmp", "csm-test", "restored.php")
	got, err := validateQuarantineRestorePath(restorePath)
	if err != nil {
		t.Fatalf("validateQuarantineRestorePath() error = %v", err)
	}
	if got != restorePath {
		t.Fatalf("validateQuarantineRestorePath() = %q, want %q", got, restorePath)
	}
}

func TestValidateQuarantineRestorePath_RejectsOutsideRoots(t *testing.T) {
	if _, err := validateQuarantineRestorePath("/etc/passwd"); err == nil {
		t.Fatal("validateQuarantineRestorePath() = nil error, want root validation failure")
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

// --- jsonForScript ---

func TestJSONForScript_EscapesBrowserDangerousChars(t *testing.T) {
	// This helper is the single source of truth for JSON embedded in
	// <script> blocks. It must neutralize every character sequence that
	// a browser's HTML or JS parser interprets specially: </script>, raw
	// <, >, &, and the line-separator codepoints U+2028/U+2029.
	cases := []struct {
		name        string
		in          interface{}
		mustHave    []string
		mustNotHave []string
	}{
		{
			name:        "script breakout attempt",
			in:          map[string]string{"x": "</script><script>alert(1)</script>"},
			mustHave:    []string{`\u003c/script\u003e`, `\u003cscript\u003e`},
			mustNotHave: []string{`</script>`, `<script>`},
		},
		{
			name:        "ampersand and brackets",
			in:          map[string]string{"x": "<a href='x'>&</a>"},
			mustHave:    []string{`\u003c`, `\u003e`, `\u0026`},
			mustNotHave: []string{"<a href", "</a>"},
		},
		{
			name:        "js line separators",
			in:          map[string]string{"x": "line1\u2028line2\u2029line3"},
			mustHave:    []string{`\u2028`, `\u2029`},
			mustNotHave: []string{"\u2028", "\u2029"},
		},
		{
			name:        "normal data survives",
			in:          map[string]interface{}{"version": "2.4.0", "enabled": true},
			mustHave:    []string{`"version"`, `"2.4.0"`, `"enabled"`, `true`},
			mustNotHave: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := string(jsonForScript(tc.in))
			for _, s := range tc.mustHave {
				if !strings.Contains(got, s) {
					t.Errorf("output missing %q:\n  got: %s", s, got)
				}
			}
			for _, s := range tc.mustNotHave {
				if strings.Contains(got, s) {
					t.Errorf("output still contains dangerous %q:\n  got: %s", s, got)
				}
			}
		})
	}
}

func TestJSONForScript_FailsSafeOnMarshalError(t *testing.T) {
	// Channels are not JSON-serializable. The helper must not return empty
	// bytes (would be invalid JS if substituted as an expression) — it must
	// return a safe JS literal so the surrounding template still parses.
	got := string(jsonForScript(make(chan int)))
	if got != "null" {
		t.Errorf("marshal-error fallback = %q, want %q", got, "null")
	}
}

func TestValidateEximMessageIDRejectsTraversal(t *testing.T) {
	for _, bad := range []string{
		"",
		"..",
		"../etc",
		"foo/bar",
		"foo\\bar",
		"foo.bar",
		"a/b",
		"foo\x00bar",
		"too-long-1234567890123456789012345",
		"weird;rm",
	} {
		if err := validateEximMessageID(bad); err == nil {
			t.Errorf("validateEximMessageID(%q) = nil, want error", bad)
		}
	}
	for _, ok := range []string{
		"abc",
		"1tBzCo-0007Lc-Vx",
		"AaZz09-AaZz09-12",
		"testmsg123",
	} {
		if err := validateEximMessageID(ok); err != nil {
			t.Errorf("validateEximMessageID(%q) = %v, want nil", ok, err)
		}
	}
}

func TestMustBeWithinRejectsEscapes(t *testing.T) {
	root := t.TempDir()
	if _, err := mustBeWithin(root, "foo/bar"); err != nil {
		t.Errorf("plain subpath rejected: %v", err)
	}
	if _, err := mustBeWithin(root, "../etc/passwd"); err == nil {
		t.Error("traversal escape accepted")
	}
	if _, err := mustBeWithin(root, "foo/../../etc"); err == nil {
		t.Error("embedded traversal accepted")
	}
	// Absolute-looking fragments are interpreted relative to root. The
	// security guarantee is that no candidate can resolve outside root.
	if _, err := mustBeWithin(root, "/etc/passwd"); err != nil {
		t.Errorf("absolute-style candidate rejected: %v", err)
	}
	if _, err := mustBeWithin(root, "/../../etc/passwd"); err == nil {
		t.Error("absolute-style traversal accepted")
	}
	if _, err := mustBeWithin(root, "."); err != nil {
		t.Errorf("root itself rejected: %v", err)
	}
	if _, err := mustBeWithin(root, "missing/../new-file"); err != nil {
		t.Errorf("missing path segment with parent traversal rejected: %v", err)
	}

	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "outside-link")); err != nil {
		t.Fatal(err)
	}
	if _, err := mustBeWithin(root, "outside-link/new-file"); err == nil {
		t.Error("missing leaf under symlink escape accepted")
	}
	if _, err := mustBeWithin(root, "outside-link/../new-file"); err == nil {
		t.Error("symlink traversal order escape accepted")
	}
	if _, err := mustBeWithin(root, "missing/../outside-link/new-file"); err == nil {
		t.Error("missing segment traversal hid symlink escape")
	}

	inside := filepath.Join(root, "inside")
	if err := os.Mkdir(inside, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("inside", filepath.Join(root, "inside-link")); err != nil {
		t.Fatal(err)
	}
	got, err := mustBeWithin(root, "inside-link/new-file")
	if err != nil {
		t.Fatalf("inside symlink rejected: %v", err)
	}
	resolvedInside, err := filepath.EvalSymlinks(inside)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(resolvedInside, "new-file")
	if got != want {
		t.Fatalf("inside symlink resolved to %q, want %q", got, want)
	}
}

func TestEmailQuarantineActionRejectsTraversalMessageID(t *testing.T) {
	s := newTestServer(t, "tok")
	dir := t.TempDir()
	s.emailQuarantine = emailav.NewQuarantine(dir)

	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodDelete, ".."},
		{http.MethodDelete, "foo.bar"},
		{http.MethodDelete, "foo%00bar"},
		{http.MethodDelete, "weird;rm"},
		{http.MethodDelete, "abc123/extra"},
		{http.MethodGet, "abc123/extra"},
		{http.MethodPost, "abc123/extra"},
		{http.MethodPost, "abc123/release/extra"},
	} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(tc.method, "/api/v1/email/quarantine/"+tc.path, nil)
		s.apiEmailQuarantineAction(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s %q = %d, want 400", tc.method, tc.path, w.Code)
		}
	}
}

func TestFlushCphulkRevalidatesIP(t *testing.T) {
	binDir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "whmapi1.args")
	script := "#!/bin/sh\nprintf 'ran\\n' > \"$CSM_TEST_MARKER\"\nprintf '%s\\n' \"$@\" >> \"$CSM_TEST_MARKER\"\n"
	if err := os.WriteFile(filepath.Join(binDir, "whmapi1"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("CSM_TEST_MARKER", marker)

	flushCphulk("203.0.113.5;touch /tmp/pwned")
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("invalid IP executed whmapi1, stat err = %v", err)
	}

	flushCphulk("203.0.113.5")
	got, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "flush_cphulk_login_history_for_ips\nip=203.0.113.5") {
		t.Fatalf("whmapi1 args = %q", string(got))
	}
}
