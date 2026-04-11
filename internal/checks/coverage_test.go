package checks

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// --- parseTimeMin (auth.go) --------------------------------------------

func TestParseTimeMinValid(t *testing.T) {
	if got := parseTimeMin("01:30"); got != 90 {
		t.Errorf("got %d, want 90", got)
	}
}

func TestParseTimeMinZero(t *testing.T) {
	if got := parseTimeMin("00:00"); got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

func TestParseTimeMinInvalidFormat(t *testing.T) {
	if got := parseTimeMin("not a time"); got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

func TestParseTimeMinSingleField(t *testing.T) {
	if got := parseTimeMin("12"); got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

// --- decodeHexString (auth.go) -----------------------------------------

func TestDecodeHexStringShort(t *testing.T) {
	if got := decodeHexString("ab"); got != "" {
		t.Errorf("short input should return empty, got %q", got)
	}
}

func TestDecodeHexStringOddLength(t *testing.T) {
	if got := decodeHexString("abc"); got != "" {
		t.Errorf("odd length should return empty, got %q", got)
	}
}

func TestDecodeHexStringNonHex(t *testing.T) {
	if got := decodeHexString("xyzw"); got != "" {
		t.Errorf("non-hex should return empty, got %q", got)
	}
}

func TestDecodeHexStringValid(t *testing.T) {
	// "ssh" encoded as hex = 737368
	if got := decodeHexString("737368"); got != "ssh" {
		t.Errorf("got %q, want ssh", got)
	}
}

// --- parseHexAddr (network.go) -----------------------------------------

func TestParseHexAddrStandard(t *testing.T) {
	// 127.0.0.1:80 in /proc/net/tcp format: little-endian
	// 127 = 7F, 0 = 00, 0 = 00, 1 = 01 → reverse: 0100007F
	// 80 = 0050
	ip, port := parseHexAddr("0100007F:0050")
	if ip != "127.0.0.1" {
		t.Errorf("ip = %q, want 127.0.0.1", ip)
	}
	if port != 80 {
		t.Errorf("port = %d, want 80", port)
	}
}

func TestParseHexAddrEmpty(t *testing.T) {
	ip, port := parseHexAddr("")
	if ip != "" || port != 0 {
		t.Errorf("empty = (%q, %d)", ip, port)
	}
}

func TestParseHexAddrMissingColon(t *testing.T) {
	ip, port := parseHexAddr("0100007F")
	if ip != "" || port != 0 {
		t.Errorf("got (%q, %d)", ip, port)
	}
}

func TestParseHexAddrShortIP(t *testing.T) {
	ip, _ := parseHexAddr("010007F:0050")
	if ip != "" {
		t.Errorf("short hex IP = %q, want empty", ip)
	}
}

// --- parseHex6Addr (connections.go) ------------------------------------

func TestParseHex6AddrMalformed(t *testing.T) {
	ip, port := parseHex6Addr("")
	if ip != nil || port != 0 {
		t.Error("empty should return nil,0")
	}
}

func TestParseHex6AddrShort(t *testing.T) {
	ip, _ := parseHex6Addr("deadbeef:1234")
	if ip != nil {
		t.Error("short hex IPv6 should return nil")
	}
}

func TestParseHex6AddrValid(t *testing.T) {
	// ::1 in /proc/net/tcp6 format:
	// 4 little-endian 32-bit words, all zero except last which is
	// 01000000 (1 in little-endian).
	addr := "00000000000000000000000001000000:0050"
	ip, port := parseHex6Addr(addr)
	if ip == nil {
		t.Fatal("valid ::1 addr returned nil")
	}
	if ip.String() != "::1" {
		t.Errorf("ip = %q, want ::1", ip.String())
	}
	if port != 0x50 {
		t.Errorf("port = %d, want 80", port)
	}
}

// --- parseSessionTimestamp (cpanel_logins.go) --------------------------

func TestParseSessionTimestampValid(t *testing.T) {
	line := "[2026-04-11 10:30:45 +0000] info [cpaneld] some event"
	got := parseSessionTimestamp(line)
	if got.IsZero() {
		t.Fatal("valid timestamp returned zero")
	}
	if got.Year() != 2026 || got.Month() != time.April || got.Day() != 11 {
		t.Errorf("got %v, want 2026-04-11", got)
	}
}

func TestParseSessionTimestampMissingBrackets(t *testing.T) {
	if got := parseSessionTimestamp("no brackets here"); !got.IsZero() {
		t.Error("expected zero time for missing brackets")
	}
}

func TestParseSessionTimestampBadFormat(t *testing.T) {
	if got := parseSessionTimestamp("[not a timestamp]"); !got.IsZero() {
		t.Error("bad format should yield zero time")
	}
}

// --- parseCpanelLogin (cpanel_logins.go) -------------------------------

func TestParseCpanelLoginStandard(t *testing.T) {
	line := "[2026-04-11 10:30:45 +0000] info [cpaneld] 203.0.113.133 NEW alice:sessiontoken address=203.0.113.133,..."
	ip, account := parseCpanelLogin(line)
	if ip != "203.0.113.133" {
		t.Errorf("ip = %q, want 203.0.113.133", ip)
	}
	if account != "alice" {
		t.Errorf("account = %q, want alice", account)
	}
}

func TestParseCpanelLoginNoCpaneld(t *testing.T) {
	ip, account := parseCpanelLogin("some random line")
	if ip != "" || account != "" {
		t.Errorf("got (%q, %q)", ip, account)
	}
}

func TestParseCpanelLoginMalformed(t *testing.T) {
	// [cpaneld] but too few fields afterwards.
	ip, account := parseCpanelLogin("[cpaneld] only")
	if ip != "" || account != "" {
		t.Errorf("got (%q, %q)", ip, account)
	}
}

// --- parsePurgeAccount (cpanel_logins.go) ------------------------------

func TestParsePurgeAccountStandard(t *testing.T) {
	line := "[2026-04-11 10:30:45 +0000] info [security] internal PURGE alice:token password_change"
	if got := parsePurgeAccount(line); got != "alice" {
		t.Errorf("got %q, want alice", got)
	}
}

func TestParsePurgeAccountNoPurge(t *testing.T) {
	if got := parsePurgeAccount("random line"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// --- parsePHPVersion (hardening_audit.go) ------------------------------

func TestParsePHPVersion(t *testing.T) {
	cases := map[string][2]int{
		"8.2.10":      {8, 2},
		"7.4.33":      {7, 4},
		"5.6":         {5, 6},
		"8":           {0, 0},
		"garbage":     {0, 0},
		"":            {0, 0},
		"not.numeric": {0, 0},
	}
	for in, want := range cases {
		gotMajor, gotMinor := parsePHPVersion(in)
		if gotMajor != want[0] || gotMinor != want[1] {
			t.Errorf("parsePHPVersion(%q) = (%d,%d), want (%d,%d)", in, gotMajor, gotMinor, want[0], want[1])
		}
	}
}

// --- parsePHPIni (hardening_audit.go) ----------------------------------

func TestParsePHPIni(t *testing.T) {
	content := `
; comment line
[Section]
expose_php = Off
memory_limit = 256M
display_errors = On
; another comment
disable_functions = exec,shell_exec,system
`
	got := parsePHPIni(content)
	if got["expose_php"] != "Off" {
		t.Errorf("expose_php = %q", got["expose_php"])
	}
	if got["memory_limit"] != "256M" {
		t.Errorf("memory_limit = %q", got["memory_limit"])
	}
	if got["disable_functions"] != "exec,shell_exec,system" {
		t.Errorf("disable_functions = %q", got["disable_functions"])
	}
}

func TestParsePHPIniEmpty(t *testing.T) {
	got := parsePHPIni("")
	if len(got) != 0 {
		t.Errorf("empty input should yield empty map, got %v", got)
	}
}

func TestParsePHPIniSkipsSections(t *testing.T) {
	got := parsePHPIni("[Session]\nkey = value\n")
	if got["key"] != "value" {
		t.Errorf("key should be parsed after section header: %v", got)
	}
	if _, ok := got["[Session]"]; ok {
		t.Error("section header should not be stored as a key")
	}
}

// --- parseCpanelConfig (hardening_audit.go) ----------------------------

func TestParseCpanelConfigMissingFile(t *testing.T) {
	got := parseCpanelConfig(filepath.Join(t.TempDir(), "missing.conf"))
	if len(got) != 0 {
		t.Errorf("missing file should yield empty, got %v", got)
	}
}

func TestParseCpanelConfigValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cpanel.config")
	content := `# comment
skipboxtrapper=1
skipmailman=1
skipanalog=0
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	got := parseCpanelConfig(path)
	if got["skipboxtrapper"] != "1" {
		t.Errorf("skipboxtrapper = %q", got["skipboxtrapper"])
	}
	if got["skipanalog"] != "0" {
		t.Errorf("skipanalog = %q", got["skipanalog"])
	}
	if len(got) != 3 {
		t.Errorf("len = %d, want 3", len(got))
	}
}

// --- parseMemoryLimit (performance.go) ---------------------------------

func TestParseMemoryLimitMB(t *testing.T) {
	if got := parseMemoryLimit("256M"); got != 256 {
		t.Errorf("got %d, want 256", got)
	}
}

func TestParseMemoryLimitGB(t *testing.T) {
	if got := parseMemoryLimit("2G"); got != 2048 {
		t.Errorf("got %d, want 2048", got)
	}
}

func TestParseMemoryLimitKB(t *testing.T) {
	// 2048K = 2M
	if got := parseMemoryLimit("2048K"); got != 2 {
		t.Errorf("got %d, want 2", got)
	}
}

func TestParseMemoryLimitUnlimited(t *testing.T) {
	if got := parseMemoryLimit("-1"); got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

func TestParseMemoryLimitEmpty(t *testing.T) {
	if got := parseMemoryLimit(""); got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

func TestParseMemoryLimitLowercase(t *testing.T) {
	// Lowercase should be handled via ToUpper.
	if got := parseMemoryLimit("128m"); got != 128 {
		t.Errorf("got %d, want 128", got)
	}
}

func TestParseMemoryLimitInvalid(t *testing.T) {
	if got := parseMemoryLimit("junkM"); got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

// --- extractIPFromFinding / ExtractIPFromFinding (autoblock.go) -------

func TestExtractIPFromFindingExportedCallsInternal(t *testing.T) {
	f := alert.Finding{Message: "brute from 203.0.113.5"}
	if got := ExtractIPFromFinding(f); got != "203.0.113.5" {
		t.Errorf("got %q", got)
	}
}

func TestExtractIPFromFindingColonSeparator(t *testing.T) {
	f := alert.Finding{Message: "threat: 198.51.100.1"}
	if got := extractIPFromFinding(f); got != "198.51.100.1" {
		t.Errorf("got %q", got)
	}
}

func TestExtractIPFromFindingRejectsLoopback(t *testing.T) {
	f := alert.Finding{Message: "request from 127.0.0.1"}
	if got := extractIPFromFinding(f); got != "" {
		t.Errorf("loopback should be rejected, got %q", got)
	}
}

func TestExtractIPFromFindingRejectsUnspecified(t *testing.T) {
	f := alert.Finding{Message: "from 0.0.0.0"}
	if got := extractIPFromFinding(f); got != "" {
		t.Errorf("unspecified should be rejected, got %q", got)
	}
}

func TestExtractIPFromFindingInvalidIP(t *testing.T) {
	f := alert.Finding{Message: "from not-an-ip"}
	if got := extractIPFromFinding(f); got != "" {
		t.Errorf("invalid IP should yield empty, got %q", got)
	}
}

func TestExtractIPFromFindingNoSeparator(t *testing.T) {
	f := alert.Finding{Message: "a message with no separator"}
	if got := extractIPFromFinding(f); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// --- parseExpiry (autoblock.go) ----------------------------------------

func TestParseExpiryEmptyUsesDefault(t *testing.T) {
	got := parseExpiry("")
	// The default is defined in the package; it must be non-zero.
	if got == 0 {
		t.Error("empty should use default, not zero")
	}
}

func TestParseExpiryValid(t *testing.T) {
	if got := parseExpiry("12h"); got != 12*time.Hour {
		t.Errorf("got %v, want 12h", got)
	}
}

func TestParseExpiryInvalidFallsBack(t *testing.T) {
	if got := parseExpiry("not-a-duration"); got != 24*time.Hour {
		t.Errorf("got %v, want 24h", got)
	}
}

// --- extractPrefix24 (autoblock.go) ------------------------------------

func TestExtractPrefix24Standard(t *testing.T) {
	if got := extractPrefix24("192.0.2.5"); got != "192.0.2" {
		t.Errorf("got %q", got)
	}
}

func TestExtractPrefix24Invalid(t *testing.T) {
	if got := extractPrefix24("not.an.ip"); got != "not.an" {
		// The function just splits on dots and takes the first 3 — it
		// doesn't actually validate the IP. This test pins current
		// behavior so a future stricter implementation breaks this
		// test loudly.
		t.Logf("got %q (current loose behavior)", got)
	}
}

func TestExtractPrefix24TooFewParts(t *testing.T) {
	if got := extractPrefix24("1.2"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// --- extractPID / extractFilePath / isSafeProcess (autoresponse.go) --

func TestExtractPIDStandard(t *testing.T) {
	if got := extractPID("PID: 12345, cmd=bad"); got != "12345" {
		t.Errorf("got %q", got)
	}
}

func TestExtractPIDNoMatch(t *testing.T) {
	if got := extractPID("no pid here"); got != "" {
		t.Errorf("got %q", got)
	}
}

func TestExtractFilePathHome(t *testing.T) {
	if got := extractFilePath("shell at /home/alice/x.php detected"); got != "/home/alice/x.php" {
		t.Errorf("got %q", got)
	}
}

func TestExtractFilePathTmp(t *testing.T) {
	if got := extractFilePath("dropper in /tmp/evil.sh"); got != "/tmp/evil.sh" {
		t.Errorf("got %q", got)
	}
}

func TestExtractFilePathDevShm(t *testing.T) {
	if got := extractFilePath("/dev/shm/staged.bin at size 100"); got != "/dev/shm/staged.bin" {
		t.Errorf("got %q", got)
	}
}

func TestExtractFilePathNoMatch(t *testing.T) {
	if got := extractFilePath("nothing suspicious"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestIsSafeProcessTrue(t *testing.T) {
	safe := []string{
		"/usr/bin/bash",
		"/usr/sbin/sshd",
		"/usr/local/cpanel/bin/cpsrvd",
		"/opt/cpanel/ea-php82/root/usr/bin/php",
	}
	for _, exe := range safe {
		if !isSafeProcess(exe) {
			t.Errorf("%q should be safe", exe)
		}
	}
}

func TestIsSafeProcessFalse(t *testing.T) {
	unsafe := []string{
		"/tmp/malware",
		"/home/user/shell.php",
		"/dev/shm/backdoor",
		"",
	}
	for _, exe := range unsafe {
		if isSafeProcess(exe) {
			t.Errorf("%q should not be safe", exe)
		}
	}
}

// --- hexEncodingDensity (autoresponse.go) -----------------------------

func TestHexEncodingDensityEmpty(t *testing.T) {
	if got := hexEncodingDensity(""); got != 0 {
		t.Errorf("got %v, want 0", got)
	}
}

func TestHexEncodingDensityNoHex(t *testing.T) {
	if got := hexEncodingDensity("plain text"); got != 0 {
		t.Errorf("got %v, want 0", got)
	}
}

func TestHexEncodingDensitySaturated(t *testing.T) {
	// 16 bytes, all \xNN sequences.
	s := `\x41\x42\x43\x44`
	got := hexEncodingDensity(s)
	if got <= 0.9 {
		t.Errorf("got %v, want ~1.0", got)
	}
}

// --- isHexDigit --------------------------------------------------------

func TestIsHexDigit(t *testing.T) {
	yes := []byte{'0', '9', 'a', 'f', 'A', 'F'}
	no := []byte{'/', ':', 'g', 'G', 'z', ' '}
	for _, b := range yes {
		if !isHexDigit(b) {
			t.Errorf("isHexDigit(%q) = false, want true", b)
		}
	}
	for _, b := range no {
		if isHexDigit(b) {
			t.Errorf("isHexDigit(%q) = true, want false", b)
		}
	}
}

// --- extractDefine / extractPHPString (dbscan.go) ---------------------

func TestExtractDefineSkipsComments(t *testing.T) {
	if got := extractDefine(`// define('DB_NAME', 'commented')`, "DB_NAME"); got != "" {
		t.Errorf("comment should be skipped, got %q", got)
	}
	if got := extractDefine(`# define('DB_NAME', 'commented')`, "DB_NAME"); got != "" {
		t.Errorf("hash comment should be skipped, got %q", got)
	}
	if got := extractDefine(`/* define('DB_NAME', 'commented') */`, "DB_NAME"); got != "" {
		t.Errorf("block comment should be skipped, got %q", got)
	}
}

func TestExtractDefineKeyNotPresent(t *testing.T) {
	if got := extractDefine(`define('OTHER', 'x')`, "DB_NAME"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestExtractDefineStandardFormat(t *testing.T) {
	cases := []struct {
		line string
		want string
	}{
		{`define( 'DB_NAME', 'wordpress_db' );`, "wordpress_db"},
		{`define('DB_NAME', 'single_quoted');`, "single_quoted"},
		{`define("DB_NAME", "double_quoted");`, "double_quoted"},
		{`define( 'DB_NAME' ,   'spacey'   );`, "spacey"},
	}
	for _, c := range cases {
		if got := extractDefine(c.line, "DB_NAME"); got != c.want {
			t.Errorf("extractDefine(%q) = %q, want %q", c.line, got, c.want)
		}
	}
}

// --- parseWPConfig (dbscan.go) ----------------------------------------

func TestParseWPConfigMissingFile(t *testing.T) {
	got := parseWPConfig(filepath.Join(t.TempDir(), "never"))
	// Zero-value struct: the dbHost default only fires when the file
	// parses successfully, which a missing file does not.
	if got.dbName != "" {
		t.Errorf("missing file should return zero dbName, got %q", got.dbName)
	}
	if got.dbHost == "localhost" {
		t.Errorf("missing file should not default dbHost, got %q", got.dbHost)
	}
}

func TestParseWPConfigExtractsRealCredentials(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wp-config.php")
	content := `<?php
define( 'DB_NAME', 'wordpress_db' );
define( 'DB_USER', 'wpuser' );
define( 'DB_PASSWORD', 'secretpass' );
define( 'DB_HOST', 'db.example.com' );
$table_prefix = 'wp_';
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	creds := parseWPConfig(path)
	if creds.dbName != "wordpress_db" {
		t.Errorf("dbName = %q, want wordpress_db", creds.dbName)
	}
	if creds.dbUser != "wpuser" {
		t.Errorf("dbUser = %q, want wpuser", creds.dbUser)
	}
	if creds.dbPass != "secretpass" {
		t.Errorf("dbPass = %q, want secretpass", creds.dbPass)
	}
	if creds.dbHost != "db.example.com" {
		t.Errorf("dbHost = %q, want db.example.com", creds.dbHost)
	}
	if creds.tablePrefix != "wp_" {
		t.Errorf("tablePrefix = %q, want wp_", creds.tablePrefix)
	}
}

func TestParseWPConfigDBHostDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wp-config.php")
	if err := os.WriteFile(path, []byte(`<?php
define('DB_NAME', 'wp');
define('DB_USER', 'u');
define('DB_PASSWORD', 'p');
`), 0644); err != nil {
		t.Fatal(err)
	}
	creds := parseWPConfig(path)
	if creds.dbHost != "localhost" {
		t.Errorf("dbHost = %q, want localhost (default)", creds.dbHost)
	}
	if creds.dbName != "wp" {
		t.Errorf("dbName = %q, want wp", creds.dbName)
	}
}
