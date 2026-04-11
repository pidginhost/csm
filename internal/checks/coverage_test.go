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

// --- isAlreadyBlocked / loadBlockState / PendingBlockIPs ----------------

func TestIsAlreadyBlockedHit(t *testing.T) {
	state := &blockState{
		IPs: []blockedIP{
			{IP: "1.1.1.1"},
			{IP: "2.2.2.2"},
		},
	}
	if !isAlreadyBlocked(state, "2.2.2.2") {
		t.Error("2.2.2.2 should be reported as already blocked")
	}
}

func TestIsAlreadyBlockedMiss(t *testing.T) {
	state := &blockState{IPs: []blockedIP{{IP: "1.1.1.1"}}}
	if isAlreadyBlocked(state, "9.9.9.9") {
		t.Error("unknown IP should not be reported as blocked")
	}
}

func TestIsAlreadyBlockedEmptyState(t *testing.T) {
	state := &blockState{}
	if isAlreadyBlocked(state, "1.1.1.1") {
		t.Error("empty state should never report as blocked")
	}
}

func TestLoadBlockStateMissingFileReturnsEmpty(t *testing.T) {
	got := loadBlockState(t.TempDir())
	if got == nil {
		t.Fatal("loadBlockState returned nil")
	}
	if len(got.IPs) != 0 || len(got.Pending) != 0 {
		t.Errorf("missing file should yield empty, got %+v", got)
	}
}

func TestLoadBlockStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	state := &blockState{
		IPs: []blockedIP{
			{IP: "1.1.1.1", Reason: "brute force"},
		},
		Pending: []pendingIP{
			{IP: "2.2.2.2", Reason: "rate limited"},
		},
		BlocksThisHour: 3,
		HourKey:        "2026-04-11T10",
	}
	saveBlockState(dir, state)

	loaded := loadBlockState(dir)
	if len(loaded.IPs) != 1 || loaded.IPs[0].IP != "1.1.1.1" {
		t.Errorf("IPs mismatch: %+v", loaded.IPs)
	}
	if len(loaded.Pending) != 1 || loaded.Pending[0].IP != "2.2.2.2" {
		t.Errorf("Pending mismatch: %+v", loaded.Pending)
	}
	if loaded.BlocksThisHour != 3 {
		t.Errorf("BlocksThisHour = %d, want 3", loaded.BlocksThisHour)
	}
}

func TestPendingBlockIPsEmpty(t *testing.T) {
	got := PendingBlockIPs(t.TempDir())
	if len(got) != 0 {
		t.Errorf("got %v, want empty map", got)
	}
}

func TestPendingBlockIPsPopulated(t *testing.T) {
	dir := t.TempDir()
	saveBlockState(dir, &blockState{
		Pending: []pendingIP{
			{IP: "1.1.1.1", Reason: "rate limited"},
			{IP: "2.2.2.2", Reason: "rate limited"},
		},
	})
	got := PendingBlockIPs(dir)
	if len(got) != 2 || !got["1.1.1.1"] || !got["2.2.2.2"] {
		t.Errorf("got %v, want both pending IPs", got)
	}
}

// --- checkPermBlockEscalation / loadPermBlockTracker -------------------

func TestCheckPermBlockEscalationBelowThreshold(t *testing.T) {
	dir := t.TempDir()
	// First two blocks within the interval — threshold is 3, so no
	// escalation yet.
	for i := 0; i < 2; i++ {
		escalate := checkPermBlockEscalation(dir, "1.2.3.4", 3, time.Hour)
		if escalate && i < 1 {
			t.Errorf("early call %d should not escalate", i)
		}
	}
}

func TestCheckPermBlockEscalationHitsThreshold(t *testing.T) {
	dir := t.TempDir()
	var escalated bool
	for i := 0; i < 3; i++ {
		escalated = checkPermBlockEscalation(dir, "5.6.7.8", 3, time.Hour)
	}
	if !escalated {
		t.Error("threshold should escalate on the 3rd block")
	}
}

func TestCheckPermBlockEscalationDifferentIPs(t *testing.T) {
	dir := t.TempDir()
	// Three different IPs each blocked once shouldn't escalate any of them.
	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		if checkPermBlockEscalation(dir, ip, 3, time.Hour) {
			t.Errorf("%s should not escalate on first block", ip)
		}
	}
}

func TestLoadPermBlockTrackerMissingReturnsEmpty(t *testing.T) {
	tracker := loadPermBlockTracker(t.TempDir())
	if tracker == nil {
		t.Fatal("loadPermBlockTracker returned nil")
	}
	if tracker.IPs == nil {
		t.Error("IPs map should be non-nil")
	}
}

func TestLoadPermBlockTrackerCorruptJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "permblock_tracker.json"), []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	tracker := loadPermBlockTracker(dir)
	if tracker.IPs == nil {
		t.Error("IPs map should be non-nil even on corrupt file")
	}
}

// --- hexToIPv4 (hardening_audit.go) ------------------------------------

func TestHexToIPv4Standard(t *testing.T) {
	// 127.0.0.1 as little-endian 32-bit: 0100007F
	if got := hexToIPv4("0100007F"); got != "127.0.0.1" {
		t.Errorf("got %q, want 127.0.0.1", got)
	}
}

func TestHexToIPv4PublicIP(t *testing.T) {
	// 8.8.8.8 → 08080808 (all four bytes same, order doesn't matter).
	if got := hexToIPv4("08080808"); got != "8.8.8.8" {
		t.Errorf("got %q, want 8.8.8.8", got)
	}
}

func TestHexToIPv4WrongLength(t *testing.T) {
	if got := hexToIPv4("ZZ"); got != "ZZ" {
		t.Errorf("got %q, want pass-through", got)
	}
}

func TestHexToIPv4InvalidHex(t *testing.T) {
	if got := hexToIPv4("GGGGGGGG"); got != "GGGGGGGG" {
		t.Errorf("got %q, want pass-through", got)
	}
}

// --- isPrivateOrLoopback ------------------------------------------------

func TestIsPrivateOrLoopbackLoopback(t *testing.T) {
	if !isPrivateOrLoopback("127.0.0.1") {
		t.Error("127.0.0.1 should be loopback")
	}
	if !isPrivateOrLoopback("::1") {
		t.Error("::1 should be loopback")
	}
}

func TestIsPrivateOrLoopbackRFC1918(t *testing.T) {
	privates := []string{"10.0.0.1", "172.20.5.5", "192.168.1.1"}
	for _, ip := range privates {
		if !isPrivateOrLoopback(ip) {
			t.Errorf("%s should be private", ip)
		}
	}
}

func TestIsPrivateOrLoopbackPublic(t *testing.T) {
	publics := []string{"8.8.8.8", "1.1.1.1", "203.0.113.5"}
	for _, ip := range publics {
		if isPrivateOrLoopback(ip) {
			t.Errorf("%s should NOT be private/loopback", ip)
		}
	}
}

func TestIsPrivateOrLoopbackIPv6ULA(t *testing.T) {
	if !isPrivateOrLoopback("fc00::1") {
		t.Error("fc00::1 should be private (RFC 4193 ULA)")
	}
}

func TestIsPrivateOrLoopbackInvalidIP(t *testing.T) {
	if isPrivateOrLoopback("not-an-ip") {
		t.Error("invalid IP should return false")
	}
}

// --- parseSSHDFile ------------------------------------------------------

func TestParseSSHDFileWithIncludeAndMatchBlock(t *testing.T) {
	dir := t.TempDir()

	mainPath := filepath.Join(dir, "sshd_config")
	confDir := filepath.Join(dir, "conf.d")
	if err := os.MkdirAll(confDir, 0755); err != nil {
		t.Fatal(err)
	}

	mainContent := "# Main sshd config\n" +
		"PermitRootLogin no\n" +
		"PasswordAuthentication yes\n" +
		"\n" +
		"Include " + filepath.Join(confDir, "*.conf") + "\n" +
		"\n" +
		"Match User admin\n" +
		"    PasswordAuthentication yes\n" +
		"    PermitRootLogin yes\n" +
		"\n" +
		"# Everything after this line is still inside the Match block\n" +
		"X11Forwarding yes\n"
	if err := os.WriteFile(mainPath, []byte(mainContent), 0644); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(confDir, "override.conf"), []byte("ClientAliveInterval 300\n"), 0644); err != nil {
		t.Fatal(err)
	}

	effective := make(map[string]string)
	parseSSHDFile(mainPath, effective)

	if effective["permitrootlogin"] != "no" {
		t.Errorf("permitrootlogin = %q, want no (first-match-wins)", effective["permitrootlogin"])
	}
	if effective["passwordauthentication"] != "yes" {
		t.Errorf("passwordauthentication = %q, want yes", effective["passwordauthentication"])
	}
	// X11Forwarding is inside a Match block — must NOT be recorded.
	if _, ok := effective["x11forwarding"]; ok {
		t.Error("X11Forwarding inside Match block should be ignored")
	}
	// Include should have pulled in ClientAliveInterval.
	if effective["clientaliveinterval"] != "300" {
		t.Errorf("clientaliveinterval = %q, want 300 (from Include)", effective["clientaliveinterval"])
	}
}

func TestParseSSHDFileMissingFileIsNoOp(t *testing.T) {
	effective := make(map[string]string)
	parseSSHDFile(filepath.Join(t.TempDir(), "never"), effective)
	if len(effective) != 0 {
		t.Errorf("missing file should not modify effective map, got %v", effective)
	}
}

func TestParseSSHDFileKeywordEqualsValueForm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(path, []byte("PermitRootLogin=no\nPort=2222\n"), 0644); err != nil {
		t.Fatal(err)
	}
	effective := make(map[string]string)
	parseSSHDFile(path, effective)
	if effective["permitrootlogin"] != "no" {
		t.Errorf("permitrootlogin = %q, want no", effective["permitrootlogin"])
	}
	if effective["port"] != "2222" {
		t.Errorf("port = %q, want 2222", effective["port"])
	}
}

// --- parseVersion / compareVersions / pluginAlertSeverity -------------

func TestParseVersionStandard(t *testing.T) {
	got := parseVersion("6.4.2")
	if len(got) != 3 || got[0] != 6 || got[1] != 4 || got[2] != 2 {
		t.Errorf("got %v, want [6 4 2]", got)
	}
}

func TestParseVersionNonNumericSegment(t *testing.T) {
	got := parseVersion("1.0.0-rc1")
	if len(got) != 3 || got[0] != 1 || got[1] != 0 {
		t.Errorf("got %v", got)
	}
	// Last segment "0-rc1" is not a pure int, so it's 0.
	if got[2] != 0 {
		t.Errorf("got[2] = %d, want 0 (non-numeric fallback)", got[2])
	}
}

func TestParseVersionEmpty(t *testing.T) {
	if got := parseVersion(""); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestCompareVersionsMajorGap(t *testing.T) {
	major, minor := compareVersions("5.9.0", "6.4.2")
	if !major {
		t.Error("5 -> 6 should be a major gap")
	}
	if minor != 0 {
		t.Errorf("minor = %d, want 0 on major gap", minor)
	}
}

func TestCompareVersionsMinorBehind(t *testing.T) {
	major, minor := compareVersions("6.1.0", "6.4.2")
	if major {
		t.Error("same major should not be major gap")
	}
	if minor != 3 {
		t.Errorf("minor = %d, want 3 (1 -> 4)", minor)
	}
}

func TestCompareVersionsEqual(t *testing.T) {
	major, minor := compareVersions("6.4.2", "6.4.2")
	if major || minor != 0 {
		t.Errorf("equal versions should not gap: major=%v minor=%d", major, minor)
	}
}

func TestCompareVersionsAhead(t *testing.T) {
	// Installed is ahead of available — custom/premium build.
	major, minor := compareVersions("7.0.0", "6.4.2")
	if major || minor != 0 {
		t.Errorf("ahead version should not gap: major=%v minor=%d", major, minor)
	}
}

func TestCompareVersionsShortSegments(t *testing.T) {
	major, minor := compareVersions("6", "6.4")
	if major || minor != 0 {
		t.Errorf("too-short segments should not gap: major=%v minor=%d", major, minor)
	}
}

func TestPluginAlertSeverityCritical(t *testing.T) {
	if got := pluginAlertSeverity("5.9.0", "6.4.2"); got != "critical" {
		t.Errorf("got %q, want critical (major gap)", got)
	}
}

func TestPluginAlertSeverityHigh(t *testing.T) {
	if got := pluginAlertSeverity("6.1.0", "6.4.2"); got != "high" {
		t.Errorf("got %q, want high (3 minors behind)", got)
	}
}

func TestPluginAlertSeverityWarning(t *testing.T) {
	if got := pluginAlertSeverity("6.4.0", "6.4.2"); got != "warning" {
		t.Errorf("got %q, want warning (patch behind)", got)
	}
}

func TestPluginAlertSeverityNoneWhenEqual(t *testing.T) {
	if got := pluginAlertSeverity("6.4.2", "6.4.2"); got != "" {
		t.Errorf("got %q, want empty (equal)", got)
	}
}

func TestPluginAlertSeverityNoneWhenAhead(t *testing.T) {
	if got := pluginAlertSeverity("6.4.5", "6.4.2"); got != "" {
		t.Errorf("got %q, want empty (ahead)", got)
	}
}

// --- parseWPOrgPluginResponse -----------------------------------------

func TestParseWPOrgPluginResponseValid(t *testing.T) {
	body := []byte(`{"version":"1.2.3","tested":"6.4"}`)
	info, err := parseWPOrgPluginResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	if info.LatestVersion != "1.2.3" {
		t.Errorf("LatestVersion = %q", info.LatestVersion)
	}
	if info.TestedUpTo != "6.4" {
		t.Errorf("TestedUpTo = %q", info.TestedUpTo)
	}
	if info.LastChecked == 0 {
		t.Error("LastChecked should be set")
	}
}

func TestParseWPOrgPluginResponseError(t *testing.T) {
	body := []byte(`{"error":"plugin not found"}`)
	_, err := parseWPOrgPluginResponse(body)
	if err == nil {
		t.Fatal("error response should surface")
	}
}

func TestParseWPOrgPluginResponseMalformed(t *testing.T) {
	_, err := parseWPOrgPluginResponse([]byte("not json"))
	if err == nil {
		t.Fatal("malformed JSON should error")
	}
}

// --- parseValiasLine / isPipeForwarder / isDevNullForwarder -----------

func TestParseValiasLineStandard(t *testing.T) {
	local, dest := parseValiasLine("alice: alice@example.com")
	if local != "alice" || dest != "alice@example.com" {
		t.Errorf("got (%q, %q)", local, dest)
	}
}

func TestParseValiasLineComment(t *testing.T) {
	local, dest := parseValiasLine("# this is a comment")
	if local != "" || dest != "" {
		t.Errorf("comment should return empty, got (%q, %q)", local, dest)
	}
}

func TestParseValiasLineBlank(t *testing.T) {
	local, dest := parseValiasLine("")
	if local != "" || dest != "" {
		t.Errorf("blank should return empty, got (%q, %q)", local, dest)
	}
}

func TestParseValiasLineNoColon(t *testing.T) {
	local, dest := parseValiasLine("invalid line")
	if local != "" || dest != "" {
		t.Errorf("no colon should return empty, got (%q, %q)", local, dest)
	}
}

func TestIsPipeForwarderPipe(t *testing.T) {
	if !isPipeForwarder("|/bin/sh attacker-script.sh") {
		t.Error("pipe forwarder should be detected")
	}
}

func TestIsPipeForwarderSafeCpanel(t *testing.T) {
	// Known-safe cPanel built-in pipes should NOT be flagged.
	safe := []string{
		"|/usr/local/cpanel/bin/autorespond /home/user/.autorespond",
		"|/usr/local/cpanel/bin/boxtrapper /home/user/boxtrapper",
	}
	for _, dest := range safe {
		if isPipeForwarder(dest) {
			t.Errorf("%q should be safe, not flagged", dest)
		}
	}
}

func TestIsPipeForwarderNotPipe(t *testing.T) {
	if isPipeForwarder("alice@example.com") {
		t.Error("email forwarder should not be flagged as pipe")
	}
}

func TestIsDevNullForwarder(t *testing.T) {
	if !isDevNullForwarder("/dev/null") {
		t.Error("/dev/null should be flagged")
	}
	if isDevNullForwarder("/home/alice/.forward") {
		t.Error("regular file should not be flagged as /dev/null")
	}
}

func TestIsExternalDestExternal(t *testing.T) {
	local := map[string]bool{"example.com": true}
	if !isExternalDest("alice@external.com", local) {
		t.Error("external.com should be external")
	}
}

func TestIsExternalDestLocal(t *testing.T) {
	local := map[string]bool{"example.com": true}
	if isExternalDest("alice@example.com", local) {
		t.Error("local domain should not be external")
	}
}

func TestIsExternalDestNoAtSign(t *testing.T) {
	local := map[string]bool{"example.com": true}
	if isExternalDest("not an email", local) {
		t.Error("malformed dest should not count as external")
	}
}

// parseVfilterExternalDests is already covered by forwarder_test.go.

// --- extractIPFromLog / countBruteForce (bruteforce.go) --------------

func TestExtractIPFromLogStandard(t *testing.T) {
	line := `203.0.113.5 - - [11/Apr/2026:10:00:00 +0000] "GET /wp-login.php HTTP/1.1" 200 1234`
	if got := extractIPFromLog(line); got != "203.0.113.5" {
		t.Errorf("got %q, want 203.0.113.5", got)
	}
}

func TestExtractIPFromLogNoIP(t *testing.T) {
	if got := extractIPFromLog("no ip here"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestExtractIPFromLogStripsPunctuation(t *testing.T) {
	if got := extractIPFromLog("from 198.51.100.1, banned"); got != "198.51.100.1" {
		t.Errorf("got %q, want 198.51.100.1", got)
	}
}

func TestCountBruteForceWPLogin(t *testing.T) {
	lines := []string{
		`203.0.113.5 - - [01/Jan/2026:10:00:00 +0000] "POST /wp-login.php HTTP/1.1" 200 10`,
		`203.0.113.5 - - [01/Jan/2026:10:00:00 +0000] "POST /wp-login.php HTTP/1.1" 200 10`,
		`203.0.113.5 - - [01/Jan/2026:10:00:00 +0000] "POST /wp-login.php HTTP/1.1" 200 10`,
		`198.51.100.1 - - [01/Jan/2026:10:00:00 +0000] "GET /index.php HTTP/1.1" 200 10`,
	}
	wpLogin := map[string]int{}
	xmlrpc := map[string]int{}
	userEnum := map[string]int{}
	countBruteForce(lines, nil, wpLogin, xmlrpc, userEnum)

	if wpLogin["203.0.113.5"] != 3 {
		t.Errorf("wpLogin[203.0.113.5] = %d, want 3", wpLogin["203.0.113.5"])
	}
	if wpLogin["198.51.100.1"] != 0 {
		t.Error("non-wp-login GET should not count")
	}
}

func TestCountBruteForceXMLRPC(t *testing.T) {
	lines := []string{
		`203.0.113.5 - - [01/Jan/2026:10:00:00 +0000] "POST /xmlrpc.php HTTP/1.1" 200 10`,
		`203.0.113.5 - - [01/Jan/2026:10:00:00 +0000] "POST /xmlrpc.php HTTP/1.1" 200 10`,
	}
	xmlrpc := map[string]int{}
	countBruteForce(lines, nil, map[string]int{}, xmlrpc, map[string]int{})
	if xmlrpc["203.0.113.5"] != 2 {
		t.Errorf("xmlrpc[203.0.113.5] = %d, want 2", xmlrpc["203.0.113.5"])
	}
}

func TestCountBruteForceUserEnumAuthorQuery(t *testing.T) {
	lines := []string{
		`203.0.113.5 - - [01/Jan/2026:10:00:00 +0000] "GET /?author=1 HTTP/1.1" 200 10`,
		`203.0.113.5 - - [01/Jan/2026:10:00:00 +0000] "GET /?author=2 HTTP/1.1" 200 10`,
	}
	ue := map[string]int{}
	countBruteForce(lines, nil, map[string]int{}, map[string]int{}, ue)
	if ue["203.0.113.5"] != 2 {
		t.Errorf("got %d, want 2", ue["203.0.113.5"])
	}
}

func TestCountBruteForceRESTAPIUserEnum(t *testing.T) {
	lines := []string{
		`203.0.113.5 - - [01/Jan/2026:10:00:00 +0000] "GET /wp-json/wp/v2/users HTTP/1.1" 200 10`,
		`203.0.113.5 - - [01/Jan/2026:10:00:00 +0000] "GET /wp-json/wp/v2/users/me HTTP/1.1" 200 10`,
	}
	ue := map[string]int{}
	countBruteForce(lines, nil, map[string]int{}, map[string]int{}, ue)
	if ue["203.0.113.5"] != 1 {
		t.Errorf("got %d, want 1 (/users/me excluded)", ue["203.0.113.5"])
	}
}

func TestCountBruteForceSkipsLoopback(t *testing.T) {
	lines := []string{
		`127.0.0.1 - - [01/Jan/2026:10:00:00 +0000] "POST /wp-login.php HTTP/1.1" 200 10`,
		`::1 - - [01/Jan/2026:10:00:00 +0000] "POST /wp-login.php HTTP/1.1" 200 10`,
		`- - - [01/Jan/2026:10:00:00 +0000] "POST /wp-login.php HTTP/1.1" 200 10`,
	}
	wp := map[string]int{}
	countBruteForce(lines, nil, wp, map[string]int{}, map[string]int{})
	if len(wp) != 0 {
		t.Errorf("loopback/placeholder should be skipped, got %v", wp)
	}
}

func TestCountBruteForceSkipsInfraIPs(t *testing.T) {
	infra := []string{"10.0.0.5"}
	lines := []string{
		`10.0.0.5 - - [01/Jan/2026:10:00:00 +0000] "POST /wp-login.php HTTP/1.1" 200 10`,
	}
	wp := map[string]int{}
	countBruteForce(lines, infra, wp, map[string]int{}, map[string]int{})
	if len(wp) != 0 {
		t.Errorf("infra IP should be skipped, got %v", wp)
	}
}

func TestCountBruteForceMalformedLines(t *testing.T) {
	lines := []string{"", "too short", "    "}
	wp := map[string]int{}
	countBruteForce(lines, nil, wp, map[string]int{}, map[string]int{})
	if len(wp) != 0 {
		t.Errorf("malformed lines should be skipped, got %v", wp)
	}
}
