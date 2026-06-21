package alert

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDeduplicate(t *testing.T) {
	findings := []Finding{
		{Check: "a", Message: "msg1"},
		{Check: "a", Message: "msg1"}, // duplicate
		{Check: "b", Message: "msg2"},
		{Check: "a", Message: "msg1"}, // duplicate
		{Check: "b", Message: "msg3"},
	}

	result := Deduplicate(findings)
	if len(result) != 3 {
		t.Errorf("expected 3 unique findings, got %d", len(result))
	}
}

func TestDeduplicateEmpty(t *testing.T) {
	result := Deduplicate(nil)
	if len(result) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result))
	}
}

func TestFindingRelayBreakdownJSONRoundTrip(t *testing.T) {
	lastSeen := time.Unix(1_700_000_000, 0).UTC()
	in := Finding{
		Check:      "email_php_relay_abuse",
		Path:       "fanout",
		SourceIP:   "192.0.2.10",
		RelayTotal: 7,
		RelayBreakdown: []RelayScriptHit{
			{ScriptKey: "site.example.com:/wp-comments-post.php", Hits: 4, LastSeen: lastSeen, SampleSubject: "Please moderate"},
			{ScriptKey: "other.example.com:/wp-comments-post.php", Hits: 3, LastSeen: lastSeen.Add(-time.Minute)},
		},
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Finding
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.RelayTotal != 7 || len(out.RelayBreakdown) != 2 {
		t.Fatalf("round trip lost data: total=%d len=%d", out.RelayTotal, len(out.RelayBreakdown))
	}
	if out.RelayBreakdown[0].Hits != 4 || out.RelayBreakdown[0].SampleSubject != "Please moderate" {
		t.Fatalf("breakdown[0] wrong: %+v", out.RelayBreakdown[0])
	}
	if !out.RelayBreakdown[0].LastSeen.Equal(lastSeen) {
		t.Fatalf("breakdown[0] last_seen = %s, want %s", out.RelayBreakdown[0].LastSeen, lastSeen)
	}
}

func TestFindingOmitsRelayFieldsWhenEmpty(t *testing.T) {
	b, _ := json.Marshal(Finding{Check: "waf", Message: "m"})
	if strings.Contains(string(b), "relay_total") || strings.Contains(string(b), "relay_breakdown") {
		t.Fatalf("empty relay fields must be omitted: %s", b)
	}
}

func TestFindingKey(t *testing.T) {
	f := Finding{Check: "test", Message: "hello"}
	if f.Key() != "test:hello" {
		t.Errorf("expected 'test:hello', got '%s'", f.Key())
	}
}

func TestFindingKeyIncludesDetailsHash(t *testing.T) {
	f := Finding{Check: "test", Message: "hello", Details: "detail payload"}
	if got := f.Key(); got == "test:hello" {
		t.Fatalf("expected details hash in key, got %q", got)
	}
}

func TestFindingKeyHTTPAbuseStableForSourceIP(t *testing.T) {
	a := Finding{
		Check:   "xmlrpc_abuse",
		Message: "XML-RPC abuse from 203.0.113.9: 15 hits",
		Details: "Aggregated across 272 domlog files",
	}
	b := Finding{
		Check:   "xmlrpc_abuse",
		Message: "XML-RPC abuse from 203.0.113.9: 42 hits",
		Details: "Aggregated across 173 domlog files",
	}

	if a.Key() != b.Key() {
		t.Fatalf("source-IP HTTP finding key changed: %q vs %q", a.Key(), b.Key())
	}
	if a.Fingerprint() != b.Fingerprint() {
		t.Fatalf("source-IP HTTP finding fingerprint changed: %q vs %q", a.Fingerprint(), b.Fingerprint())
	}
}

func TestFindingKeyUsesStructuredSourceIP(t *testing.T) {
	f := Finding{
		Check:    "wp_login_bruteforce",
		Message:  "WordPress brute force from untrusted text",
		SourceIP: "198.51.100.44",
	}
	if got := f.Key(); got != "wp_login_bruteforce:ip:198.51.100.44" {
		t.Fatalf("key = %q, want structured source IP", got)
	}
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{Warning, "WARNING"},
		{High, "HIGH"},
		{Critical, "CRITICAL"},
		{Severity(99), "UNKNOWN"},
	}
	for _, tt := range tests {
		if got := tt.sev.String(); got != tt.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

func TestFormatAlert(t *testing.T) {
	findings := []Finding{
		{Severity: Critical, Check: "test", Message: "bad thing", Timestamp: time.Now()},
	}
	body := FormatAlert("test-host", findings)
	if body == "" {
		t.Error("expected non-empty alert body")
	}
	if !contains(body, "SECURITY ALERT") {
		t.Error("expected SECURITY ALERT in body")
	}
	if !contains(body, "test-host") {
		t.Error("expected hostname in body")
	}
}

func TestFilterChecks(t *testing.T) {
	findings := []Finding{
		{Check: "email_spam_outbreak", Message: "a"},
		{Check: "perf_memory", Message: "b"},
		{Check: "malware", Message: "c"},
	}

	got := filterChecks(findings, []string{"email_spam_outbreak", " perf_memory ", ""})
	if len(got) != 1 {
		t.Fatalf("expected 1 finding after filtering, got %d", len(got))
	}
	if got[0].Check != "malware" {
		t.Fatalf("expected malware to remain, got %s", got[0].Check)
	}
}

func TestBuildSubject(t *testing.T) {
	if got := buildSubject("host1", []Finding{{Severity: High}, {Severity: Warning}}); got != "[CSM] host1 - 2 security finding(s)" {
		t.Fatalf("unexpected non-critical subject: %s", got)
	}
	if got := buildSubject("host1", []Finding{{Severity: High}, {Severity: Critical}}); got != "[CSM] CRITICAL - host1 - 2 finding(s)" {
		t.Fatalf("unexpected critical subject: %s", got)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestFinding_PHPRelayFields(t *testing.T) {
	f := Finding{
		Severity:  Critical,
		Check:     "email_php_relay_abuse",
		Path:      "header",
		ScriptKey: "rentvsloan.example.com:/wp-admin/admin-ajax.php",
		SourceIP:  "192.0.2.10",
		CPUser:    "exampleuser",
		MsgIDs:    []string{"1wHpIU-0000000G8Fo-1FA1"},
	}
	if f.Path != "header" || f.ScriptKey == "" || f.SourceIP == "" || f.CPUser == "" || len(f.MsgIDs) != 1 {
		t.Fatalf("structured fields not retained: %+v", f)
	}
}

func TestFinding_BackwardCompat_ZeroValues(t *testing.T) {
	// Existing callers that don't set these fields must still produce a
	// valid Finding (zero values, no panics).
	f := Finding{Severity: Warning, Check: "x", Message: "y"}
	if f.Path != "" || f.ScriptKey != "" || f.SourceIP != "" || f.CPUser != "" || f.MsgIDs != nil {
		t.Fatalf("zero-value Finding must keep php_relay fields empty: %+v", f)
	}
}

func TestFindingKeyHTTPAbuseNewChecksUseStructuredSourceIP(t *testing.T) {
	for _, check := range []string{"http_request_flood", "http_scanner_profile", "http_claimed_bot_unverified", "http_ua_spoof"} {
		a := Finding{Check: check, SourceIP: "203.0.113.88", Message: "sample A"}
		b := Finding{Check: check, SourceIP: "203.0.113.88", Message: "sample B"}
		if a.Key() != b.Key() {
			t.Fatalf("%s key changed with message text: %q vs %q", check, a.Key(), b.Key())
		}
	}
}

func TestFindingKeyFTPBruteforceDedupsBySourceIP(t *testing.T) {
	a := Finding{Check: "ftp_bruteforce", SourceIP: "203.0.113.5", Message: "FTP brute force from 203.0.113.5: 10 failed attempts in 30m"}
	b := Finding{Check: "ftp_bruteforce", SourceIP: "203.0.113.5", Message: "FTP brute force from 203.0.113.5: 55 failed attempts in 30m"}
	if a.Key() != b.Key() {
		t.Fatalf("same-IP ftp_bruteforce findings must share a key: %q vs %q", a.Key(), b.Key())
	}
}
