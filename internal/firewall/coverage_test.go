package firewall

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- InferProvenance --------------------------------------------------

func TestInferProvenanceDynDNS(t *testing.T) {
	if got := InferProvenance("allow", "dyndns: home.example.org"); got != SourceDynDNS {
		t.Errorf("got %q, want dyndns", got)
	}
}

func TestInferProvenanceChallenge(t *testing.T) {
	cases := []string{
		"passed challenge",
		"CSM challenge-timeout: brute force",
		"challenge timeout",
	}
	for _, reason := range cases {
		if got := InferProvenance("allow", reason); got != SourceChallenge {
			t.Errorf("%q -> %q, want challenge", reason, got)
		}
	}
}

func TestInferProvenanceWhitelist(t *testing.T) {
	cases := []string{
		"temp whitelist",
		"whitelist: trusted IP",
		"bulk whitelist import",
		"customer IP from WHM",
	}
	for _, reason := range cases {
		if got := InferProvenance("allow", reason); got != SourceWhitelist {
			t.Errorf("%q -> %q, want whitelist", reason, got)
		}
	}
}

func TestInferProvenanceAutoResponse(t *testing.T) {
	cases := []string{
		"auto-block for brute force",
		"permblock after 5 offenses",
		"auto-netblock subnet",
	}
	for _, reason := range cases {
		if got := InferProvenance("block", reason); got != SourceAutoResponse {
			t.Errorf("%q -> %q, want auto_response", reason, got)
		}
	}
}

func TestInferProvenanceCLI(t *testing.T) {
	if got := InferProvenance("block", "blocked via CLI"); got != SourceCLI {
		t.Errorf("got %q, want cli", got)
	}
}

func TestInferProvenanceWebUI(t *testing.T) {
	cases := []string{
		"blocked via CSM web UI",
		"via ui",
		"allowed from firewall lookup",
		"manual block from admin panel",
	}
	for _, reason := range cases {
		if got := InferProvenance("block", reason); got != SourceWebUI {
			t.Errorf("%q -> %q, want web_ui", reason, got)
		}
	}
}

func TestInferProvenanceSystemActions(t *testing.T) {
	if got := InferProvenance("temp_allow_expired", ""); got != SourceSystem {
		t.Errorf("got %q, want system", got)
	}
	if got := InferProvenance("flush", ""); got != SourceSystem {
		t.Errorf("got %q, want system", got)
	}
}

func TestInferProvenanceUnknown(t *testing.T) {
	if got := InferProvenance("unknown", "no match here"); got != SourceUnknown {
		t.Errorf("got %q, want unknown", got)
	}
}

func TestInferProvenanceTrimsAndLowercase(t *testing.T) {
	// Leading/trailing whitespace + mixed case should not prevent matching.
	if got := InferProvenance("  BLOCK  ", "  Via CLI  "); got != SourceCLI {
		t.Errorf("got %q, want cli (should trim + lowercase)", got)
	}
}

// --- DefaultConfig -----------------------------------------------------

func TestDefaultConfigNonNil(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}
	if cfg.ConnRateLimit == 0 {
		t.Error("ConnRateLimit should be set")
	}
	if cfg.PassiveFTPStart == 0 {
		t.Error("PassiveFTPStart should be set")
	}
	if len(cfg.TCPIn) == 0 {
		t.Error("TCPIn should have default ports")
	}
	if len(cfg.PortFlood) == 0 {
		t.Error("PortFlood should have default rules")
	}
}

// --- LoadState ---------------------------------------------------------

func TestLoadStateMissingFileReturnsEmpty(t *testing.T) {
	state, err := LoadState(t.TempDir())
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if state == nil {
		t.Fatal("state should not be nil")
	}
	if len(state.Blocked) != 0 || len(state.BlockedNet) != 0 || len(state.Allowed) != 0 {
		t.Errorf("empty dir should yield empty state, got %+v", state)
	}
}

func TestLoadStatePrunesExpired(t *testing.T) {
	dir := t.TempDir()
	fwDir := filepath.Join(dir, "firewall")
	if err := os.MkdirAll(fwDir, 0700); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	state := &FirewallState{
		Blocked: []BlockedEntry{
			{IP: "1.1.1.1", ExpiresAt: now.Add(-1 * time.Hour)}, // expired
			{IP: "2.2.2.2", ExpiresAt: now.Add(1 * time.Hour)},  // active
			{IP: "3.3.3.3", ExpiresAt: time.Time{}},             // permanent
		},
		BlockedNet: []SubnetEntry{
			{CIDR: "10.0.0.0/8", ExpiresAt: now.Add(-1 * time.Hour)},
			{CIDR: "203.0.113.0/24", ExpiresAt: now.Add(1 * time.Hour)},
		},
		Allowed: []AllowedEntry{
			{IP: "4.4.4.4", ExpiresAt: now.Add(-1 * time.Hour)},
			{IP: "5.5.5.5", ExpiresAt: time.Time{}},
		},
	}
	data, _ := json.Marshal(state)
	if err := os.WriteFile(filepath.Join(fwDir, "state.json"), data, 0600); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}

	blockedIPs := make(map[string]bool)
	for _, b := range loaded.Blocked {
		blockedIPs[b.IP] = true
	}
	if blockedIPs["1.1.1.1"] {
		t.Error("expired block 1.1.1.1 should be pruned")
	}
	if !blockedIPs["2.2.2.2"] {
		t.Error("active block 2.2.2.2 should remain")
	}
	if !blockedIPs["3.3.3.3"] {
		t.Error("permanent block 3.3.3.3 should remain")
	}

	netCIDRs := make(map[string]bool)
	for _, n := range loaded.BlockedNet {
		netCIDRs[n.CIDR] = true
	}
	if netCIDRs["10.0.0.0/8"] {
		t.Error("expired subnet should be pruned")
	}
	if !netCIDRs["203.0.113.0/24"] {
		t.Error("active subnet should remain")
	}

	allowedIPs := make(map[string]bool)
	for _, a := range loaded.Allowed {
		allowedIPs[a.IP] = true
	}
	if allowedIPs["4.4.4.4"] {
		t.Error("expired allow should be pruned")
	}
	if !allowedIPs["5.5.5.5"] {
		t.Error("permanent allow should remain")
	}
}

func TestLoadStateMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	fwDir := filepath.Join(dir, "firewall")
	if err := os.MkdirAll(fwDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fwDir, "state.json"), []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadState(dir)
	if err == nil {
		t.Fatal("malformed JSON should error")
	}
}

// --- AppendAudit / ReadAuditLog ---------------------------------------

func TestAppendAuditAndReadBackRoundTrip(t *testing.T) {
	// AppendAudit receives statePath WITHOUT "firewall" suffix (the
	// production caller is engine.go which pre-pends "firewall" to
	// e.statePath). ReadAuditLog receives statePath WITH "firewall"
	// unresolved — it appends "firewall" internally. To round-trip via
	// the pair, we must call AppendAudit with the firewall dir and
	// ReadAuditLog with its parent.
	parent := t.TempDir()
	fwDir := filepath.Join(parent, "firewall")
	if err := os.MkdirAll(fwDir, 0700); err != nil {
		t.Fatal(err)
	}

	AppendAudit(fwDir, "block", "203.0.113.5", "brute force", "", 1*time.Hour)
	AppendAudit(fwDir, "unblock", "203.0.113.5", "", "", 0)

	// Read back via the public API (passing the PARENT path).
	entries := ReadAuditLog(parent, 10)
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].Action != "block" {
		t.Errorf("entries[0].Action = %q", entries[0].Action)
	}
	if entries[0].Duration == "" {
		t.Error("block with non-zero duration should set Duration field")
	}
	if entries[1].Action != "unblock" {
		t.Errorf("entries[1].Action = %q", entries[1].Action)
	}
}

func TestAppendAuditInfersSourceFromReason(t *testing.T) {
	fwDir := filepath.Join(t.TempDir(), "firewall")
	if err := os.MkdirAll(fwDir, 0700); err != nil {
		t.Fatal(err)
	}
	// No explicit Source; should get inferred as "auto_response".
	AppendAudit(fwDir, "block", "1.2.3.4", "auto-block triggered", "", 0)

	data, err := os.ReadFile(filepath.Join(fwDir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var entry AuditEntry
	if err := json.Unmarshal(data[:len(data)-1], &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Source != SourceAutoResponse {
		t.Errorf("Source = %q, want auto_response (inferred)", entry.Source)
	}
}

func TestReadAuditLogMissingFileReturnsNil(t *testing.T) {
	if got := ReadAuditLog(t.TempDir(), 10); got != nil {
		t.Errorf("missing file = %v, want nil", got)
	}
}

func TestReadAuditLogLimit(t *testing.T) {
	parent := t.TempDir()
	fwDir := filepath.Join(parent, "firewall")
	if err := os.MkdirAll(fwDir, 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		AppendAudit(fwDir, "block", "1.1.1.1", "test", "cli", 0)
	}
	got := ReadAuditLog(parent, 3)
	if len(got) != 3 {
		t.Errorf("got %d entries, want 3 (limit)", len(got))
	}
}

func TestReadAuditLogNoLimitReturnsAll(t *testing.T) {
	parent := t.TempDir()
	fwDir := filepath.Join(parent, "firewall")
	if err := os.MkdirAll(fwDir, 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		AppendAudit(fwDir, "block", "1.1.1.1", "test", "cli", 0)
	}
	got := ReadAuditLog(parent, 0)
	if len(got) != 5 {
		t.Errorf("got %d, want 5 (no limit)", len(got))
	}
}

func TestReadAuditLogSkipsMalformedLines(t *testing.T) {
	parent := t.TempDir()
	fwDir := filepath.Join(parent, "firewall")
	if err := os.MkdirAll(fwDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Write a real entry followed by a malformed line.
	valid := AuditEntry{Timestamp: time.Now(), Action: "block", IP: "1.1.1.1"}
	body, _ := json.Marshal(valid)
	var content []byte
	content = append(content, body...)
	content = append(content, '\n')
	content = append(content, []byte("not-json\n")...)
	if err := os.WriteFile(filepath.Join(fwDir, "audit.jsonl"), content, 0600); err != nil {
		t.Fatal(err)
	}

	got := ReadAuditLog(parent, 10)
	if len(got) != 1 {
		t.Errorf("got %d, want 1 (malformed line should be skipped)", len(got))
	}
}

// --- AppendAudit rotation ---------------------------------------------

func TestAppendAuditRotatesLargeFile(t *testing.T) {
	fwDir := filepath.Join(t.TempDir(), "firewall")
	if err := os.MkdirAll(fwDir, 0700); err != nil {
		t.Fatal(err)
	}
	// Seed a file slightly above the 10 MB rotation threshold.
	auditPath := filepath.Join(fwDir, "audit.jsonl")
	big := make([]byte, 11*1024*1024)
	for i := range big {
		big[i] = 'x'
	}
	if err := os.WriteFile(auditPath, big, 0600); err != nil {
		t.Fatal(err)
	}

	AppendAudit(fwDir, "block", "1.2.3.4", "test", "cli", 0)

	// Rotation should have moved the old file to audit.jsonl.1.
	if _, err := os.Stat(auditPath + ".1"); err != nil {
		t.Errorf("rotated file audit.jsonl.1 not present: %v", err)
	}
	// New file should exist with just the new entry.
	info, err := os.Stat(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() >= int64(len(big)) {
		t.Errorf("new audit file should be smaller than the rotated one, got %d", info.Size())
	}
}

// --- LoadCFRefreshTime + fetchCIDRList (HTTP-backed) -----------------

func TestLoadCFRefreshTimeMissing(t *testing.T) {
	// LoadCFRefreshTime returns zero when the marker file doesn't exist.
	got := LoadCFRefreshTime(t.TempDir())
	if !got.IsZero() {
		t.Errorf("missing marker should yield zero time, got %v", got)
	}
}

func TestLoadCFRefreshTimeRoundTrip(t *testing.T) {
	// LoadCFRefreshTime reads the "# refreshed: <RFC3339>" header from
	// {statePath}/firewall/cf_whitelist.txt. Write a minimal file and
	// verify it parses back.
	dir := t.TempDir()
	cfDir := filepath.Join(dir, "firewall")
	if err := os.MkdirAll(cfDir, 0700); err != nil {
		t.Fatal(err)
	}
	stamp := time.Date(2026, 4, 11, 10, 0, 0, 0, time.UTC)
	content := "# refreshed: " + stamp.Format(time.RFC3339) + "\n192.0.2.0/24\n"
	if err := os.WriteFile(filepath.Join(cfDir, "cf_whitelist.txt"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	got := LoadCFRefreshTime(dir)
	if !got.Equal(stamp) {
		t.Errorf("got %v, want %v", got, stamp)
	}
}

func TestLoadCFRefreshTimeMalformedHeader(t *testing.T) {
	dir := t.TempDir()
	cfDir := filepath.Join(dir, "firewall")
	if err := os.MkdirAll(cfDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfDir, "cf_whitelist.txt"), []byte("# refreshed: not a timestamp\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := LoadCFRefreshTime(dir); !got.IsZero() {
		t.Errorf("malformed header should yield zero time, got %v", got)
	}
}

func TestLoadCFRefreshTimeNoHeader(t *testing.T) {
	dir := t.TempDir()
	cfDir := filepath.Join(dir, "firewall")
	if err := os.MkdirAll(cfDir, 0700); err != nil {
		t.Fatal(err)
	}
	// File exists but the first line is not a refresh comment.
	if err := os.WriteFile(filepath.Join(cfDir, "cf_whitelist.txt"), []byte("192.0.2.0/24\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := LoadCFRefreshTime(dir); !got.IsZero() {
		t.Errorf("no refresh header should yield zero time, got %v", got)
	}
}

func TestFetchCIDRListSuccess(t *testing.T) {
	// fetchCIDRList is package-private so we call it directly.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("192.0.2.0/24\n198.51.100.0/24\n# comment\n\n203.0.113.0/24\n"))
	}))
	defer srv.Close()

	cidrs, err := fetchCIDRList(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("fetchCIDRList: %v", err)
	}
	if len(cidrs) != 3 {
		t.Errorf("got %d CIDRs, want 3 (comments + blank lines skipped)", len(cidrs))
	}
	if cidrs[0] != "192.0.2.0/24" {
		t.Errorf("got %q, want 192.0.2.0/24", cidrs[0])
	}
}

func TestFetchCIDRListHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	_, err := fetchCIDRList(srv.Client(), srv.URL)
	if err == nil {
		t.Fatal("HTTP 503 should error")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("err = %v, want 503 in message", err)
	}
}

func TestFetchCIDRListDialFailure(t *testing.T) {
	_, err := fetchCIDRList(http.DefaultClient, "http://127.0.0.1:1/nope")
	if err == nil {
		t.Fatal("unreachable should error")
	}
}
