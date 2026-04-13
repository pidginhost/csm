package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/emailav"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

// =========================================================================
// fullBlocker implements IPBlocker + AllowIP/TempAllowIP/RemoveAllowIP
// + BlockSubnet/UnblockSubnet/FlushBlocked for firewall_api.go coverage.
// =========================================================================

type fullBlocker struct {
	blocked        map[string]string
	allowed        map[string]string
	subnetsBlocked map[string]string
	flushed        bool
}

func newFullBlocker() *fullBlocker {
	return &fullBlocker{
		blocked:        make(map[string]string),
		allowed:        make(map[string]string),
		subnetsBlocked: make(map[string]string),
	}
}

func (fb *fullBlocker) BlockIP(ip, reason string, _ time.Duration) error {
	fb.blocked[ip] = reason
	return nil
}

func (fb *fullBlocker) UnblockIP(ip string) error {
	delete(fb.blocked, ip)
	return nil
}

func (fb *fullBlocker) AllowIP(ip, reason string) error {
	fb.allowed[ip] = reason
	return nil
}

func (fb *fullBlocker) TempAllowIP(ip, reason string, _ time.Duration) error {
	fb.allowed[ip] = reason
	return nil
}

func (fb *fullBlocker) RemoveAllowIP(ip string) error {
	delete(fb.allowed, ip)
	return nil
}

func (fb *fullBlocker) BlockSubnet(cidr, reason string, _ time.Duration) error {
	fb.subnetsBlocked[cidr] = reason
	return nil
}

func (fb *fullBlocker) UnblockSubnet(cidr string) error {
	delete(fb.subnetsBlocked, cidr)
	return nil
}

func (fb *fullBlocker) FlushBlocked() error {
	fb.flushed = true
	fb.blocked = make(map[string]string)
	return nil
}

// =========================================================================
// hardening_api.go tests
// =========================================================================

func TestAPIHardeningWithBbolt(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	w := httptest.NewRecorder()
	s.apiHardening(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	// Verify it returns valid JSON (even if empty report)
	var data json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestAPIHardeningRunMethodNotAllowed(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiHardeningRun(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET hardening run = %d, want 405", w.Code)
	}
}

func TestAPIHardeningRunConflictWhileScanning(t *testing.T) {
	s := newTestServer(t, "tok")
	// Acquire the scan lock to simulate an ongoing scan
	if !s.acquireScan() {
		t.Fatal("failed to acquire scan lock")
	}
	defer s.releaseScan()

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", nil)
	s.apiHardeningRun(w, req)
	if w.Code != http.StatusConflict {
		t.Errorf("concurrent scan = %d, want 409", w.Code)
	}
	if !strings.Contains(w.Body.String(), "already in progress") {
		t.Error("expected 'already in progress' message")
	}
}

// =========================================================================
// email_api.go tests
// =========================================================================

func TestAPIEmailStatsFieldsPresent(t *testing.T) {
	s := newTestServer(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{
		SMTPBlock:      true,
		SMTPAllowUsers: []string{"root"},
		SMTPPorts:      []int{25, 587},
		PortFlood: []firewall.PortFloodRule{
			{Port: 25, Proto: "tcp", Hits: 10, Seconds: 60},
			{Port: 80, Proto: "tcp", Hits: 100, Seconds: 60}, // non-SMTP, should be excluded
		},
	}
	w := httptest.NewRecorder()
	s.apiEmailStats(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	var resp emailStatsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if !resp.SMTPBlock {
		t.Error("expected smtp_block=true")
	}
	if len(resp.SMTPAllowUsers) != 1 || resp.SMTPAllowUsers[0] != "root" {
		t.Errorf("smtp_allow_users = %v, want [root]", resp.SMTPAllowUsers)
	}
	if len(resp.SMTPPorts) != 2 {
		t.Errorf("smtp_ports count = %d, want 2", len(resp.SMTPPorts))
	}
	// Only port 25 flood rule should appear (port 80 is not SMTP)
	if len(resp.PortFlood) != 1 || resp.PortFlood[0].Port != 25 {
		t.Errorf("port_flood = %+v, want 1 entry for port 25", resp.PortFlood)
	}
}

func TestAPIEmailStatsNilSlicesInitialized(t *testing.T) {
	s := newTestServer(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{}
	w := httptest.NewRecorder()
	s.apiEmailStats(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	var resp emailStatsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	// Verify nil slices are returned as empty arrays in JSON
	if resp.SMTPAllowUsers == nil {
		t.Error("smtp_allow_users should not be nil")
	}
	if resp.SMTPPorts == nil {
		t.Error("smtp_ports should not be nil")
	}
	if resp.PortFlood == nil {
		t.Error("port_flood should not be nil")
	}
}

func TestAPIEmailQuarantineListMethodNotAllowedPost(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiEmailQuarantineList(w, httptest.NewRequest("POST", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST quarantine list = %d, want 405", w.Code)
	}
}

func TestAPIEmailQuarantineListWithQuarantine(t *testing.T) {
	s := newTestServer(t, "tok")
	dir := t.TempDir()
	s.emailQuarantine = emailav.NewQuarantine(dir)

	w := httptest.NewRecorder()
	s.apiEmailQuarantineList(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	// Should return empty array since quarantine dir has no messages
	if w.Body.String() != "[]" && !strings.HasPrefix(w.Body.String(), "[") {
		t.Errorf("expected JSON array, got: %s", w.Body.String())
	}
}

func TestAPIEmailQuarantineActionMissingMsgID(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/email/quarantine/", nil)
	s.apiEmailQuarantineAction(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("empty msg ID = %d, want 400", w.Code)
	}
}

func TestAPIEmailQuarantineActionDotID(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/email/quarantine/.", nil)
	s.apiEmailQuarantineAction(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("dot msg ID = %d, want 400", w.Code)
	}
}

func TestAPIEmailQuarantineActionNotConfiguredAllMethods(t *testing.T) {
	s := newTestServer(t, "tok")
	s.emailQuarantine = nil

	for _, method := range []string{"GET", "POST", "DELETE"} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/api/v1/email/quarantine/testmsg", nil)
		s.apiEmailQuarantineAction(w, req)
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("%s no quarantine = %d, want 503", method, w.Code)
		}
	}
}

func TestAPIEmailQuarantineActionGetNotFound(t *testing.T) {
	s := newTestServer(t, "tok")
	dir := t.TempDir()
	s.emailQuarantine = emailav.NewQuarantine(dir)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/email/quarantine/nonexistent", nil)
	s.apiEmailQuarantineAction(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("GET missing msg = %d, want 404", w.Code)
	}
}

func TestAPIEmailQuarantineActionPostBadAction(t *testing.T) {
	s := newTestServer(t, "tok")
	dir := t.TempDir()
	s.emailQuarantine = emailav.NewQuarantine(dir)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/email/quarantine/testmsg/badaction", nil)
	s.apiEmailQuarantineAction(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad action = %d, want 400", w.Code)
	}
}

func TestAPIEmailQuarantineActionPostReleaseNotFound(t *testing.T) {
	s := newTestServer(t, "tok")
	dir := t.TempDir()
	s.emailQuarantine = emailav.NewQuarantine(dir)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/email/quarantine/nonexistent/release", nil)
	s.apiEmailQuarantineAction(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("release missing = %d, want 500", w.Code)
	}
}

func TestAPIEmailQuarantineActionDeleteSuccess(t *testing.T) {
	s := newTestServer(t, "tok")
	dir := t.TempDir()
	s.emailQuarantine = emailav.NewQuarantine(dir)
	// Create a fake quarantine directory to delete
	msgDir := filepath.Join(dir, "testmsg123")
	if err := os.MkdirAll(msgDir, 0755); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/api/v1/email/quarantine/testmsg123", nil)
	s.apiEmailQuarantineAction(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("delete = %d, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "deleted") {
		t.Error("expected 'deleted' in response")
	}
}

func TestAPIEmailQuarantineActionMethodNotAllowed(t *testing.T) {
	s := newTestServer(t, "tok")
	dir := t.TempDir()
	s.emailQuarantine = emailav.NewQuarantine(dir)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/v1/email/quarantine/testmsg", nil)
	s.apiEmailQuarantineAction(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT = %d, want 405", w.Code)
	}
}

func TestAPIEmailAVStatusNotAllowedPost(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiEmailAVStatus(w, httptest.NewRequest("POST", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST AV status = %d, want 405", w.Code)
	}
}

func TestAPIEmailAVStatusFieldsPresent(t *testing.T) {
	s := newTestServer(t, "tok")
	s.emailAVWatcherMode = "fanotify"
	dir := t.TempDir()
	s.emailQuarantine = emailav.NewQuarantine(dir)

	w := httptest.NewRecorder()
	s.apiEmailAVStatus(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	var resp emailAVStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if resp.WatcherMode != "fanotify" {
		t.Errorf("watcher_mode = %q, want fanotify", resp.WatcherMode)
	}
	if resp.ClamdSocket == "" {
		t.Error("clamd_socket should not be empty")
	}
}

func TestAPIEmailAVStatusDisabledWatcherMode(t *testing.T) {
	s := newTestServer(t, "tok")
	// Leave emailAVWatcherMode empty
	w := httptest.NewRecorder()
	s.apiEmailAVStatus(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	var resp emailAVStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if resp.WatcherMode != "disabled" {
		t.Errorf("watcher_mode = %q, want disabled", resp.WatcherMode)
	}
}

// =========================================================================
// firewall_api.go deeper coverage
// =========================================================================

func TestAPIFirewallAllowIPSuccess(t *testing.T) {
	s := newTestServer(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{Enabled: true}
	fb := newFullBlocker()
	s.blocker = fb

	w := httptest.NewRecorder()
	body := `{"ip":"203.0.113.5","reason":"testing"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallAllowIP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "allowed") {
		t.Error("expected 'allowed' in response")
	}
	if fb.allowed["203.0.113.5"] != "testing" {
		t.Error("IP not in allowed map")
	}
}

func TestAPIFirewallAllowIPTempDuration(t *testing.T) {
	s := newTestServer(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{Enabled: true}
	fb := newFullBlocker()
	s.blocker = fb

	w := httptest.NewRecorder()
	body := `{"ip":"203.0.113.10","reason":"temp","duration":"24h"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallAllowIP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "temp_allowed") {
		t.Error("expected 'temp_allowed' in response")
	}
}

func TestAPIFirewallAllowIPInvalidIP(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	body := `{"ip":"not-an-ip"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallAllowIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid IP = %d, want 400", w.Code)
	}
}

func TestAPIFirewallAllowIPNoBlocker(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	s.blocker = nil
	w := httptest.NewRecorder()
	body := `{"ip":"203.0.113.5","reason":"test"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallAllowIP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("no blocker = %d, want 503", w.Code)
	}
}

func TestAPIFirewallAllowIPDefaultReason(t *testing.T) {
	s := newTestServer(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{Enabled: true}
	fb := newFullBlocker()
	s.blocker = fb

	w := httptest.NewRecorder()
	body := `{"ip":"203.0.113.7"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallAllowIP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if fb.allowed["203.0.113.7"] != "Allowed via CSM Web UI" {
		t.Errorf("default reason = %q", fb.allowed["203.0.113.7"])
	}
}

func TestAPIFirewallRemoveAllowMissingIP(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	body := `{}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallRemoveAllow(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing IP = %d, want 400", w.Code)
	}
}

func TestAPIFirewallRemoveAllowInvalidIP(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	body := `{"ip":"not-valid"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallRemoveAllow(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid IP = %d, want 400", w.Code)
	}
}

func TestAPIFirewallRemoveAllowNoBlocker(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	s.blocker = nil
	w := httptest.NewRecorder()
	body := `{"ip":"203.0.113.5"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallRemoveAllow(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("no blocker = %d, want 503", w.Code)
	}
}

func TestAPIFirewallRemoveAllowSuccess(t *testing.T) {
	s := newTestServer(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{Enabled: true}
	fb := newFullBlocker()
	fb.allowed["203.0.113.5"] = "test"
	s.blocker = fb

	w := httptest.NewRecorder()
	body := `{"ip":"203.0.113.5"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallRemoveAllow(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "removed") {
		t.Error("expected 'removed' in response")
	}
}

func TestAPIFirewallAuditWithSearchFilter(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	// Seed an audit log entry in the state path
	auditDir := filepath.Join(s.cfg.StatePath, "firewall")
	if err := os.MkdirAll(auditDir, 0755); err != nil {
		t.Fatal(err)
	}
	entry := `{"timestamp":"2026-04-13T10:00:00Z","action":"block","ip":"203.0.113.50","reason":"brute force","source":"daemon"}`
	if err := os.WriteFile(filepath.Join(auditDir, "audit.jsonl"), []byte(entry+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Test with search filter
	w := httptest.NewRecorder()
	s.apiFirewallAudit(w, httptest.NewRequest("GET", "/?limit=10&search=brute", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "brute force") {
		t.Error("expected search result to contain 'brute force'")
	}
}

func TestAPIFirewallAuditWithActionFilter(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	auditDir := filepath.Join(s.cfg.StatePath, "firewall")
	if err := os.MkdirAll(auditDir, 0755); err != nil {
		t.Fatal(err)
	}
	lines := `{"timestamp":"2026-04-13T10:00:00Z","action":"block","ip":"203.0.113.50","reason":"test"}
{"timestamp":"2026-04-13T10:01:00Z","action":"unblock","ip":"203.0.113.50","reason":"manual"}
`
	if err := os.WriteFile(filepath.Join(auditDir, "audit.jsonl"), []byte(lines), 0644); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.apiFirewallAudit(w, httptest.NewRequest("GET", "/?limit=10&action=block", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var result []json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if len(result) != 1 {
		t.Errorf("filtered count = %d, want 1", len(result))
	}
}

func TestAPIFirewallAuditWithSourceFilter(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	auditDir := filepath.Join(s.cfg.StatePath, "firewall")
	if err := os.MkdirAll(auditDir, 0755); err != nil {
		t.Fatal(err)
	}
	entry := `{"timestamp":"2026-04-13T10:00:00Z","action":"block","ip":"203.0.113.50","reason":"test","source":"daemon"}`
	if err := os.WriteFile(filepath.Join(auditDir, "audit.jsonl"), []byte(entry+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.apiFirewallAudit(w, httptest.NewRequest("GET", "/?limit=10&source=daemon", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "daemon") {
		t.Error("expected source=daemon in result")
	}
}

func TestAPIFirewallSubnetsWithData(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	// Seed firewall state with blocked subnets
	stateDir := filepath.Join(s.cfg.StatePath, "firewall")
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		t.Fatal(err)
	}
	state := firewall.FirewallState{
		BlockedNet: []firewall.SubnetEntry{
			{CIDR: "198.51.100.0/24", Reason: "abuse", BlockedAt: time.Now()},
		},
	}
	data, _ := json.Marshal(state)
	if err := os.WriteFile(filepath.Join(stateDir, "state.json"), data, 0644); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.apiFirewallSubnets(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "198.51.100.0/24") {
		t.Error("expected subnet in response")
	}
}

func TestAPIFirewallDenySubnetMissingCIDR(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	body := `{}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallDenySubnet(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing CIDR = %d, want 400", w.Code)
	}
}

func TestAPIFirewallDenySubnetInvalidCIDR(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	body := `{"cidr":"not-a-cidr"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallDenySubnet(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid CIDR = %d, want 400", w.Code)
	}
}

func TestAPIFirewallDenySubnetNoBlocker(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	s.blocker = nil
	w := httptest.NewRecorder()
	body := `{"cidr":"198.51.100.0/24","reason":"test"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallDenySubnet(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("no blocker = %d, want 503", w.Code)
	}
}

func TestAPIFirewallDenySubnetSuccess(t *testing.T) {
	s := newTestServer(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{Enabled: true}
	fb := newFullBlocker()
	s.blocker = fb

	w := httptest.NewRecorder()
	body := `{"cidr":"198.51.100.0/24","reason":"abuse"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallDenySubnet(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "blocked") {
		t.Error("expected 'blocked' in response")
	}
	if fb.subnetsBlocked["198.51.100.0/24"] != "abuse" {
		t.Error("subnet not in blocked map")
	}
}

func TestAPIFirewallDenySubnetDefaultReason(t *testing.T) {
	s := newTestServer(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{Enabled: true}
	fb := newFullBlocker()
	s.blocker = fb

	w := httptest.NewRecorder()
	body := `{"cidr":"198.51.100.0/24"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallDenySubnet(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if fb.subnetsBlocked["198.51.100.0/24"] != "Blocked via CSM Web UI" {
		t.Errorf("default reason = %q", fb.subnetsBlocked["198.51.100.0/24"])
	}
}

func TestAPIFirewallRemoveSubnetMissingCIDR(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	body := `{}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallRemoveSubnet(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing CIDR = %d, want 400", w.Code)
	}
}

func TestAPIFirewallRemoveSubnetInvalidCIDR(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	body := `{"cidr":"bad"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallRemoveSubnet(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid CIDR = %d, want 400", w.Code)
	}
}

func TestAPIFirewallRemoveSubnetNoBlocker(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	s.blocker = nil
	w := httptest.NewRecorder()
	body := `{"cidr":"198.51.100.0/24"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallRemoveSubnet(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("no blocker = %d, want 503", w.Code)
	}
}

func TestAPIFirewallRemoveSubnetSuccess(t *testing.T) {
	s := newTestServer(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{Enabled: true}
	fb := newFullBlocker()
	fb.subnetsBlocked["198.51.100.0/24"] = "test"
	s.blocker = fb

	w := httptest.NewRecorder()
	body := `{"cidr":"198.51.100.0/24"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallRemoveSubnet(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "removed") {
		t.Error("expected 'removed' in response")
	}
}

func TestAPIFirewallFlushNoBlocker(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	s.blocker = nil
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", nil)
	s.apiFirewallFlush(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("no blocker = %d, want 503", w.Code)
	}
}

func TestAPIFirewallFlushSuccess(t *testing.T) {
	s := newTestServer(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{Enabled: true}
	fb := newFullBlocker()
	fb.blocked["203.0.113.5"] = "test"
	s.blocker = fb

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", nil)
	s.apiFirewallFlush(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if !fb.flushed {
		t.Error("flush was not called")
	}
}

func TestAPIFirewallFlushCphulkGetRejected(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	s.apiFirewallFlushCphulk(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET flush cphulk = %d, want 405", w.Code)
	}
}

func TestAPIFirewallFlushCphulkMissingIP(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	body := `{}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallFlushCphulk(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing IP = %d, want 400", w.Code)
	}
}

func TestAPIFirewallFlushCphulkInvalidIP(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	body := `{"ip":"not-valid"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallFlushCphulk(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid IP = %d, want 400", w.Code)
	}
}

func TestAPIFirewallFlushCphulkSuccess(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	body := `{"ip":"203.0.113.5"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallFlushCphulk(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "flushed") {
		t.Error("expected 'flushed' in response")
	}
}

func TestAPIFirewallCheckInvalidIP(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	s.apiFirewallCheck(w, httptest.NewRequest("GET", "/?ip=not-an-ip", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"success": false`) {
		t.Error("expected success=false for invalid IP")
	}
}

func TestAPIFirewallCheckWithBlockedState(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	// Seed firewall state with a blocked IP
	stateDir := filepath.Join(s.cfg.StatePath, "firewall")
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		t.Fatal(err)
	}
	fwState := firewall.FirewallState{
		Blocked: []firewall.BlockedEntry{
			{IP: "203.0.113.50", Reason: "brute force", ExpiresAt: time.Time{}},
		},
	}
	data, _ := json.Marshal(fwState)
	if err := os.WriteFile(filepath.Join(stateDir, "state.json"), data, 0644); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.apiFirewallCheck(w, httptest.NewRequest("GET", "/?ip=203.0.113.50", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "brute force") {
		t.Error("expected permanent block reason in response")
	}
}

func TestAPIFirewallCheckWithTempBlock(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	stateDir := filepath.Join(s.cfg.StatePath, "firewall")
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		t.Fatal(err)
	}
	fwState := firewall.FirewallState{
		Blocked: []firewall.BlockedEntry{
			{IP: "203.0.113.51", Reason: "temp block", ExpiresAt: time.Now().Add(1 * time.Hour)},
		},
	}
	data, _ := json.Marshal(fwState)
	if err := os.WriteFile(filepath.Join(stateDir, "state.json"), data, 0644); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.apiFirewallCheck(w, httptest.NewRequest("GET", "/?ip=203.0.113.51", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "temp block") {
		t.Error("expected temporary block reason in response")
	}
}

func TestAPIFirewallCheckWithSubnetBlock(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	stateDir := filepath.Join(s.cfg.StatePath, "firewall")
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		t.Fatal(err)
	}
	fwState := firewall.FirewallState{
		BlockedNet: []firewall.SubnetEntry{
			{CIDR: "203.0.113.0/24", Reason: "subnet abuse"},
		},
	}
	data, _ := json.Marshal(fwState)
	if err := os.WriteFile(filepath.Join(stateDir, "state.json"), data, 0644); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.apiFirewallCheck(w, httptest.NewRequest("GET", "/?ip=203.0.113.99", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "subnet abuse") {
		t.Error("expected subnet block reason in response")
	}
}

func TestAPIFirewallUnbanMissingIP(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	body := `{}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallUnban(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"success": false`) {
		t.Error("expected success=false for missing IP")
	}
}

func TestAPIFirewallUnbanInvalidIP(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	w := httptest.NewRecorder()
	body := `{"ip":"not-valid"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallUnban(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"success": false`) {
		t.Error("expected success=false for invalid IP")
	}
}

func TestAPIFirewallUnbanSuccess(t *testing.T) {
	s := newTestServer(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{Enabled: true}
	fb := newFullBlocker()
	fb.blocked["203.0.113.5"] = "test"
	s.blocker = fb

	w := httptest.NewRecorder()
	body := `{"ip":"203.0.113.5"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallUnban(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"success": true`) {
		t.Error("expected success=true")
	}
}

func TestAPIFirewallUnbanRemovesSubnet(t *testing.T) {
	s := newTestServer(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{Enabled: true}
	fb := newFullBlocker()
	s.blocker = fb

	// Seed state with a subnet that covers the IP
	stateDir := filepath.Join(s.cfg.StatePath, "firewall")
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		t.Fatal(err)
	}
	fwState := firewall.FirewallState{
		BlockedNet: []firewall.SubnetEntry{
			{CIDR: "203.0.113.0/24", Reason: "abuse"},
		},
	}
	data, _ := json.Marshal(fwState)
	if err := os.WriteFile(filepath.Join(stateDir, "state.json"), data, 0644); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	body := `{"ip":"203.0.113.5"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallUnban(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "subnet_removed") {
		t.Error("expected subnet_removed in response")
	}
}

func TestAPIFirewallAllowedWithStateData(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	stateDir := filepath.Join(s.cfg.StatePath, "firewall")
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		t.Fatal(err)
	}
	fwState := firewall.FirewallState{
		Allowed: []firewall.AllowedEntry{
			{IP: "203.0.113.1", Reason: "test-perm", Source: "csm"},
			{IP: "203.0.113.2", Reason: "test-temp", ExpiresAt: time.Now().Add(1 * time.Hour)},
			{IP: "203.0.113.3", Reason: "test-expired", ExpiresAt: time.Now().Add(-1 * time.Hour)},
		},
		PortAllowed: []firewall.PortAllowEntry{
			{IP: "203.0.113.4", Port: 8080, Proto: "tcp", Reason: "custom port"},
		},
	}
	data, _ := json.Marshal(fwState)
	if err := os.WriteFile(filepath.Join(stateDir, "state.json"), data, 0644); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.apiFirewallAllowed(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	var resp struct {
		Allowed     []firewallAllowView     `json:"allowed"`
		PortAllowed []firewallPortAllowView `json:"port_allowed"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	// Expired entry should be filtered out
	if len(resp.Allowed) != 2 {
		t.Errorf("allowed count = %d, want 2 (expired should be filtered)", len(resp.Allowed))
	}
	if len(resp.PortAllowed) != 1 {
		t.Errorf("port_allowed count = %d, want 1", len(resp.PortAllowed))
	}
}

func TestAPIFirewallStatusWithBlockedCounts(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	stateDir := filepath.Join(s.cfg.StatePath, "firewall")
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		t.Fatal(err)
	}
	fwState := firewall.FirewallState{
		Blocked: []firewall.BlockedEntry{
			{IP: "203.0.113.1", Reason: "perm", ExpiresAt: time.Time{}},
			{IP: "203.0.113.2", Reason: "temp", ExpiresAt: time.Now().Add(1 * time.Hour)},
		},
		Allowed: []firewall.AllowedEntry{
			{IP: "203.0.113.10", Reason: "perm"},
			{IP: "203.0.113.11", Reason: "temp", ExpiresAt: time.Now().Add(2 * time.Hour)},
		},
	}
	data, _ := json.Marshal(fwState)
	if err := os.WriteFile(filepath.Join(stateDir, "state.json"), data, 0644); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.apiFirewallStatus(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if resp["blocked_permanent"].(float64) != 1 {
		t.Errorf("blocked_permanent = %v, want 1", resp["blocked_permanent"])
	}
	if resp["blocked_temporary"].(float64) != 1 {
		t.Errorf("blocked_temporary = %v, want 1", resp["blocked_temporary"])
	}
	if resp["allow_permanent"].(float64) != 1 {
		t.Errorf("allow_permanent = %v, want 1", resp["allow_permanent"])
	}
	if resp["allow_temporary"].(float64) != 1 {
		t.Errorf("allow_temporary = %v, want 1", resp["allow_temporary"])
	}
}

// =========================================================================
// suppressions_api.go tests
// =========================================================================

func TestAPISuppressionsPostMissingCheck(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	body := `{"path_pattern":"*.php","reason":"test"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiSuppressions(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing check = %d, want 400", w.Code)
	}
}

func TestAPISuppressionsPostBadJSON(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{bad`))
	req.Header.Set("Content-Type", "application/json")
	s.apiSuppressions(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad JSON = %d, want 400", w.Code)
	}
}

func TestAPISuppressionsDeleteMissingID(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	body := `{}`
	req := httptest.NewRequest("DELETE", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiSuppressions(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing ID = %d, want 400", w.Code)
	}
}

func TestAPISuppressionsDeleteBadJSON(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/", strings.NewReader(`{bad`))
	req.Header.Set("Content-Type", "application/json")
	s.apiSuppressions(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad JSON delete = %d, want 400", w.Code)
	}
}

func TestAPISuppressionsMethodNotAllowed(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiSuppressions(w, httptest.NewRequest("PUT", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT = %d, want 405", w.Code)
	}
}

func TestAPISuppressionsAddAndDelete(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")

	// Add a suppression rule
	w := httptest.NewRecorder()
	body := `{"check":"webshell","path_pattern":"/tmp/*.php","reason":"testing"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiSuppressions(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("add status = %d, body = %s", w.Code, w.Body.String())
	}

	var addResp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &addResp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	ruleID := addResp["id"]
	if ruleID == "" {
		t.Fatal("expected non-empty rule ID")
	}

	// List should contain the rule
	w2 := httptest.NewRecorder()
	s.apiSuppressions(w2, httptest.NewRequest("GET", "/", nil))
	if w2.Code != http.StatusOK {
		t.Fatalf("list status = %d", w2.Code)
	}
	if !strings.Contains(w2.Body.String(), ruleID) {
		t.Error("rule ID not found in list")
	}

	// Delete the rule
	w3 := httptest.NewRecorder()
	delBody := `{"id":"` + ruleID + `"}`
	delReq := httptest.NewRequest("DELETE", "/", strings.NewReader(delBody))
	delReq.Header.Set("Content-Type", "application/json")
	s.apiSuppressions(w3, delReq)
	if w3.Code != http.StatusOK {
		t.Fatalf("delete status = %d, body = %s", w3.Code, w3.Body.String())
	}
	if !strings.Contains(w3.Body.String(), "deleted") {
		t.Error("expected 'deleted' in response")
	}
}

// =========================================================================
// modsec_api.go tests
// =========================================================================

func TestAPIModSecBlocksWithFindings(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	sdb := store.Global()

	// Seed modsec findings via bbolt AppendHistory for modsecFindings24h
	findings := []alert.Finding{
		{
			Check:     "modsec_block",
			Severity:  alert.Warning,
			Message:   "ModSecurity block from 203.0.113.50 on example.com",
			Details:   "Rule: 900001\nMessage: Blocked CGI\nHostname: example.com\nURI: /cgi-bin/test",
			Timestamp: time.Now(),
		},
		{
			Check:     "modsec_block",
			Severity:  alert.Warning,
			Message:   "ModSecurity block from 203.0.113.50 on example.com",
			Details:   "Rule: 900002\nMessage: Blocked dir\nHostname: example.com\nURI: /uploads/",
			Timestamp: time.Now(),
		},
		{
			Check:     "modsec_csm_block_escalation",
			Severity:  alert.Critical,
			Message:   "Escalated block from 203.0.113.50",
			Details:   "[client 203.0.113.50]",
			Timestamp: time.Now(),
		},
	}
	if err := sdb.AppendHistory(findings); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.apiModSecBlocks(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	// Should return valid JSON array
	var result []modsecBlockView
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
}

func TestAPIModSecEventsWithLimit(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	sdb := store.Global()

	findings := []alert.Finding{
		{
			Check:     "modsec_block",
			Severity:  alert.Warning,
			Message:   "ModSecurity block from 203.0.113.50 on example.com",
			Details:   "Rule: 900001\nMessage: Blocked\nHostname: example.com\nURI: /test1",
			Timestamp: time.Now().Add(-5 * time.Minute),
		},
		{
			Check:     "modsec_block",
			Severity:  alert.Warning,
			Message:   "ModSecurity block from 203.0.113.51 on test.com",
			Details:   "Rule: 900002\nMessage: Blocked\nHostname: test.com\nURI: /test2",
			Timestamp: time.Now(),
		},
	}
	if err := sdb.AppendHistory(findings); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.apiModSecEvents(w, httptest.NewRequest("GET", "/?limit=1", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	var result []modsecEventView
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if len(result) > 1 {
		t.Errorf("events count = %d, want <= 1", len(result))
	}
}

func TestAPIModSecEventsInvalidLimit(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	// limit=0 is invalid, should use default 100
	s.apiModSecEvents(w, httptest.NewRequest("GET", "/?limit=0", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

func TestAPIModSecEventsLimitAboveMax(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	// limit=999 is above 500, should use default 100
	s.apiModSecEvents(w, httptest.NewRequest("GET", "/?limit=999", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

func TestAPIModSecRulesApplyNotConfigured(t *testing.T) {
	s := newTestServer(t, "tok")
	// ModSec config fields are empty
	w := httptest.NewRecorder()
	body := `{"disabled":[]}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiModSecRulesApply(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("not configured = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "not configured") {
		t.Error("expected 'not configured' message")
	}
}

func TestAPIModSecRulesApplyBadJSON(t *testing.T) {
	s := newTestServer(t, "tok")
	s.cfg.ModSec.RulesFile = "/tmp/nonexistent"
	s.cfg.ModSec.OverridesFile = "/tmp/nonexistent"
	s.cfg.ModSec.ReloadCommand = "true"

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{bad`))
	req.Header.Set("Content-Type", "application/json")
	s.apiModSecRulesApply(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad JSON = %d, want 400", w.Code)
	}
}

func TestAPIModSecEscalationPostWithBbolt(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")

	// Add a no-escalate rule
	w := httptest.NewRecorder()
	body := `{"rule_id":900001,"escalate":false}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiModSecRulesEscalation(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("add no-escalate = %d, body = %s", w.Code, w.Body.String())
	}

	// Remove the no-escalate rule (re-enable escalation)
	w2 := httptest.NewRecorder()
	body2 := `{"rule_id":900001,"escalate":true}`
	req2 := httptest.NewRequest("POST", "/", strings.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	s.apiModSecRulesEscalation(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("remove no-escalate = %d, body = %s", w2.Code, w2.Body.String())
	}
}

func TestAPIModSecEscalationPostNoStore(t *testing.T) {
	s := newTestServer(t, "tok")
	// No bbolt store set globally
	store.SetGlobal(nil)

	w := httptest.NewRecorder()
	body := `{"rule_id":900001,"escalate":false}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiModSecRulesEscalation(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("no store = %d, want 500", w.Code)
	}
}

func TestAPIModSecEscalationPostBadJSON(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{bad`))
	req.Header.Set("Content-Type", "application/json")
	s.apiModSecRulesEscalation(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad JSON = %d, want 400", w.Code)
	}
}

func TestAPIModSecEscalationPostInvalidRuleID(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	w := httptest.NewRecorder()
	body := `{"rule_id":123,"escalate":true}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiModSecRulesEscalation(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid rule ID = %d, want 400", w.Code)
	}
}

func TestAPIModSecEscalationPostRuleIDTooHigh(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	w := httptest.NewRecorder()
	body := `{"rule_id":901000,"escalate":true}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiModSecRulesEscalation(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("rule ID too high = %d, want 400", w.Code)
	}
}

// =========================================================================
// deduplicateModSecFindings coverage
// =========================================================================

func TestDeduplicateModSecFindingsMergesDuplicates(t *testing.T) {
	ts := time.Date(2026, 4, 13, 10, 30, 0, 0, time.UTC)
	findings := []alert.Finding{
		{
			Check:     "modsec_block",
			Message:   "ModSecurity block from 203.0.113.50 on example.com",
			Details:   `[id "900001"]`,
			Timestamp: ts,
		},
		{
			Check:     "modsec_block",
			Message:   "ModSecurity block from 203.0.113.50 on example.com",
			Details:   `[id "900001"] [hostname "example.com"] [uri "/test"]`,
			Timestamp: ts,
		},
	}

	result := deduplicateModSecFindings(findings)
	if len(result) != 1 {
		t.Errorf("dedup count = %d, want 1", len(result))
	}
}

// =========================================================================
// looksLikeIP edge cases
// =========================================================================

func TestLooksLikeIPShortString(t *testing.T) {
	if looksLikeIP("1.2") {
		t.Error("short string should not look like IP")
	}
}

func TestLooksLikeIPWithLetters(t *testing.T) {
	if looksLikeIP("example.com") {
		t.Error("domain should not look like IP")
	}
}

func TestLooksLikeIPValid(t *testing.T) {
	if !looksLikeIP("203.0.113.50") {
		t.Error("valid IP should look like IP")
	}
}
