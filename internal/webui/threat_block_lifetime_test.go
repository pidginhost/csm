package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/store"
)

// ttlBlocker captures the TTL each operator block was issued with, so a test
// can prove the threat evidence lives exactly as long as the firewall block
// that produced it, and that operator blocks take the dry-run-bypass path.
type ttlBlocker struct {
	blocked map[string]time.Duration
	forced  map[string]time.Duration
}

func newTTLBlocker() *ttlBlocker {
	return &ttlBlocker{
		blocked: make(map[string]time.Duration),
		forced:  make(map[string]time.Duration),
	}
}

func (rb *ttlBlocker) BlockIP(ip, _ string, timeout time.Duration) error {
	rb.blocked[ip] = timeout
	return nil
}

func (rb *ttlBlocker) BlockIPForce(ip, _ string, timeout time.Duration) error {
	rb.blocked[ip] = timeout
	rb.forced[ip] = timeout
	return nil
}

func (rb *ttlBlocker) UnblockIP(ip string) error {
	delete(rb.blocked, ip)
	return nil
}

func postThreatJSON(t *testing.T, handler func(http.ResponseWriter, *http.Request), path string, body map[string]interface{}) map[string]interface{} {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	rec := httptest.NewRecorder()
	handler(rec, bearerRequest("POST", path, raw))
	if rec.Code != http.StatusOK {
		t.Fatalf("%s status = %d; body=%s", path, rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode %s response: %v; body=%s", path, err, rec.Body.String())
	}
	return resp
}

func threatTestServer(t *testing.T) (*Server, *ttlBlocker) {
	t.Helper()
	s := newTestServerWithBbolt(t, "tok")
	t.Cleanup(checks.SetGlobalThreatDBForTest(t.TempDir()))
	rb := newTTLBlocker()
	s.blocker = rb
	return s, rb
}

// A 24h manual block must leave no live threat evidence once the firewall
// block lapses. The permanent row it used to write kept the address at
// score 100 forever and re-blocked every later sighting.
func TestManualBlockRecordsEvidenceThatExpiresWithTheBlock(t *testing.T) {
	s, rb := threatTestServer(t)

	postThreatJSON(t, s.apiThreatBlockIP, "/api/v1/threat/block-ip", map[string]interface{}{"ip": "192.0.2.80"})

	if ttl, ok := rb.forced["192.0.2.80"]; !ok || ttl != 24*time.Hour {
		t.Fatalf("firewall block ttl = %v (forced=%v), want 24h", ttl, ok)
	}
	entry, found := store.Global().GetPermanentBlock("192.0.2.80")
	if !found {
		t.Fatal("manual block recorded no threat evidence")
	}
	if entry.Source != store.ThreatSourceOperator {
		t.Fatalf("source = %q, want operator", entry.Source)
	}
	if entry.ExpiresAt.IsZero() {
		t.Fatal("manual 24h block wrote never-expiring threat evidence")
	}
	if entry.Expired(time.Now().Add(23 * time.Hour)) {
		t.Fatal("evidence lapsed before the firewall block")
	}
	if !entry.Expired(time.Now().Add(25 * time.Hour)) {
		t.Fatal("evidence outlived the firewall block")
	}
	if _, ok := checks.GetThreatDB().Lookup("192.0.2.80"); !ok {
		t.Fatal("blocked IP not flagged while the block is live")
	}
}

func TestManualBlockDoesNotDowngradeExistingPermanentEvidence(t *testing.T) {
	s, _ := threatTestServer(t)
	checks.GetThreatDB().AddPermanent("192.0.2.81", "Permanently blocked via CSM Web UI")

	postThreatJSON(t, s.apiThreatBlockIP, "/api/v1/threat/block-ip", map[string]interface{}{"ip": "192.0.2.81"})

	entry, found := store.Global().GetPermanentBlock("192.0.2.81")
	if !found || !entry.ExpiresAt.IsZero() {
		t.Fatalf("permanent evidence downgraded by a 24h block: found=%v entry=%+v", found, entry)
	}
}

func TestPermanentBlockWritesPermanentEvidenceAndBlock(t *testing.T) {
	s, rb := threatTestServer(t)

	postThreatJSON(t, s.apiThreatBlockIPPermanent, "/api/v1/threat/block-ip-permanent", map[string]interface{}{"ip": "192.0.2.82"})

	ttl, ok := rb.forced["192.0.2.82"]
	if !ok {
		t.Fatal("permanent block did not reach the firewall through the operator path")
	}
	if ttl != 0 {
		t.Fatalf("firewall block ttl = %v, want 0 (permanent)", ttl)
	}
	entry, found := store.Global().GetPermanentBlock("192.0.2.82")
	if !found || entry.Source != store.ThreatSourceOperator || !entry.ExpiresAt.IsZero() {
		t.Fatalf("permanent block evidence wrong: found=%v entry=%+v", found, entry)
	}
	if entry.Expired(time.Now().Add(365 * 24 * time.Hour)) {
		t.Fatal("permanent evidence lapses")
	}
}

func TestPermanentBlockRejectsNonPOSTAndBadIP(t *testing.T) {
	s, _ := threatTestServer(t)

	rec := httptest.NewRecorder()
	s.apiThreatBlockIPPermanent(rec, httptest.NewRequest("GET", "/api/v1/threat/block-ip-permanent", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET = %d, want 405", rec.Code)
	}

	rec = httptest.NewRecorder()
	s.apiThreatBlockIPPermanent(rec, bearerRequest("POST", "/api/v1/threat/block-ip-permanent", []byte(`{"ip":"127.0.0.1"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("loopback = %d, want 400", rec.Code)
	}

	s.blocker = nil
	rec = httptest.NewRecorder()
	s.apiThreatBlockIPPermanent(rec, bearerRequest("POST", "/api/v1/threat/block-ip-permanent", []byte(`{"ip":"192.0.2.83"}`)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no firewall engine = %d, want 503", rec.Code)
	}
}

func TestBulkBlockLifetimesMatchTheirFirewallBlocks(t *testing.T) {
	s, rb := threatTestServer(t)

	postThreatJSON(t, s.apiThreatBulkAction, "/api/v1/threat/bulk-action",
		map[string]interface{}{"ips": []string{"192.0.2.84"}, "action": "block"})
	postThreatJSON(t, s.apiThreatBulkAction, "/api/v1/threat/bulk-action",
		map[string]interface{}{"ips": []string{"192.0.2.85"}, "action": "block_permanent"})

	if ttl := rb.forced["192.0.2.84"]; ttl != 24*time.Hour {
		t.Fatalf("bulk 24h firewall ttl = %v, want 24h", ttl)
	}
	if ttl, ok := rb.forced["192.0.2.85"]; !ok || ttl != 0 {
		t.Fatalf("bulk permanent firewall ttl = %v (present=%v), want 0", ttl, ok)
	}
	timed, found := store.Global().GetPermanentBlock("192.0.2.84")
	if !found || timed.ExpiresAt.IsZero() || timed.Source != store.ThreatSourceOperator {
		t.Fatalf("bulk 24h evidence wrong: found=%v entry=%+v", found, timed)
	}
	permanent, found := store.Global().GetPermanentBlock("192.0.2.85")
	if !found || !permanent.ExpiresAt.IsZero() || permanent.Source != store.ThreatSourceOperator {
		t.Fatalf("bulk permanent evidence wrong: found=%v entry=%+v", found, permanent)
	}
}

// Undo of a bulk block must unblock the IPs, drop the evidence the block
// added, and put back whatever evidence was on file before it.
func TestUndoBulkBlockRestoresPriorEvidence(t *testing.T) {
	s, rb := threatTestServer(t)
	tdb := checks.GetThreatDB()
	tdb.AddPermanent("192.0.2.86", "Permanently blocked via CSM Web UI")
	tdb.AddTemporary("192.0.2.87", "web_attack", time.Hour)

	resp := postThreatJSON(t, s.apiThreatBulkAction, "/api/v1/threat/bulk-action",
		map[string]interface{}{"ips": []string{"192.0.2.86", "192.0.2.87", "192.0.2.88"}, "action": "block"})
	token, _ := resp["undo_token"].(string)
	if token == "" {
		t.Fatal("bulk block returned no undo token")
	}
	runUndo(t, s, token)

	if len(rb.blocked) != 0 {
		t.Fatalf("undo left firewall blocks in place: %v", rb.blocked)
	}
	if _, found := store.Global().GetPermanentBlock("192.0.2.88"); found {
		t.Fatal("undo left the evidence the block created")
	}
	restoredPermanent, found := store.Global().GetPermanentBlock("192.0.2.86")
	if !found || !restoredPermanent.ExpiresAt.IsZero() || restoredPermanent.Source != store.ThreatSourceOperator {
		t.Fatalf("pre-existing permanent evidence not restored: found=%v entry=%+v", found, restoredPermanent)
	}
	restoredTemp, found := store.Global().GetPermanentBlock("192.0.2.87")
	if !found || restoredTemp.Source != store.ThreatSourceAutoBlock || restoredTemp.ExpiresAt.IsZero() {
		t.Fatalf("pre-existing auto-block evidence not restored: found=%v entry=%+v", found, restoredTemp)
	}
}

// A bulk firewall unblock captures the evidence it drops; the undo must put
// a timed operator row back as a timed operator row, not as an auto-block
// row and not as a permanent one.
func TestUndoBulkUnblockRestoresTimedOperatorEvidence(t *testing.T) {
	s, _ := threatTestServer(t)
	checks.GetThreatDB().AddOperatorTemporary("192.0.2.89", "Manually blocked via CSM Web UI", 24*time.Hour)

	resp := postThreatJSON(t, s.apiUnblockBulk, "/api/v1/unblock-bulk",
		map[string]interface{}{"ips": []string{"192.0.2.89"}})
	token, _ := resp["undo_token"].(string)
	if token == "" {
		t.Fatal("bulk unblock returned no undo token")
	}
	if _, found := store.Global().GetPermanentBlock("192.0.2.89"); found {
		t.Fatal("firewall unblock left the timed operator evidence behind")
	}

	runUndo(t, s, token)

	entry, found := store.Global().GetPermanentBlock("192.0.2.89")
	if !found {
		t.Fatal("undo did not restore the timed operator evidence")
	}
	if entry.Source != store.ThreatSourceOperator || entry.ExpiresAt.IsZero() {
		t.Fatalf("timed operator evidence not restored faithfully: %+v", entry)
	}
}

// Unblock & clear removes both kinds of operator evidence.
func TestClearIPRemovesTimedAndPermanentEvidence(t *testing.T) {
	s, _ := threatTestServer(t)
	tdb := checks.GetThreatDB()
	tdb.AddOperatorTemporary("192.0.2.90", "Manually blocked via CSM Web UI", 24*time.Hour)
	tdb.AddPermanent("192.0.2.91", "Permanently blocked via CSM Web UI")

	for _, ip := range []string{"192.0.2.90", "192.0.2.91"} {
		postThreatJSON(t, s.apiThreatClearIP, "/api/v1/threat/clear-ip", map[string]interface{}{"ip": ip})
		if _, found := store.Global().GetPermanentBlock(ip); found {
			t.Fatalf("clear left threat evidence for %s", ip)
		}
		if _, ok := tdb.Lookup(ip); ok {
			t.Fatalf("clear left %s flagged in the threat DB", ip)
		}
	}
}

// The audit trail has to separate a 24h block from a permanent one, or an
// operator reviewing a lockout cannot tell which action caused it.
func TestOperatorBlockAuditDistinguishesLifetime(t *testing.T) {
	s, _ := threatTestServer(t)

	postThreatJSON(t, s.apiThreatBlockIP, "/api/v1/threat/block-ip", map[string]interface{}{"ip": "192.0.2.92"})
	postThreatJSON(t, s.apiThreatBlockIPPermanent, "/api/v1/threat/block-ip-permanent", map[string]interface{}{"ip": "192.0.2.93"})

	entries := readUIAuditLog(s.cfg.StatePath, 200)
	byTarget := map[string]UIAuditEntry{}
	for _, e := range entries {
		byTarget[e.Target] = e
	}
	timed, ok := byTarget["192.0.2.92"]
	if !ok || timed.Action != "block_ip" || timed.Details != "manual block 24h" {
		t.Fatalf("24h block audit entry = %+v", timed)
	}
	permanent, ok := byTarget["192.0.2.93"]
	if !ok || permanent.Action != "block_ip_permanent" || permanent.Details != "manual permanent block" {
		t.Fatalf("permanent block audit entry = %+v", permanent)
	}
}
