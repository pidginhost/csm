package webui

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

// ttlBlocker captures the TTL each operator block was issued with, so a test
// can prove the threat evidence lives exactly as long as the firewall block
// that produced it, and that operator blocks take the dry-run-bypass path.
type ttlBlocker struct {
	blocked     map[string]time.Duration
	forced      map[string]time.Duration
	statePath   string
	entries     map[string]firewall.BlockedEntry
	failBlock   bool
	failUnblock bool
}

func newTTLBlocker() *ttlBlocker {
	return &ttlBlocker{
		blocked: make(map[string]time.Duration),
		forced:  make(map[string]time.Duration),
		entries: make(map[string]firewall.BlockedEntry),
	}
}

func (rb *ttlBlocker) BlockIP(ip, _ string, timeout time.Duration) error {
	rb.blocked[ip] = timeout
	return nil
}

func (rb *ttlBlocker) BlockIPForce(ip, reason string, timeout time.Duration) error {
	if rb.failBlock {
		return errors.New("block failed")
	}
	entry := firewall.BlockedEntry{IP: ip, Reason: reason, BlockedAt: time.Now()}
	if timeout > 0 {
		entry.ExpiresAt = entry.BlockedAt.Add(timeout)
	}
	rb.entries[ip] = entry
	rb.blocked[ip] = timeout
	rb.forced[ip] = timeout
	return rb.save()
}

func (rb *ttlBlocker) UnblockIP(ip string) error {
	if parsed := net.ParseIP(ip); parsed != nil {
		ip = parsed.String()
	}
	if rb.failUnblock {
		return errors.New("unblock failed")
	}
	delete(rb.blocked, ip)
	delete(rb.entries, ip)
	return rb.save()
}

func (rb *ttlBlocker) save() error {
	if rb.statePath == "" {
		return nil
	}
	state := firewall.FirewallState{}
	for _, entry := range rb.entries {
		state.Blocked = append(state.Blocked, entry)
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	dir := filepath.Join(rb.statePath, "firewall")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "state.json"), raw, 0600)
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
	rb.statePath = s.cfg.StatePath
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
	s, rb := threatTestServer(t)
	if err := rb.BlockIPForce("192.0.2.89", manualBlockReason, manualBlockTTL); err != nil {
		t.Fatal(err)
	}
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

func TestTimedBlockRefusesPermanentFirewallDowngrade(t *testing.T) {
	for _, bulk := range []bool{false, true} {
		t.Run(fmt.Sprint(bulk), func(t *testing.T) {
			s, rb := threatTestServer(t)
			const ip = "192.0.2.100"
			// A CLI-created block has no local threat evidence.
			if err := rb.BlockIPForce(ip, "operator deny", 0); err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			if bulk {
				s.apiThreatBulkAction(rec, bearerRequest("POST", "/api/v1/threat/bulk-action", []byte(`{"ips":["192.0.2.100"],"action":"block"}`)))
				var resp struct {
					Count    int
					Warnings []string
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatal(err)
				}
				if resp.Count != 0 || len(resp.Warnings) != 1 {
					t.Fatalf("downgrade accepted: %s", rec.Body.String())
				}
			} else {
				s.apiThreatBlockIP(rec, bearerRequest("POST", "/api/v1/threat/block-ip", []byte(`{"ip":"192.0.2.100"}`)))
				if rec.Code != http.StatusConflict {
					t.Fatalf("downgrade status=%d body=%s", rec.Code, rec.Body.String())
				}
			}
			if rb.blocked[ip] != 0 {
				t.Fatal("permanent firewall block shortened")
			}
			if _, ok := store.Global().GetPermanentBlock(ip); ok {
				t.Fatal("refused block wrote evidence")
			}
		})
	}
}

func TestBulkBlockDuplicateUndoDoesNotResurrectEvidence(t *testing.T) {
	s, rb := threatTestServer(t)
	resp := postThreatJSON(t, s.apiThreatBulkAction, "/api/v1/threat/bulk-action", map[string]interface{}{
		"ips": []string{"192.0.2.101", "::ffff:192.0.2.101"}, "action": "block_permanent",
	})
	runUndo(t, s, resp["undo_token"].(string))
	if len(rb.blocked) != 0 {
		t.Fatal("undo left a firewall block")
	}
	if entry, ok := store.Global().GetPermanentBlock("192.0.2.101"); ok {
		t.Fatalf("duplicate restored its own evidence: %+v", entry)
	}
	if resp["count"] != float64(1) {
		t.Fatalf("count=%v, want one canonical IP", resp["count"])
	}
}

func TestBulkBlockUndoKeepsPriorFirewallLifetime(t *testing.T) {
	for _, ttl := range []time.Duration{0, 2 * time.Hour} {
		t.Run(ttl.String(), func(t *testing.T) {
			s, rb := threatTestServer(t)
			const ip = "192.0.2.102"
			if err := rb.BlockIPForce(ip, "prior block", ttl); err != nil {
				t.Fatal(err)
			}
			prior := rb.entries[ip]
			resp := postThreatJSON(t, s.apiThreatBulkAction, "/api/v1/threat/bulk-action", map[string]interface{}{"ips": []string{ip}, "action": "block_permanent"})
			runUndo(t, s, resp["undo_token"].(string))
			got, ok := rb.entries[ip]
			if !ok || got.Reason != prior.Reason || got.ExpiresAt.IsZero() != prior.ExpiresAt.IsZero() || got.ExpiresAt.Sub(prior.ExpiresAt).Abs() > time.Second {
				t.Fatalf("undo changed prior lifetime: got=%+v present=%v prior=%+v", got, ok, prior)
			}
		})
	}
}

func TestBulkUnblockUndoKeepsFirewallLifetime(t *testing.T) {
	for _, ttl := range []time.Duration{0, 2 * time.Hour} {
		t.Run(ttl.String(), func(t *testing.T) {
			s, rb := threatTestServer(t)
			const ip = "192.0.2.103"
			if err := rb.BlockIPForce(ip, "prior block", ttl); err != nil {
				t.Fatal(err)
			}
			prior := rb.entries[ip]
			resp := postThreatJSON(t, s.apiUnblockBulk, "/api/v1/unblock-bulk", map[string]interface{}{"ips": []string{ip}})
			runUndo(t, s, resp["undo_token"].(string))
			got, ok := rb.entries[ip]
			if !ok || got.Reason != prior.Reason || got.ExpiresAt.IsZero() != prior.ExpiresAt.IsZero() || got.ExpiresAt.Sub(prior.ExpiresAt).Abs() > time.Second {
				t.Fatalf("undo changed prior lifetime: got=%+v present=%v prior=%+v", got, ok, prior)
			}
		})
	}
}

func TestBlockUndoCannotResurrectDismissedOrDowngradedEvidence(t *testing.T) {
	for _, downgrade := range []bool{false, true} {
		t.Run(fmt.Sprint(downgrade), func(t *testing.T) {
			s, rb := threatTestServer(t)
			const ip = "192.0.2.104"
			checks.GetThreatDB().AddPermanent(ip, "prior permanent evidence")
			resp := postThreatJSON(t, s.apiThreatBulkAction, "/api/v1/threat/bulk-action", map[string]interface{}{"ips": []string{ip}, "action": "block_permanent"})
			postThreatJSON(t, s.apiThreatClearIP, "/api/v1/threat/clear-ip", map[string]interface{}{"ip": ip})
			if downgrade {
				postThreatJSON(t, s.apiThreatBlockIP, "/api/v1/threat/block-ip", map[string]interface{}{"ip": ip})
			}
			rec := httptest.NewRecorder()
			raw, _ := json.Marshal(undoRunRequest{ID: resp["undo_token"].(string)})
			s.apiUndoRun(rec, bearerRequest("POST", "/api/v1/undo/run", raw))
			if rec.Code != http.StatusGone {
				t.Fatalf("stale undo accepted: status=%d body=%s", rec.Code, rec.Body.String())
			}
			entry, found := store.Global().GetPermanentBlock(ip)
			if downgrade {
				if !found || entry.ExpiresAt.IsZero() || rb.blocked[ip] != manualBlockTTL {
					t.Fatalf("downgrade replaced: %+v", entry)
				}
			} else if found {
				t.Fatalf("dismissed evidence restored: %+v", entry)
			}
		})
	}
}

func TestUndoBlockFailureKeepsCurrentEvidence(t *testing.T) {
	s, rb := threatTestServer(t)
	resp := postThreatJSON(t, s.apiThreatBulkAction, "/api/v1/threat/bulk-action", map[string]interface{}{"ips": []string{"192.0.2.105"}, "action": "block_permanent"})
	before, _ := store.Global().GetPermanentBlock("192.0.2.105")
	rb.failUnblock = true
	rec := httptest.NewRecorder()
	raw, _ := json.Marshal(undoRunRequest{ID: resp["undo_token"].(string)})
	s.apiUndoRun(rec, bearerRequest("POST", "/api/v1/undo/run", raw))
	var result undoRunResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &result)
	if result.Count != 0 {
		t.Fatalf("failed unblock counted: %s", rec.Body.String())
	}
	after, ok := store.Global().GetPermanentBlock("192.0.2.105")
	if !ok || !after.BlockedAt.Equal(before.BlockedAt) {
		t.Fatalf("failed unblock changed evidence: %+v", after)
	}
}

func TestPermanentBlockRouteRequiresAdminAndCSRF(t *testing.T) {
	s, rb := threatTestServer(t)
	s.cfg.WebUI.Tokens = []config.WebUIToken{{Name: "admin", Token: "tok", Scope: "admin"}, {Name: "reader", Token: "read-tok", Scope: "read"}}
	cookie := loginBrowser(t, s, "tok", nil)
	for _, tc := range []struct {
		name, bearer  string
		browser, csrf bool
		want          int
	}{
		{name: "anonymous", want: http.StatusUnauthorized},
		{name: "read token", bearer: "read-tok", want: http.StatusUnauthorized},
		{name: "session without CSRF", browser: true, want: http.StatusForbidden},
		{name: "admin bearer", bearer: "tok", want: http.StatusOK},
		{name: "session with CSRF", browser: true, csrf: true, want: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := bearerRequest("POST", "/api/v1/threat/block-ip-permanent", []byte(`{"ip":"192.0.2.122"}`))
			req.Header.Del("Authorization")
			if tc.bearer != "" {
				req.Header.Set("Authorization", "Bearer "+tc.bearer)
			}
			if tc.browser {
				req.AddCookie(cookie)
			}
			if tc.csrf {
				req.Header.Set("X-CSRF-Token", s.csrfToken())
			}
			rec := httptest.NewRecorder()
			s.httpSrv.Handler.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, tc.want, rec.Body.String())
			}
			if tc.want != http.StatusOK && len(rb.blocked) != 0 {
				t.Fatal("unauthorized request blocked an IP")
			}
		})
	}
}

func TestTimedBlockRejectsInjectedPermanence(t *testing.T) {
	s, rb := threatTestServer(t)
	for _, tc := range []struct {
		path, body string
		handler    func(http.ResponseWriter, *http.Request)
	}{
		{"/api/v1/threat/block-ip", `{"ip":"192.0.2.123","permanent":true,"ttl":0,"action":"block_permanent"}`, s.apiThreatBlockIP},
		{"/api/v1/threat/bulk-action", `{"ips":["192.0.2.124"],"action":"block","permanent":true,"ttl":0}`, s.apiThreatBulkAction},
	} {
		rec := httptest.NewRecorder()
		tc.handler(rec, bearerRequest("POST", tc.path, []byte(tc.body)))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("injected lifetime accepted: %s", rec.Body.String())
		}
	}
	if len(rb.forced) != 0 || len(store.Global().AllPermanentBlocks()) != 0 {
		t.Fatal("injected request caused a block")
	}
}

func TestFailedUnblockUndoDoesNotRestoreThreatEvidence(t *testing.T) {
	s, rb := threatTestServer(t)
	const ip = "192.0.2.125"
	postThreatJSON(t, s.apiThreatBlockIP, "/api/v1/threat/block-ip", map[string]interface{}{"ip": ip})
	resp := postThreatJSON(t, s.apiUnblockBulk, "/api/v1/unblock-bulk", map[string]interface{}{"ips": []string{ip}})
	rb.failBlock = true
	runUndo(t, s, resp["undo_token"].(string))
	if _, ok := store.Global().GetPermanentBlock(ip); ok {
		t.Fatal("failed reblock restored threat evidence")
	}
	if _, ok := checks.GetThreatDB().Lookup(ip); ok {
		t.Fatal("failed reblock left in-memory evidence")
	}
}

func TestUnblockUndoDoesNotExtendExpiredBlock(t *testing.T) {
	s, rb := threatTestServer(t)
	const ip = "192.0.2.126"
	payload := undoPayloadIPs{
		IPs: []string{ip}, BlockSnapshot: true,
		RestoreBlocks:  map[string]firewall.BlockedEntry{ip: {IP: ip, Reason: manualBlockReason, ExpiresAt: time.Now().Add(-time.Second)}},
		RestoreThreats: []undoThreatRow{{IP: ip, Source: store.ThreatSourceOperator, Reason: manualBlockReason, ExpiresAt: time.Now().Add(-time.Second)}},
	}
	raw, err := encodeUndoPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.runUndoEntry(nil, store.UndoEntry{Inverse: undoInverseFirewallUnblock, Payload: raw})
	if err != nil {
		t.Fatal(err)
	}
	if result.Count != 0 || len(rb.blocked) != 0 {
		t.Fatal("undo revived an expired block")
	}
	if _, ok := store.Global().GetPermanentBlock(ip); ok {
		t.Fatal("undo revived expired evidence")
	}
}

func TestTimedBlockDoesNotOutliveShortenedFirewallBlock(t *testing.T) {
	s, rb := threatTestServer(t)
	const ip = "192.0.2.129"
	if err := rb.BlockIPForce(ip, "longer timed block", 72*time.Hour); err != nil {
		t.Fatal(err)
	}
	checks.GetThreatDB().AddOperatorTemporary(ip, "longer timed block", 72*time.Hour)
	rec := httptest.NewRecorder()
	s.apiThreatBlockIP(rec, bearerRequest("POST", "/api/v1/threat/block-ip", []byte(`{"ip":"192.0.2.129"}`)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("shortened firewall while preserving longer evidence: %s", rec.Body.String())
	}
	if rb.blocked[ip] != 72*time.Hour {
		t.Fatal("longer firewall block shortened")
	}
}

func TestSingleUnblockClearsMappedOperatorEvidence(t *testing.T) {
	s, rb := threatTestServer(t)
	const ip = "192.0.2.130"
	postThreatJSON(t, s.apiThreatBlockIP, "/api/v1/threat/block-ip", map[string]interface{}{"ip": ip})
	postThreatJSON(t, s.apiUnblockIP, "/api/v1/unblock-ip", map[string]interface{}{"ip": "::ffff:192.0.2.130"})
	if len(rb.blocked) != 0 {
		t.Fatal("mapped unblock left the canonical firewall block")
	}
	if _, ok := store.Global().GetPermanentBlock(ip); ok {
		t.Fatal("mapped unblock left timed operator evidence")
	}
	if _, ok := checks.GetThreatDB().Lookup(ip); ok {
		t.Fatal("mapped unblock left in-memory operator evidence")
	}
}
