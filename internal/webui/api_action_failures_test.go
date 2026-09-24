package webui

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/store"
)

type failedReleaseBlocker struct {
	*fullBlocker
}

func (*failedReleaseBlocker) UnblockIP(string) error       { return errors.New("unblock failed") }
func (*failedReleaseBlocker) AllowIP(string, string) error { return errors.New("allow failed") }
func (*failedReleaseBlocker) TempAllowIP(string, string, time.Duration) error {
	return errors.New("temporary allow failed")
}
func (*failedReleaseBlocker) RemoveAllowIP(string) error { return errors.New("remove allow failed") }

func TestThreatReleaseReportsFirewallFailures(t *testing.T) {
	s := newTestServer(t, "tok")
	s.blocker = &failedReleaseBlocker{newFullBlocker()}
	for name, handler := range map[string]http.HandlerFunc{
		"clear":               s.apiThreatClearIP,
		"whitelist":           s.apiThreatWhitelistIP,
		"temporary whitelist": s.apiThreatTempWhitelistIP,
		"remove whitelist":    s.apiThreatUnwhitelistIP,
	} {
		t.Run(name, func(t *testing.T) {
			w := postJSON(handler, `{"ip":"203.0.113.9"}`)
			assertJSONError(t, name, w, http.StatusInternalServerError)
		})
	}
}

func TestThreatBulkReportsEveryInvalidAddress(t *testing.T) {
	s := newTestServer(t, "tok")
	s.blocker = newFullBlocker()
	w := postJSON(s.apiThreatBulkAction, `{"ips":["203.0.113.9","not-an-address"],"action":"block"}`)
	var body struct {
		OK       bool     `json:"ok"`
		Count    int      `json:"count"`
		Warnings []string `json:"warnings"`
	}
	if json.Unmarshal(w.Body.Bytes(), &body) != nil || w.Code != http.StatusOK || !body.OK || body.Count != 1 || len(body.Warnings) != 1 {
		t.Fatalf("partial batch lost a failure: %d %s", w.Code, w.Body.String())
	}
}

type partialReleaseBlocker struct{ *fullBlocker }

func (b *partialReleaseBlocker) AllowIP(ip, reason string) error {
	if ip == "203.0.113.9" {
		return errors.New("allow failed")
	}
	return b.fullBlocker.AllowIP(ip, reason)
}

func TestThreatBulkWhitelistUndoIncludesOnlyCompletedAddresses(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	t.Cleanup(checks.SetGlobalThreatDBForTest(t.TempDir()))
	s.blocker = &partialReleaseBlocker{newFullBlocker()}
	for _, ip := range []string{"203.0.113.9", "203.0.113.10"} {
		checks.GetThreatDB().AddPermanent(ip, "operator block")
	}
	req := bearerRequest(http.MethodPost, "/api/v1/threat/bulk-action", []byte(`{"ips":["203.0.113.9","203.0.113.10"],"action":"whitelist"}`))
	w := httptest.NewRecorder()
	s.apiThreatBulkAction(w, req)
	var body struct {
		Count    int      `json:"count"`
		Warnings []string `json:"warnings"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != http.StatusOK || body.Count != 1 || len(body.Warnings) != 1 {
		t.Fatalf("partial batch: %d %s", w.Code, w.Body.String())
	}
	entry, ok, err := store.Global().LatestUndoEntry(s.operatorKey(req))
	if err != nil || !ok {
		t.Fatalf("undo missing: %v", err)
	}
	var payload undoPayloadIPs
	if err := decodeUndoPayload(entry.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.IPs) != 1 || payload.IPs[0] != "203.0.113.10" || len(payload.RestoreThreats) != 1 || payload.RestoreThreats[0].IP != "203.0.113.10" {
		t.Fatalf("undo affects failed addresses: %+v", payload)
	}
}

func TestBulkFixRejectsEmptyBatch(t *testing.T) {
	s := newTestServer(t, "tok")
	assertJSONError(t, "empty batch", postJSON(s.apiBulkFix, `[]`), http.StatusBadRequest)
}

func TestActionAndTimelineDurationsUseSeconds(t *testing.T) {
	s := newTestServer(t, "tok")
	s.blocker = newFullBlocker()
	w := postJSON(s.apiThreatTempWhitelistIP, `{"ip":"203.0.113.9","hours":2}`)
	var body map[string]any
	if json.Unmarshal(w.Body.Bytes(), &body) != nil || body["duration_seconds"] != float64(7200) || body["hours"] != nil {
		t.Errorf("temporary whitelist duration: %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	s.apiIncident(w, httptest.NewRequest(http.MethodGet, "/api/v1/incident?ip=203.0.113.9&hours=2", nil))
	body = nil
	if json.Unmarshal(w.Body.Bytes(), &body) != nil || body["window_seconds"] != float64(7200) || body["hours"] != nil {
		t.Errorf("incident window duration: %s", w.Body.String())
	}
}
