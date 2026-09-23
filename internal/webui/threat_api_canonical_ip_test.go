package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
)

// The threat handlers validated the request address and then used the raw
// string as the key for the firewall, the threat DB and the attack DB. A
// pasted address with a trailing space, or an upper-case IPv6 spelling,
// validated fine and then whitelisted or cleared nothing while answering
// 200. Every downstream call receives the canonical form.
func TestThreatWhitelistUsesCanonicalIP(t *testing.T) {
	s := newTestServer(t, "tok")
	for raw, want := range map[string]string{
		`" 203.0.113.5 "`: "203.0.113.5",
		`"2001:DB8::1"`:   "2001:db8::1",
	} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":`+raw+`}`))
		req.Header.Set("Content-Type", "application/json")
		s.apiThreatWhitelistIP(w, req)
		if w.Code != 200 {
			t.Fatalf("status = %d body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			IP string `json:"ip"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.IP != want {
			t.Fatalf("whitelisted %q, want the canonical %q", resp.IP, want)
		}
	}
}

func TestThreatBulkWhitelistUsesCanonicalIP(t *testing.T) {
	t.Cleanup(checks.SetGlobalThreatDBForTest(t.TempDir()))
	s := newTestServer(t, "tok")
	blocker := newFullBlocker()
	s.blocker = blocker
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader("{\"ips\":[\" 2001:DB8::5 \"],\"action\":\"whitelist\"}"))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatBulkAction(w, req)
	if w.Code != 200 {
		t.Fatalf("status = %d body = %s", w.Code, w.Body.String())
	}
	if _, ok := blocker.allowed["2001:db8::5"]; !ok {
		t.Fatalf("bulk whitelist used raw keys: %+v", blocker.allowed)
	}
	var resp struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Count != 1 {
		t.Fatalf("count = %d, want 1", resp.Count)
	}
	entries := checks.GetThreatDB().WhitelistedIPs()
	if len(entries) != 1 || entries[0].IP != "2001:db8::5" {
		t.Fatalf("threat whitelist = %+v, want canonical IPv6", entries)
	}
}

// Whitelist, temporary whitelist and Unblock & Clear release an address the
// same way, so each reports the same trailing steps, cPHulk included.
func TestThreatReleaseActionsReportTheSameSteps(t *testing.T) {
	s := newTestServer(t, "tok")
	fakeWhmapi1(t, 0)
	for _, tc := range []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
		body    string
	}{
		{"whitelist", s.apiThreatWhitelistIP, `{"ip":"203.0.113.7"}`},
		{"temp whitelist", s.apiThreatTempWhitelistIP, `{"ip":"203.0.113.8","hours":2}`},
		{"clear", s.apiThreatClearIP, `{"ip":"203.0.113.9"}`},
	} {
		name := tc.name
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/", strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		tc.handler(w, req)
		if w.Code != 200 {
			t.Fatalf("%s: status = %d body = %s", name, w.Code, w.Body.String())
		}
		var resp struct {
			Actions []string `json:"actions"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		n := len(resp.Actions)
		if n < 2 || resp.Actions[n-2] != "removed from subnet block history" || resp.Actions[n-1] != "flushed cPanel login history" {
			t.Errorf("%s: actions = %q", name, resp.Actions)
		}
	}
}
