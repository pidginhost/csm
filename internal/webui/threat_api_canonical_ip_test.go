package webui

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
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
