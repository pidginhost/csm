package webui

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// The firewall check compared the queried address to state entries as raw
// strings, so an IPv6 block saved in one spelling ("2001:DB8::1") was
// reported as "not blocked" when queried in another ("2001:db8::1" or the
// expanded form). Addresses are compared as parsed IPs.
func TestFirewallCheckComparesIPv6Canonically(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	fwDir := filepath.Join(s.cfg.StatePath, "firewall")
	if err := os.MkdirAll(fwDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fwDir, "state.json"),
		[]byte(`{"blocked":[{"ip":"2001:DB8::1","reason":"spray"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, spelling := range []string{"2001:db8::1", "2001:0db8:0000:0000:0000:0000:0000:0001"} {
		w := httptest.NewRecorder()
		s.apiFirewallCheck(w, httptest.NewRequest("GET", "/?ip="+spelling, nil))
		body := decodeFirewallCheckBody(t, w)
		if body["permanent"] == nil {
			t.Fatalf("block saved as 2001:DB8::1 not found when queried as %s: %v", spelling, body)
		}
	}
}
