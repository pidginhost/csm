package webui

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
)

// coveringBlocker is a test blocker whose blocked_nets still cover the IP.
type coveringBlocker struct {
	*fullBlocker
	cidr string
}

func (c *coveringBlocker) BlockedSubnetCovering(string) (string, bool) { return c.cidr, true }

// Whitelisting an IP unblocked it and added an allow rule, but a blocked
// subnet covering that IP keeps dropping it (the chain drops @blocked_nets
// before it accepts @allowed_ips). The response reported plain success and
// the customer stayed offline with no hint why. The handler now names the
// covering subnet.
func TestWhitelistWarnsAboutCoveringBlockedSubnet(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	restore := checks.SetGlobalThreatDBForTest(t.TempDir())
	t.Cleanup(restore)
	s.blocker = &coveringBlocker{fullBlocker: newFullBlocker(), cidr: "203.0.113.0/24"}

	req := httptest.NewRequest("POST", "/api/v1/threat/whitelist", strings.NewReader(`{"ip":"203.0.113.7"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.apiThreatWhitelistIP(w, req)

	var resp struct {
		Status  string `json:"status"`
		Warning string `json:"warning"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v: %s", err, w.Body.String())
	}
	if !strings.Contains(resp.Warning, "203.0.113.0/24") {
		t.Fatalf("response does not name the covering blocked subnet: %s", w.Body.String())
	}
}
