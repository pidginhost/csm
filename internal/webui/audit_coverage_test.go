package webui

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
)

// Several write endpoints changed firewall or detection state without
// leaving a UI audit entry, so an operator's unban, un-whitelist or rules
// reload was invisible in the audit trail. Every state-changing endpoint
// records what it did.
func TestWriteEndpointsLeaveAuditEntries(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	restore := checks.SetGlobalThreatDBForTest(t.TempDir())
	t.Cleanup(restore)
	s.blocker = newFullBlocker()

	unban := httptest.NewRequest("POST", "/api/v1/firewall/unban", strings.NewReader(`{"ip":"203.0.113.77"}`))
	unban.Header.Set("Content-Type", "application/json")
	s.apiFirewallUnban(httptest.NewRecorder(), unban)

	checks.GetThreatDB().AddWhitelist("203.0.113.78")
	unwl := httptest.NewRequest("POST", "/api/v1/threat/unwhitelist", strings.NewReader(`{"ip":"203.0.113.78"}`))
	unwl.Header.Set("Content-Type", "application/json")
	s.apiThreatUnwhitelistIP(httptest.NewRecorder(), unwl)

	s.apiRulesReload(httptest.NewRecorder(), httptest.NewRequest("POST", "/api/v1/rules/reload", nil))

	entries := readUIAuditLog(s.cfg.StatePath, 50)
	seen := map[string]bool{}
	for _, e := range entries {
		seen[e.Action] = true
	}
	for _, action := range []string{"firewall_unban", "unwhitelist_ip", "rules_reload"} {
		if !seen[action] {
			t.Errorf("no audit entry for %s; entries=%+v", action, entries)
		}
	}
}
