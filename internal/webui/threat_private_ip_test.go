package webui

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/attackdb"
)

// An internal address missing from infra_ips gets recorded like any other
// source. Unblock & Clear is the only web UI action that removes that record,
// so it has to accept private addresses.
func TestClearIPAcceptsPrivateAddress(t *testing.T) {
	binDir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "whmapi1.args")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$CSM_TEST_MARKER\"\n"
	if err := os.WriteFile(filepath.Join(binDir, "whmapi1"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("CSM_TEST_MARKER", marker)

	for _, ip := range []string{"10.0.0.5", "fd00::5"} {
		t.Run(ip, func(t *testing.T) {
			seedAttackDB(t, map[string]*attackdb.IPRecord{
				ip: {IP: ip, ThreatScore: 55, EventCount: 3},
			})
			s, _ := threatTestServer(t)

			resp := postThreatJSON(t, s.apiThreatClearIP, "/api/v1/threat/clear-ip", map[string]interface{}{"ip": ip})

			if rec := attackdb.Global().LookupIP(ip); rec != nil {
				t.Fatalf("clear left the attack record for %s: %+v", ip, rec)
			}
			actions, _ := resp["actions"].([]interface{})
			found := false
			for _, a := range actions {
				if a == "removed from attack DB" {
					found = true
				}
			}
			if !found {
				t.Fatalf("actions = %v, want removed from attack DB", actions)
			}
			got, err := os.ReadFile(marker)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(got), "ip="+ip+"\n") {
				t.Fatalf("cPHulk flush skipped %s: whmapi1 args = %q", ip, string(got))
			}
		})
	}
}

// Clearing accepts private addresses only; the other non-routable classes
// are never recorded as attackers and stay rejected.
func TestClearIPRejectsNonPrivateSpecialAddresses(t *testing.T) {
	s := newTestServer(t, "tok")
	for _, ip := range []string{"169.254.1.1", "224.0.0.1", "0.0.0.0", "255.255.255.255"} {
		w := httptest.NewRecorder()
		s.apiThreatClearIP(w, httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"`+ip+`"}`)))
		if w.Code != http.StatusBadRequest {
			t.Errorf("clear %s = %d, want 400", ip, w.Code)
		}
	}
}

// An allow rule is the wrong tool for an internal address. The rejection
// names the setting that stops CSM from flagging it.
func TestAllowActionsPointPrivateAddressesAtInfraIPs(t *testing.T) {
	s := newTestServer(t, "tok")
	s.blocker = newFullBlocker()
	handlers := map[string]http.HandlerFunc{
		"whitelist":      s.apiThreatWhitelistIP,
		"temp-whitelist": s.apiThreatTempWhitelistIP,
		"firewall-allow": s.apiFirewallAllowIP,
	}
	for name, h := range handlers {
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"10.0.0.5"}`)))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s private = %d, want 400", name, w.Code)
		}
		if !strings.Contains(w.Body.String(), "infra_ips") {
			t.Errorf("%s error does not name infra_ips: %s", name, w.Body.String())
		}
	}
}

func TestBulkWhitelistPointsPrivateAddressesAtInfraIPs(t *testing.T) {
	s := newTestServer(t, "tok")
	s.blocker = newFullBlocker()
	w := httptest.NewRecorder()
	s.apiThreatBulkAction(w, httptest.NewRequest("POST", "/", strings.NewReader(`{"ips":["10.0.0.5"],"action":"whitelist"}`)))
	if !strings.Contains(w.Body.String(), "10.0.0.5") || !strings.Contains(w.Body.String(), "infra_ips") {
		t.Fatalf("bulk whitelist warning does not name infra_ips: %d %s", w.Code, w.Body.String())
	}
}
