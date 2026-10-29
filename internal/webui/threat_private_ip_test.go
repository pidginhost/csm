package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/store"
)

// Historical imports preserve the original address spelling. Clearing an
// address must remove every equivalent record, including persisted aliases.
func TestClearPrivateIPRemovesImportedSpellings(t *testing.T) {
	for _, tc := range []struct{ canonical, alias string }{
		{"10.0.0.5", "::ffff:10.0.0.5"},
		{"fd00::5", "FD00:0:0:0:0:0:0:5"},
	} {
		t.Run(tc.canonical, func(t *testing.T) {
			s, _ := threatTestServer(t)
			fakeWhmapi1(t, 0)
			seedAttackDB(t, nil)
			adb := attackdb.Global()
			dir := filepath.Join(s.cfg.StatePath, "threat_db")
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			contents := tc.canonical + "\n" + tc.alias + "\n192.0.2.9\n"
			if err := os.WriteFile(filepath.Join(dir, "permanent.txt"), []byte(contents), 0600); err != nil {
				t.Fatal(err)
			}
			if got := adb.SeedFromPermanentBlocklist(s.cfg.StatePath); got != 3 {
				t.Fatalf("imported %d records, want 3", got)
			}
			if err := adb.Flush(); err != nil {
				t.Fatal(err)
			}
			if got := len(store.Global().LoadAllIPRecords()); got != 3 {
				t.Fatalf("persisted %d records before clear, want 3", got)
			}
			beforeEvents := make(map[string][]attackdb.Event)
			for _, ip := range []string{tc.canonical, tc.alias, "192.0.2.9"} {
				beforeEvents[ip] = adb.QueryEvents(ip, 10)
				if len(beforeEvents[ip]) != 1 || beforeEvents[ip][0].IP != ip {
					t.Fatalf("missing imported event for %s: %+v", ip, beforeEvents[ip])
				}
			}
			postThreatJSON(t, s.apiThreatClearIP, "/api/v1/threat/clear-ip", map[string]interface{}{"ip": tc.alias})
			if err := adb.Flush(); err != nil {
				t.Fatal(err)
			}
			persisted := store.Global().LoadAllIPRecords()
			for _, ip := range []string{tc.canonical, tc.alias} {
				if adb.LookupIP(ip) != nil {
					t.Errorf("clear retained attack record for %s", ip)
				}
				if _, ok := persisted[ip]; ok {
					t.Errorf("clear retained persisted attack record for %s", ip)
				}
			}
			if adb.TotalIPs() != 1 || adb.LookupIP("192.0.2.9") == nil {
				t.Fatalf("clear did not preserve exactly the unrelated record: %+v", adb.AllRecords())
			}
			if len(persisted) != 1 || persisted["192.0.2.9"] == nil {
				t.Fatalf("clear did not persist exactly the unrelated record: %+v", persisted)
			}
			for ip, before := range beforeEvents {
				if after := adb.QueryEvents(ip, 10); !slices.Equal(before, after) {
					t.Fatalf("clear changed event history for %s: before=%+v after=%+v", ip, before, after)
				}
			}
		})
	}
}

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
			s, blocker := threatTestServer(t)
			if err := blocker.BlockIPForce(ip, "historical block", time.Hour); err != nil {
				t.Fatal(err)
			}
			checks.GetThreatDB().AddPermanent(ip, "historical block")
			historyPath := filepath.Join(s.cfg.StatePath, "netblock_history.json")
			history := struct {
				IPs    map[string]time.Time `json:"ips"`
				Active map[string]bool      `json:"active"`
			}{
				IPs:    map[string]time.Time{ip: time.Now(), "192.0.2.9": time.Now()},
				Active: map[string]bool{ip: true, "192.0.2.9": true},
			}
			raw, err := json.Marshal(history)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(historyPath, raw, 0600); err != nil {
				t.Fatal(err)
			}

			resp := postThreatJSON(t, s.apiThreatClearIP, "/api/v1/threat/clear-ip", map[string]interface{}{"ip": ip})

			if _, blocked := blocker.blocked[ip]; blocked {
				t.Fatal("clear left the firewall block")
			}
			if _, found := checks.GetThreatDB().Lookup(ip); found {
				t.Fatal("clear left the threat record")
			}
			if _, found := store.Global().GetPermanentBlock(ip); found {
				t.Fatal("clear left the persisted threat record")
			}
			raw, err = os.ReadFile(historyPath)
			if err != nil {
				t.Fatal(err)
			}
			history.IPs, history.Active = nil, nil
			if err = json.Unmarshal(raw, &history); err != nil {
				t.Fatal(err)
			}
			if len(history.IPs) != 1 || history.IPs["192.0.2.9"].IsZero() || len(history.Active) != 1 || !history.Active["192.0.2.9"] {
				t.Fatalf("clear did not remove only the selected history: %+v", history)
			}
			if rec := attackdb.Global().LookupIP(ip); rec != nil {
				t.Fatalf("clear left the attack record for %s: %+v", ip, rec)
			}
			actions, _ := resp["actions"].([]interface{})
			wantActions := []string{"unblocked from firewall", "removed from threat DB", "removed from attack DB", "removed from subnet block history", "flushed cPanel login history"}
			if len(actions) != len(wantActions) {
				t.Fatalf("actions = %v, want %v", actions, wantActions)
			}
			for i, want := range wantActions {
				if actions[i] != want {
					t.Errorf("action %d = %v, want %s", i, actions[i], want)
				}
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

func TestBlockActionsRejectPrivateAddresses(t *testing.T) {
	s, blocker := threatTestServer(t)
	seedAttackDB(t, nil)
	for _, ip := range []string{"10.0.0.5", "::ffff:10.0.0.5", "fd00::5"} {
		for name, handler := range map[string]http.HandlerFunc{
			"temporary": s.apiThreatBlockIP,
			"permanent": s.apiThreatBlockIPPermanent,
			"firewall":  s.apiBlockIP,
		} {
			w := postJSON(handler, `{"ip":"`+ip+`"}`)
			if w.Code != http.StatusBadRequest {
				t.Errorf("%s block of %s = %d, want 400: %s", name, ip, w.Code, w.Body.String())
			}
		}
		for _, action := range []string{"block", "block_permanent"} {
			w := postJSON(s.apiThreatBulkAction, `{"ips":["`+ip+`"],"action":"`+action+`"}`)
			body := decodeBody(t, w)
			if w.Code != http.StatusUnprocessableEntity || body["count"] != float64(0) || body["undo_token"] != nil {
				t.Errorf("bulk %s of %s = %d: %s", action, ip, w.Code, w.Body.String())
			}
		}
	}
	if len(blocker.blocked) != 0 || len(blocker.forced) != 0 || len(store.Global().AllPermanentBlocks()) != 0 || attackdb.Global().TotalIPs() != 0 {
		t.Fatal("rejected private block changed firewall or threat state")
	}
}

func TestPrivateReleaseReportsOnlyCompletedSteps(t *testing.T) {
	for _, ip := range []string{"10.0.0.5", "fd00::5"} {
		for _, failure := range []string{"firewall", "history", "cphulk", "missing-cphulk"} {
			t.Run(ip+"/"+failure, func(t *testing.T) {
				s, blocker := threatTestServer(t)
				if err := blocker.BlockIPForce(ip, "historical block", time.Hour); err != nil {
					t.Fatal(err)
				}
				fakeWhmapi1(t, 0)
				wantErr := false
				omittedAction := ""
				switch failure {
				case "firewall":
					blocker.failUnblock = true
					wantErr = true
					omittedAction = "unblocked from firewall"
				case "history":
					if err := os.WriteFile(filepath.Join(s.cfg.StatePath, "netblock_history.json"), []byte("{"), 0600); err != nil {
						t.Fatal(err)
					}
					wantErr = true
					omittedAction = "removed from subnet block history"
				case "cphulk":
					fakeWhmapi1(t, 1)
					omittedAction = "flushed cPanel login history"
				case "missing-cphulk":
					t.Setenv("PATH", t.TempDir())
					omittedAction = "flushed cPanel login history"
				}
				actions, err := s.releaseIP(ip, ipRelease{})
				if (err != nil) != wantErr {
					t.Fatalf("release error = %v, want error = %v", err, wantErr)
				}
				if slices.Contains(actions, omittedAction) {
					t.Fatalf("release claimed failed action %q: %v", omittedAction, actions)
				}
				if _, blocked := blocker.blocked[ip]; blocked != blocker.failUnblock {
					t.Fatalf("firewall blocked = %v after release, failed = %v", blocked, blocker.failUnblock)
				}
			})
		}
	}
}
