package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// An address typed in another spelling ("2001:DB8::10") is the same address.
// Handlers pass the canonical form on, so audit entries, incident and threat
// bookkeeping and the response agree with the firewall state.
func TestFirewallHandlersUseTheCanonicalAddress(t *testing.T) {
	fakeWhmapi1(t, 0)
	for _, tc := range []struct{ typed, canonical string }{
		{"2001:DB8:0::10", "2001:db8::10"},
		{" ::ffff:192.0.2.10 ", "192.0.2.10"},
	} {
		t.Run(tc.typed, func(t *testing.T) { testFirewallCanonicalAddress(t, tc.typed, tc.canonical) })
	}
}

func testFirewallCanonicalAddress(t *testing.T, typed, canonical string) {
	t.Helper()
	cases := []struct {
		action string
		call   func(*Server, http.ResponseWriter, *http.Request)
		body   map[string]any
	}{
		{"block_ip", (*Server).apiBlockIP, map[string]any{"ip": typed, "reason": "test"}},
		{"firewall_allow", (*Server).apiFirewallAllowIP, map[string]any{"ip": typed, "reason": "test"}},
		{"firewall_remove_allow", (*Server).apiFirewallRemoveAllow, map[string]any{"ip": typed}},
		{"cphulk_clear", (*Server).apiFirewallFlushCphulk, map[string]any{"ip": typed}},
		{"firewall_unban", (*Server).apiFirewallUnban, map[string]any{"ip": typed}},
	}
	for _, tc := range cases {
		t.Run(tc.action, func(t *testing.T) {
			s := newTestServerWithFirewall(t, "tok")
			fb := newFullBlocker()
			s.SetIPBlocker(fb)
			body, _ := json.Marshal(tc.body)
			w := httptest.NewRecorder()
			tc.call(s, w, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
			if w.Code != http.StatusOK {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			var resp map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			if resp["ip"] != canonical {
				t.Errorf("response ip = %v, want %s", resp["ip"], canonical)
			}
			entries := readUIAuditLog(s.cfg.StatePath, 10)
			if len(entries) == 0 || entries[len(entries)-1].Action != tc.action || entries[len(entries)-1].Target != canonical {
				t.Errorf("audit = %+v, want %s on %s", entries, tc.action, canonical)
			}
			for ip := range fb.blocked {
				if ip != canonical {
					t.Errorf("blocker got %q, want %s", ip, canonical)
				}
			}
			for ip := range fb.allowed {
				if ip != canonical {
					t.Errorf("allower got %q, want %s", ip, canonical)
				}
			}
		})
	}
}

func TestFirewallRejectsScopedAddresses(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	fb := newFullBlocker()
	s.SetIPBlocker(fb)
	for _, call := range []func(*Server, http.ResponseWriter, *http.Request){
		(*Server).apiBlockIP, (*Server).apiFirewallAllowIP, (*Server).apiFirewallRemoveAllow, (*Server).apiFirewallFlushCphulk,
	} {
		w := httptest.NewRecorder()
		call(s, w, httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"ip":"2001:db8::10%eth0"}`)))
		if w.Code != http.StatusBadRequest {
			t.Errorf("status %d, want 400", w.Code)
		}
	}
	if len(fb.blocked) != 0 || len(fb.allowed) != 0 {
		t.Fatal("scoped address changed firewall state")
	}
}
