package webui

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/health"
)

type stubComponentsProvider struct {
	statuses map[string]bool
	changed  map[string]time.Time
}

func (s *stubComponentsProvider) WatcherStatuses() map[string]bool       { return s.statuses }
func (s *stubComponentsProvider) WatcherChangedAt() map[string]time.Time { return s.changed }

// All other health.Provider methods are unused by apiComponents; the
// handler casts to componentsProvider so we satisfy that surface only.
func (s *stubComponentsProvider) Hostname() string               { return "test" }
func (s *stubComponentsProvider) StartedAt() time.Time           { return time.Time{} }
func (s *stubComponentsProvider) LatestScan() time.Time          { return time.Time{} }
func (s *stubComponentsProvider) BaselineAt() time.Time          { return time.Time{} }
func (s *stubComponentsProvider) StoreHealthy() bool             { return true }
func (s *stubComponentsProvider) StoreSizeMB() float64           { return 0 }
func (s *stubComponentsProvider) SeverityCounts() map[string]int { return nil }
func (s *stubComponentsProvider) BlocklistSize() int             { return 0 }
func (s *stubComponentsProvider) IncidentsOpen() int             { return 0 }
func (s *stubComponentsProvider) BPFEnforcementActive() bool     { return false }
func (s *stubComponentsProvider) HistoryCount() int              { return 0 }
func (s *stubComponentsProvider) ConfigHash() string             { return "" }
func (s *stubComponentsProvider) BinaryHash() string             { return "" }
func (s *stubComponentsProvider) DryRunBlocksCount() int         { return 0 }
func (s *stubComponentsProvider) UpdateInfo() health.UpdateInfo  { return health.UpdateInfo{} }

// componentsTestServer wires a test Server with a stub provider and the
// supplied watcher state. Findings seeded via the latest set so the
// derived "last event" path is exercised without bbolt history writes.
func componentsTestServer(t *testing.T, statuses map[string]bool, changed map[string]time.Time, latest []alert.Finding) *Server {
	t.Helper()
	s := newTestServer(t, "tok")
	s.provider = &stubComponentsProvider{statuses: statuses, changed: changed}
	if len(latest) > 0 {
		s.store.SetLatestFindings(latest)
	}
	return s
}

func decodeComponentRows(t *testing.T, s *Server) []componentRow {
	t.Helper()
	w := httptest.NewRecorder()
	s.apiComponents(w, httptest.NewRequest("GET", "/api/v1/components", nil))
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	var rows []componentRow
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return rows
}

func TestAPIComponents_DegradedAndIdleStatuses(t *testing.T) {
	now := time.Now()
	s := componentsTestServer(t,
		map[string]bool{
			"fanotify": true,
			"modsec":   false,
		},
		map[string]time.Time{
			"fanotify": now.Add(-3 * time.Minute),
			"modsec":   now.Add(-30 * time.Second),
		},
		nil,
	)

	rows := decodeComponentRows(t, s)
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d: %+v", len(rows), rows)
	}

	// Sorted: degraded (modsec) before idle (fanotify).
	if rows[0].Name != "modsec" || rows[0].Status != "degraded" {
		t.Errorf("first row: want modsec/degraded, got %+v", rows[0])
	}
	if rows[1].Name != "fanotify" || rows[1].Status != "idle" {
		t.Errorf("second row: want fanotify/idle (no events seeded), got %+v", rows[1])
	}
	if rows[0].Label == "modsec" {
		t.Errorf("modsec should resolve to a friendly label, got raw key")
	}
}

func TestAPIComponents_RealtimeChecksAttributeToWatcher(t *testing.T) {
	cases := []struct {
		check   string
		watcher string
	}{
		{check: "modsec_block_realtime", watcher: "modsec"},
		{check: "webshell_realtime", watcher: "fanotify"},
		{check: "email_auth_failure_realtime", watcher: "maillog"},
		{check: "email_php_relay_abuse", watcher: "phprelay"},
		{check: "email_malware", watcher: "email_av_spool"},
		{check: "pam_login", watcher: "pamlistener"},
	}

	for _, tc := range cases {
		t.Run(tc.check, func(t *testing.T) {
			now := time.Now()
			s := componentsTestServer(t,
				map[string]bool{tc.watcher: true},
				map[string]time.Time{tc.watcher: now.Add(-1 * time.Hour)},
				[]alert.Finding{
					{Check: tc.check, Severity: alert.High, Message: "event", Timestamp: now.Add(-2 * time.Minute)},
				},
			)

			rows := decodeComponentRows(t, s)
			if len(rows) != 1 {
				t.Fatalf("expected 1 row, got %d", len(rows))
			}
			if rows[0].Name != tc.watcher {
				t.Fatalf("row name = %q, want %q", rows[0].Name, tc.watcher)
			}
			if rows[0].Status != "ok" {
				t.Errorf("expected ok status when finding present, got %s", rows[0].Status)
			}
			if rows[0].LastEventCheck != tc.check {
				t.Errorf("expected last_event_check %q, got %q", tc.check, rows[0].LastEventCheck)
			}
			if rows[0].LastEventISO == "" {
				t.Errorf("expected last_event_iso populated, got empty")
			}
		})
	}
}

func TestAPIComponents_NonUniqueCheckFindingsDoNotAttributeToWatcher(t *testing.T) {
	cases := []struct {
		check   string
		watcher string
	}{
		{check: "af_alg_socket_use", watcher: "afalg"},
		{check: "email_cloud_relay_abuse", watcher: "maillog"},
		{check: "email_pipe_forwarder", watcher: "forwarder"},
		{check: "email_suspicious_forwarder", watcher: "forwarder"},
		{check: "outdated_plugins", watcher: "fanotify"},
		{check: "suspicious_crontab", watcher: "fanotify"},
		{check: "webshell", watcher: "fanotify"},
		{check: "waf_status", watcher: "modsec"},
		{check: "waf_attack_blocked", watcher: "modsec"},
		{check: "mail_queue", watcher: "maillog"},
		{check: "php_suspicious_execution", watcher: "exec"},
	}

	for _, tc := range cases {
		t.Run(tc.check, func(t *testing.T) {
			now := time.Now()
			s := componentsTestServer(t,
				map[string]bool{tc.watcher: true},
				map[string]time.Time{tc.watcher: now.Add(-1 * time.Hour)},
				[]alert.Finding{
					{Check: tc.check, Severity: alert.High, Message: "X", Timestamp: now.Add(-30 * time.Second)},
				},
			)

			rows := decodeComponentRows(t, s)
			if len(rows) != 1 {
				t.Fatalf("expected 1 row, got %d", len(rows))
			}
			if rows[0].LastEventISO != "" {
				t.Errorf("non-unique finding leaked into last_event: %+v", rows[0])
			}
			if rows[0].Status != "idle" {
				t.Errorf("watcher with no real-time event should be idle, got %s", rows[0].Status)
			}
		})
	}
}

func TestAPIComponents_StaleLatestFindingDoesNotAttributeToWatcher(t *testing.T) {
	now := time.Now()
	s := componentsTestServer(t,
		map[string]bool{"fanotify": true},
		map[string]time.Time{"fanotify": now.Add(-1 * time.Hour)},
		[]alert.Finding{
			{Check: "webshell_realtime", Severity: alert.Critical, Message: "old", Timestamp: now.Add(-8 * 24 * time.Hour)},
		},
	)

	rows := decodeComponentRows(t, s)
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].LastEventISO != "" {
		t.Errorf("stale latest finding leaked into last_event: %+v", rows[0])
	}
	if rows[0].Status != "idle" {
		t.Errorf("watcher with no event in lookback should be idle, got %s", rows[0].Status)
	}
}

func TestAPIComponents_NoProviderReturnsEmptyArray(t *testing.T) {
	s := newTestServer(t, "tok")
	s.provider = nil

	rows := decodeComponentRows(t, s)
	if len(rows) != 0 {
		t.Errorf("expected empty array, got %+v", rows)
	}
}
