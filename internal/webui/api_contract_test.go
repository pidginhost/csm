package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/health"
	"github.com/pidginhost/csm/internal/store"
)

func TestAPIStatusCarriesHealthSnapshotContract(t *testing.T) {
	now := time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)
	s := &Server{cfg: capsTestCfg(), startTime: now.Add(-time.Hour), version: "test"}
	s.SetHealthProvider(statusFakeProvider{
		bpfEnforcementActive: true,
		latestScan:           now.Add(-10 * time.Minute),
		baselineAt:           now.Add(-24 * time.Hour),
		automation: health.AutomationStatus{
			AutoResponseEnabled:           true,
			AutoResponseBlockIPs:          true,
			AutoResponseDryRun:            true,
			DryRunBlocks:                  3,
			ChallengeEnabled:              true,
			ChallengePending:              2,
			FirewallRollbackPending:       true,
			FirewallRollbackSecondsRemain: 120,
			LastAction: &health.AutomationAction{
				Check:     "auto_block",
				Message:   "AUTO-BLOCK: 203.0.113.5 blocked",
				Timestamp: now,
			},
		},
		update: health.UpdateInfo{
			LatestVersion: "3.0.1",
			Available:     true,
			Source:        "github",
			CheckedAt:     now,
		},
	})

	rec := httptest.NewRecorder()
	s.apiStatus(rec, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))

	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	assertJSONKeys(t, raw, jsonStructKeys(reflect.TypeOf(health.Snapshot{})))
	automation, ok := raw["automation"].(map[string]any)
	if !ok {
		t.Fatalf("automation payload = %T, want object", raw["automation"])
	}
	assertJSONKeys(t, automation, jsonStructKeys(reflect.TypeOf(health.AutomationStatus{})))
}

func TestAPICapabilitiesContract(t *testing.T) {
	s := &Server{version: "test"}
	rec := httptest.NewRecorder()
	s.apiCapabilities(rec, httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil))

	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal capabilities: %v", err)
	}
	assertJSONKeys(t, raw, []string{"capabilities", "version"})
}

func TestAPIComponentsContract(t *testing.T) {
	now := time.Now()
	s := componentsTestServer(t,
		map[string]bool{"fanotify": true},
		map[string]time.Time{"fanotify": now.Add(-5 * time.Minute)},
		[]alert.Finding{
			{Check: "webshell_realtime", Severity: alert.High, Message: "event", Timestamp: now},
		},
	)
	stub := s.provider.(*stubComponentsProvider)
	stub.upstream = map[string]health.UpstreamResult{
		"fanotify": {Fresh: false, LastActivity: now.Add(-2 * time.Hour), Reason: "no marks"},
	}

	rec := httptest.NewRecorder()
	s.apiComponents(rec, httptest.NewRequest(http.MethodGet, "/api/v1/components", nil))

	var raw []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal components: %v", err)
	}
	if len(raw) != 1 {
		t.Fatalf("component rows = %d, want 1", len(raw))
	}
	assertJSONKeys(t, raw[0], jsonStructKeys(reflect.TypeOf(componentRow{})))
}

func TestAPIEmailGroupsContract(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	now := time.Now()
	s.store.AppendHistory([]alert.Finding{{
		Severity:  alert.Critical,
		Check:     "email_spam_outbreak",
		Message:   "spam",
		Mailbox:   "user@example.com",
		Domain:    "example.com",
		SourceIP:  "198.51.100.20",
		MsgIDs:    []string{"1AA", "1BB"},
		Timestamp: now,
	}})

	rec := httptest.NewRecorder()
	s.apiEmailGroups(rec, httptest.NewRequest(http.MethodGet, "/api/v1/email/groups", nil))

	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal email groups: %v", err)
	}
	assertJSONKeys(t, raw, jsonStructKeys(reflect.TypeOf(emailGroupsResponse{})))
	groups, ok := raw["groups"].([]any)
	if !ok {
		t.Fatalf("groups payload = %T, want array", raw["groups"])
	}
	if len(groups) != 1 {
		t.Fatalf("groups = %d, want 1", len(groups))
	}
	group, ok := groups[0].(map[string]any)
	if !ok {
		t.Fatalf("group payload = %T, want object", groups[0])
	}
	assertJSONKeys(t, group, jsonStructKeys(reflect.TypeOf(emailGroup{})))
}

func TestAPIModSecBlocksContract(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	sdb := store.Global()
	now := time.Now()
	if err := sdb.AppendHistory([]alert.Finding{
		modsecBlock("203.0.113.50", "example.com", "/wp-login.php", "900113", now),
	}); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	s.apiModSecBlocks(rec, httptest.NewRequest(http.MethodGet, "/api/v1/modsec/blocks", nil))

	var raw []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal modsec blocks: %v", err)
	}
	if len(raw) != 1 {
		t.Fatalf("modsec rows = %d, want 1", len(raw))
	}
	assertJSONKeys(t, raw[0], jsonStructKeys(reflect.TypeOf(modsecBlockView{})))
	samples, ok := raw[0]["sample_events"].([]any)
	if !ok {
		t.Fatalf("sample_events payload = %T, want array", raw[0]["sample_events"])
	}
	if len(samples) != 1 {
		t.Fatalf("sample_events = %d, want 1", len(samples))
	}
	sample, ok := samples[0].(map[string]any)
	if !ok {
		t.Fatalf("sample payload = %T, want object", samples[0])
	}
	assertJSONKeys(t, sample, jsonStructKeys(reflect.TypeOf(modsecSampleEvent{})))
}

func jsonStructKeys(typ reflect.Type) []string {
	keys := make([]string, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}
		name := field.Tag.Get("json")
		if idx := strings.IndexByte(name, ','); idx >= 0 {
			name = name[:idx]
		}
		if name == "" {
			name = field.Name
		}
		if name == "-" {
			continue
		}
		keys = append(keys, name)
	}
	return keys
}

func assertJSONKeys(t *testing.T, raw map[string]any, keys []string) {
	t.Helper()
	for _, key := range keys {
		if _, ok := raw[key]; !ok {
			t.Errorf("JSON key %q missing from %#v", key, raw)
		}
	}
}
