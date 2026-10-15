package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/health"
)

type admissionStatusProvider struct {
	statusFakeProvider
	status *health.AdmissionStatus
}

func (p admissionStatusProvider) AdmissionStatus() *health.AdmissionStatus { return p.status }

// /api/v1/status copies the admission view when the daemon owns a ledger
// and leaves the key out otherwise.
func TestAPIStatusCopiesAdmission(t *testing.T) {
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	status := func(p health.Provider) map[string]json.RawMessage {
		s := &Server{cfg: capsTestCfg(), startTime: now.Add(-time.Hour), version: "test"}
		s.SetHealthProvider(p)
		rec := httptest.NewRecorder()
		s.apiStatus(rec, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if _, ok := status(statusFakeProvider{})["admission"]; ok {
		t.Fatal("admission key without a ledger")
	}
	raw := status(admissionStatusProvider{status: &health.AdmissionStatus{
		CheckedAt: now, Ingress: &admission.IngressHealth{Admitting: true},
		Ledger: &admission.LedgerStatus{Queue: admission.QueueStatus{Queued: 3}},
	}})
	var got health.AdmissionStatus
	if err := json.Unmarshal(raw["admission"], &got); err != nil {
		t.Fatal(err)
	}
	if !got.CheckedAt.Equal(now) || got.Ledger.Queue.Queued != 3 || !got.Ingress.Admitting {
		t.Fatalf("admission = %+v", got)
	}
}

// Spec 3.8, 6.4: /api/v1/status and the control socket's status carry the
// same admission object, built from one provider: the dry-run and verdict
// objects agree field by field, nulls and zero counters included, for an
// active and an inactive forecast.
func TestAPIStatusAdmissionMatchesTheControlSocket(t *testing.T) {
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	session, reset, class := "0123456789abcdef0123456789abcdef", "mode_change", "timeout"
	kinds, scope := []string{"block_ip"}, "ceiling_and_temporary_capacity"
	for name, dryRun := range map[string]*health.AdmissionDryRun{
		"active": {
			Active: true, SessionID: &session, Since: &now, ResetReason: &reset, ModelledKinds: kinds, PredictionScope: scope,
			Occupancy: &health.AdmissionDryRunOccupancy{Actual: 8, ShadowOnly: 1, Predicted: 9, Limit: 10},
			Ceiling:   &health.AdmissionDryRunCeiling{Limit: 5, GeneralUsed: 1, GeneralBudget: 3},
			Picks:     map[string]uint64{"capacity_admit": 2, "set_full": 0}, LastHour: map[string]uint64{"capacity_admit": 2, "set_full": 0},
		},
		"inactive": {
			SessionID: &session, Since: &now, ResetReason: &reset, ModelledKinds: kinds, PredictionScope: scope,
			Picks: map[string]uint64{"capacity_admit": 0}, LastHour: map[string]uint64{"capacity_admit": 0},
			ExamplesLost: 3, ExamplesStale: true, ComparisonIncomplete: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := admissionStatusProvider{status: &health.AdmissionStatus{CheckedAt: now, Owner: &health.AdmissionOwner{
				DryRun: dryRun, Verdict: &health.AdmissionVerdict{Enabled: true, Epoch: 2, Asked: 1, Failed: 1, LastError: &class, LastErrorAt: &now},
			}}}
			s := &Server{cfg: capsTestCfg(), startTime: now.Add(-time.Hour), version: "test"}
			s.SetHealthProvider(p)
			rec := httptest.NewRecorder()
			s.apiStatus(rec, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
			var api map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &api); err != nil {
				t.Fatal(err)
			}
			snap := health.Build(p, "test", health.Capabilities())
			data, err := json.Marshal(control.StatusResult{Snapshot: &snap})
			if err != nil {
				t.Fatal(err)
			}
			var socket struct {
				Snapshot map[string]any `json:"snapshot"`
			}
			if err = json.Unmarshal(data, &socket); err != nil {
				t.Fatal(err)
			}
			if api["admission"] == nil || !reflect.DeepEqual(api["admission"], socket.Snapshot["admission"]) {
				t.Fatalf("HTTP admission %v, control socket %v", api["admission"], socket.Snapshot["admission"])
			}
			owner := api["admission"].(map[string]any)["owner"].(map[string]any)
			if d := owner["dry_run"].(map[string]any); d["forecast_error"] != nil || d["last_error_at"] != nil || (name == "inactive" && (d["occupancy"] != nil || d["ceiling"] != nil)) {
				t.Fatalf("absent dry-run values are not null: %v", d)
			}
		})
	}
}
