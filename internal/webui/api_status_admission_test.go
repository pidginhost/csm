package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
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
