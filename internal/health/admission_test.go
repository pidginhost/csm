package health

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

type admissionFakeProvider struct {
	*fakeProvider
	status *AdmissionStatus
}

func (f admissionFakeProvider) AdmissionStatus() *AdmissionStatus { return f.status }

// The admission view reaches the snapshot only from a provider that owns an
// admission ledger; without one the field stays nil and its JSON key is
// left out, so status output is unchanged.
func TestBuildCarriesAdmissionOnlyFromAnOwner(t *testing.T) {
	plain := Build(&fakeProvider{}, "v", nil)
	if plain.Admission != nil {
		t.Fatal("a provider without a ledger reported admission")
	}
	data, err := json.Marshal(plain)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"admission"`) {
		t.Fatalf("nil admission published: %s", data)
	}
	want := &AdmissionStatus{
		CheckedAt: time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC),
		Ledger:    &admission.LedgerStatus{Queue: admission.QueueStatus{Queued: 2}},
		Ingress:   &admission.IngressHealth{Admitting: true},
	}
	owned := Build(admissionFakeProvider{&fakeProvider{}, want}, "v", nil)
	if owned.Admission == nil || owned.Admission.Ledger.Queue.Queued != 2 || !owned.Admission.Ingress.Admitting {
		t.Fatalf("admission = %+v", owned.Admission)
	}
	if data, err = json.Marshal(owned); err != nil || !strings.Contains(string(data), `"admission":{"checked_at"`) {
		t.Fatalf("owned snapshot: %s, %v", data, err)
	}
}
