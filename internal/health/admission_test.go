package health

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

type admissionFakeProvider struct {
	*fakeProvider
	status *AdmissionStatus
}

func TestBuildOwnsAdmissionSnapshot(t *testing.T) {
	status := &AdmissionStatus{
		CheckedAt: time.Unix(100, 0),
		Ledger: &admission.LedgerStatus{
			Queue:    admission.QueueStatus{Occupancy: []admission.QueueOccupancy{{Count: 1}}},
			Counters: admission.CountersStatus{Rows: []admission.CountRow{{N: 2}}},
			Outcomes: admission.OutcomesStatus{
				Hour:  []admission.OutcomeStatusRow{{N: 3}},
				Day:   []admission.OutcomeStatusRow{{N: 4}},
				Month: []admission.OutcomeStatusRow{{N: 5}},
			},
			Notices: admission.NoticesStatus{Records: []admission.NoticeStatusRow{{Count: 6}}},
		},
		Ingress: &admission.IngressHealth{Admitting: true},
		Owner:   &AdmissionOwner{CeilingSource: "default", Import: &AdmissionImport{Units: 7}},
	}
	snapshot := Build(admissionFakeProvider{&fakeProvider{}, status}, "v", nil)
	before, err := json.Marshal(snapshot.Admission)
	if err != nil {
		t.Fatal(err)
	}
	status.CheckedAt = time.Unix(200, 0)
	status.Ingress.Admitting = false
	status.Ledger.Queue.Occupancy[0].Count++
	status.Ledger.Counters.Rows[0].N++
	status.Ledger.Outcomes.Hour[0].N++
	status.Ledger.Outcomes.Day[0].N++
	status.Ledger.Outcomes.Month[0].N++
	status.Ledger.Notices.Records[0].Count++
	status.Owner.CeilingSource = "configured"
	status.Owner.Import.Units++
	after, err := json.Marshal(snapshot.Admission)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("provider mutation changed a published snapshot: before=%s after=%s", before, after)
	}
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
