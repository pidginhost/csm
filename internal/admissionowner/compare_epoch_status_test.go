package admissionowner

import (
	"errors"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

// A startup retry begins a new ingress generation. The summaries the
// running owner writes afterwards name that generation, the one status
// reports, so a comparison can bind its verdict to the status's run.
func TestComparisonEpochFollowsTheStatusGeneration(t *testing.T) {
	withTestRegistry(t)
	f := newOwnerFixture(t)
	comparisonClock(t, f.host.now)
	original := readSnapshot
	failSnapshot := true
	readSnapshot = func(l *store.AdmissionLedger) (*admission.QueueSnapshot, error) {
		if failSnapshot {
			return nil, errors.New("snapshot unavailable")
		}
		return original(l)
	}
	t.Cleanup(func() { readSnapshot = original })
	sink := &actionSink{}
	opts := respondOptions(f)
	opts.WriteAudit = sink.write
	o := f.start(opts)
	if o.started || o.startErr == nil {
		t.Fatal("startup did not fail at publication")
	}
	if err := o.do(func() error {
		failSnapshot = false
		return o.start()
	}); err != nil {
		t.Fatal(err)
	}
	o.Refuse(admission.KindBlockIP, sshFinding(f.host.now(), "offset=1", alert.High), 0,
		&admission.Error{Reason: admission.ReasonEngineUnavailable})
	f.host.advance(time.Hour)
	if err := o.do(func() error { o.writeComparison(false); return nil }); err != nil {
		t.Fatal(err)
	}
	generation := ledgerStatus(t, o).Ingress.Generation
	o.Stop()
	if len(sink.recs) != 1 || sink.recs[0].Result != actionlog.Refused || sink.recs[0].Epoch != generation {
		t.Fatalf("rows = %+v, want one refusal in the status generation %d", sink.recs, generation)
	}
}
