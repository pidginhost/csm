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

// Each hourly summary names the daemon run that counted it: the ledger's
// ingress generation, which every start advances. The comparison judges
// one run at a time and never mixes two.
func TestComparisonSummariesNameTheirRun(t *testing.T) {
	withTestRegistry(t)
	f := newOwnerFixture(t)
	comparisonClock(t, f.host.now)
	sink := &actionSink{}
	opts := respondOptions(f)
	opts.WriteAudit = sink.write
	var last uint64
	for run, cursor := range []string{"offset=1", "offset=2"} {
		before := len(sink.recs)
		o := f.start(opts)
		e, err := o.Mint(sshFinding(f.host.now(), cursor, alert.High))
		if err != nil {
			t.Fatal(err)
		}
		if err = o.Respond(admission.KindBlockIP, targetOf(e), e, 0); err != nil {
			t.Fatal(err)
		}
		if err = o.do(o.drain); err != nil {
			t.Fatal(err)
		}
		o.Stop()
		rows := sink.recs[before:]
		if len(rows) == 0 {
			t.Fatalf("run %d wrote no summary", run+1)
		}
		epoch := rows[0].Epoch
		for _, r := range rows {
			if r.Count == 0 || r.Epoch != epoch {
				t.Fatalf("run %d rows %+v, want summaries of one run", run+1, rows)
			}
		}
		if epoch <= last {
			t.Fatalf("run %d epoch %d, earlier run %d: a restart must start a new run", run+1, epoch, last)
		}
		last = epoch
	}
}

// A failed publication retries ingress startup in the same daemon run.
// Its written and pending summaries must keep the run's first identity.
func TestComparisonEpochSurvivesStartupRetries(t *testing.T) {
	for _, pending := range []bool{false, true} {
		name := "written"
		if pending {
			name = "pending"
		}
		t.Run(name, func(t *testing.T) {
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
			failWrite := pending
			var attempted []actionlog.Record
			opts := respondOptions(f)
			opts.WriteAudit = func(rows []actionlog.Record) error {
				attempted = append(attempted, rows...)
				if failWrite {
					return errors.New("audit unavailable")
				}
				return sink.write(rows)
			}
			o := f.start(opts)
			if o.started || o.startErr == nil {
				t.Fatal("startup did not fail at publication")
			}
			o.Refuse(admission.KindBlockIP, sshFinding(f.host.now(), "offset=1", alert.High), 0,
				&admission.Error{Reason: admission.ReasonEngineUnavailable})
			f.host.advance(time.Hour)
			if err := o.do(func() error { o.writeComparison(false); return nil }); err != nil {
				t.Fatal(err)
			}
			if len(attempted) != 1 || attempted[0].Count != 1 || attempted[0].Epoch == 0 {
				t.Fatalf("first write = %+v, want one named refusal", attempted)
			}
			epoch := attempted[0].Epoch
			if err := o.do(o.start); err == nil {
				t.Fatal("retry did not fail at publication")
			}
			o.Refuse(admission.KindBlockIP, sshFinding(f.host.now(), "offset=2", alert.High), 0,
				&admission.Error{Reason: admission.ReasonEngineUnavailable})
			if err := o.do(func() error {
				failSnapshot, failWrite = false, false
				return o.start()
			}); err != nil {
				t.Fatal(err)
			}
			if generation := ledgerStatus(t, o).Ingress.Generation; generation <= epoch {
				t.Fatalf("startup did not advance ingress: %d <= %d", generation, epoch)
			}
			o.Stop()
			if len(sink.recs) != 2 {
				t.Fatalf("rows = %+v, want two hourly refusals", sink.recs)
			}
			for _, row := range sink.recs {
				if row.Epoch != epoch || row.Count != 1 || row.Result != actionlog.Refused {
					t.Errorf("row = %+v, want one refusal in epoch %d", row, epoch)
				}
			}
		})
	}
}
