package admissionowner

import (
	"sync/atomic"
	"testing"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
)

// A root can lose its attribution before submission or queue placement.
// Both refusal paths must keep the cause in the hourly summary.
func TestOwnerSummarizesRetainedAttributionRefusals(t *testing.T) {
	for _, stage := range []string{"respond", "drain"} {
		t.Run(stage, func(t *testing.T) {
			var kinds atomic.Uint32
			kinds.Store(uint32(admission.Attributions(admission.AttributionPeer)))
			reg, err := admission.NewRegistry(func(check string) (string, admission.Policy, bool) {
				return check, admission.Policy{Family: admission.FamilySSH, Basis: admission.BasisLocal,
					Attribution: admission.AttributionSet(kinds.Load())}, check == "ssh_brute"
			})
			if err != nil {
				t.Fatal(err)
			}
			p, err := reg.Register(admission.ProducerSpec{ID: "sshd_log", Entry: admission.EntryScan,
				Observation: admission.ObservationLogCursor, Checks: []string{"ssh_brute"},
				Attribution: admission.Attributions(admission.AttributionPeer)})
			if err != nil {
				t.Fatal(err)
			}
			reg.Seal()
			previous := buildRegistry
			buildRegistry = func() (*admission.Registry, map[admission.ProducerID]*admission.Producer, error) {
				return reg, map[admission.ProducerID]*admission.Producer{p.ID(): p}, nil
			}
			t.Cleanup(func() { buildRegistry = previous })
			f := newOwnerFixture(t)
			comparisonClock(t, f.host.now)
			sink := &actionSink{}
			opts := respondOptions(f)
			opts.WriteAudit = sink.write
			o := f.start(opts)
			finding := sshFinding(f.host.now(), "offset=1", alert.High)
			root, err := o.Mint(finding)
			if err != nil {
				t.Fatal(err)
			}
			if stage == "respond" {
				kinds.Store(0)
				if err := o.Respond(admission.KindBlockIP, finding.SourceIP, root, 0); admission.CauseOf(err) != admission.CauseKindNotAllowed {
					t.Fatalf("retained root refusal: %v", err)
				}
			} else {
				// Two selections of one observation must keep their count
				// when the ledger refuses the coalesced arrival.
				for range 2 {
					if err := o.Respond(admission.KindBlockIP, finding.SourceIP, root, 0); err != nil {
						t.Fatal(err)
					}
				}
				kinds.Store(0)
				if err := o.do(o.drain); err != nil {
					t.Fatal(err)
				}
			}
			if err := o.do(func() error { o.writeComparison(true); return nil }); err != nil {
				t.Fatal(err)
			}
			sink.mu.Lock()
			defer sink.mu.Unlock()
			var refusals []actionlog.Record
			for _, row := range sink.recs {
				if row.Count > 0 && row.Result == actionlog.Refused {
					refusals = append(refusals, row)
				}
			}
			want := uint64(1)
			if stage == "drain" {
				want = 2
			}
			if len(refusals) != 1 || refusals[0].Count != want || refusals[0].Error != "attribution" || refusals[0].Cause != "kind_not_allowed" {
				t.Fatalf("refusals = %+v, want one attribution/kind_not_allowed summary counting %d", refusals, want)
			}
		})
	}
}
