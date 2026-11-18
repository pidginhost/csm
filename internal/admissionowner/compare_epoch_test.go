package admissionowner

import (
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
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
