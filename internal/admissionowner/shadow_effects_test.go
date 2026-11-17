package admissionowner

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
)

// The model counts each slot the ledger's records hold in the record's
// partition, as the live ledger does; admission rows beyond the records
// are unclaimed, as live reads them.
func TestShadowOccupancySeedsTheLedgerRecords(t *testing.T) {
	s := testShadow(t, freshCeiling(t, 2000), nil)
	adm := firewall.BlockAdmission{Limit: 20, Unclaimed: 1, Imported: 2, Admission: 6}
	for _, tc := range []struct {
		name    string
		effects admission.EffectTally
		want    admission.SetOccupancy
	}{
		{"no record: every admission row is unclaimed", admission.EffectTally{}, admission.SetOccupancy{Limit: 20, Unclaimed: 7, General: 2}},
		{"records hold their partitions", admission.EffectTally{General: 3, Reserved: 1}, admission.SetOccupancy{Limit: 20, Unclaimed: 3, General: 5, Reserved: 1}},
		{"records beyond the rows", admission.EffectTally{General: 5, Reserved: 2}, admission.SetOccupancy{Limit: 20, Unclaimed: 1, General: 7, Reserved: 2}},
	} {
		s.effects = tc.effects
		if got := s.occupancy(adm); got != tc.want {
			t.Fatalf("%s: occupancy = %+v, want %+v", tc.name, got, tc.want)
		}
		// Status reports the unclaimed entries the partitions are sized by.
		s.adm = &adm
		wantSlots := tc.want.Slots()
		wantDrain := int64(0)
		if tc.want.Unclaimed > adm.Unclaimed {
			wantDrain = -1
		}
		if got := s.occupancyStatus(); got.Unclaimed != tc.want.Unclaimed || got.General.Used != tc.want.General || got.Reserved.Used != tc.want.Reserved ||
			got.General.Free != wantSlots.FreeGeneral || got.Reserved.Free != wantSlots.FreeReserved || got.DrainSeconds != wantDrain {
			t.Fatalf("%s: status = %+v; slots=%+v drain=%d", tc.name, got, wantSlots, wantDrain)
		}
	}
}

// The store can fail after a healthy engine snapshot. A prior forecast's
// occupancy must not survive beside that new snapshot.
type closingForecastEngine struct {
	BlockEngine
	close func() error
}

func (e closingForecastEngine) BlockAdmissionSnapshot(members []firewall.BlockMember, ips []string) (firewall.BlockAdmission, error) {
	adm, err := e.BlockEngine.BlockAdmissionSnapshot(members, ips)
	if err == nil {
		err = e.close()
	}
	return adm, err
}

func TestOwnerForecastEffectReadFailureClearsOccupancy(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.limit = 50
	o, _, _ := policyOwner(t, f, blocks, dryPolicy(1))
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.90")
	turn(t, o)
	if dryRunState(t, o).Occupancy == nil {
		t.Fatal("first forecast has no occupancy")
	}
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.91")
	if err := o.do(func() error {
		before := len(o.shadow.entries)
		o.opts.Blocks = func() BlockEngine { return closingForecastEngine{BlockEngine: blocks, close: f.db.Close} }
		err := o.forecast()
		if err == nil || !strings.Contains(err.Error(), "reading the ledger's set slots") || o.forecastErr != forecastLedgerUnavailable || o.shadow.adm != nil {
			t.Errorf("failed effect read: err=%v code=%s snapshot=%+v", err, o.forecastErr, o.shadow.adm)
		}
		if len(o.shadow.entries) != before || o.dryRunStatus().Occupancy != nil {
			t.Errorf("failed effect read changed the model or kept occupancy")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, applies := blocks.calls(); len(applies) != 0 {
		t.Fatalf("forecast sent %d batches", len(applies))
	}
}
