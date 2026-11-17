package admissionowner

import (
	"errors"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
)

type drainingSetEngine struct {
	BlockEngine
	drain time.Duration
}

func (e drainingSetEngine) BlockAdmissionSnapshot(members []firewall.BlockMember, shadow []string) (firewall.BlockAdmission, error) {
	snapshot, err := e.BlockEngine.BlockAdmissionSnapshot(members, shadow)
	snapshot.Drain = e.drain
	return snapshot, err
}

// The engine's drain excludes admission rows. If any become unclaimed,
// even a known drain for the other occupants cannot bound the whole set.
func TestOwnerUnclaimedAdmissionDrain(t *testing.T) {
	for _, tc := range []struct {
		name      string
		admitted  int
		hold      admission.Lane // the lane of the ledger's own record, if any
		unclaimed int
		drain     int64
	}{
		{"no admission rows", 0, 0, 1, 3600},
		{"unknown row", 1, 0, 2, -1},
		{"owned row", 1, admission.LaneGeneral, 1, 3600},
		{"owned reserved row", 1, admission.LaneDirect, 1, 3600},
		{"owned and unknown rows", 2, admission.LaneGeneral, 2, -1},
		{"hold without a row", 0, admission.LaneGeneral, 1, 3600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			basis := admission.BasisLocal
			if tc.hold == admission.LaneDirect {
				basis = admission.BasisCompromise // direct work holds a reserved slot
			}
			p := withTestRegistryBasis(t, basis)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			blocks.limit, blocks.temp, blocks.admitted = 10, tc.admitted+1, tc.admitted
			opts := executeOptions(f, blocks)
			opts.Blocks = func() BlockEngine { return drainingSetEngine{BlockEngine: blocks, drain: time.Hour} }
			o := f.start(opts)
			if tc.hold != 0 {
				id, now := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
				if err := o.do(func() error {
					_, _, granted, err := o.ledger.Reserve(id, tc.hold, now.Add(time.Hour))
					if err == nil && !granted {
						err = errors.New("reservation not granted")
					}
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
			for range 2 {
				if err := o.do(o.readSet); err != nil {
					t.Fatal(err)
				}
				set, setErr := ownerSet(t, o)
				if set == nil || setErr != "" || set.Unclaimed != tc.unclaimed || set.DrainSeconds != tc.drain {
					t.Fatalf("set = %+v, error = %q; want unclaimed %d, drain %d", set, setErr, tc.unclaimed, tc.drain)
				}
			}
			if blocks.setReads != 2 {
				t.Fatalf("set reads = %d, want 2", blocks.setReads)
			}
		})
	}
}
