package admissionowner

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// Lowering the default must retain spend above the new limit and clip credit,
// while an explicit former default keeps its allowance across restarts and reloads.
func TestOwnerDefaultCeilingUpgrade(t *testing.T) {
	for _, via := range []string{"restart", "reload"} {
		for _, live := range []bool{false, true} {
			for _, spent := range []uint32{0, 1200} {
				for _, tc := range []struct {
					name, yaml, source string
					limit              uint32
				}{
					{"omitted", "", config.CeilingDefault, 1000},
					{"zero", "auto_response:\n  max_blocks_per_hour: 0\n", config.CeilingDefault, 1000},
					{"explicit", "auto_response:\n  max_blocks_per_hour: 2000\n", config.CeilingConfigured, 2000},
				} {
					t.Run(fmt.Sprintf("%s/live=%t/spent=%d/%s", via, live, spent, tc.name), func(t *testing.T) {
						f := newOwnerFixture(t)
						f.host.set(func(h *fakeHost) { h.limit, h.source = 2000, config.CeilingDefault })
						f.legacy(fmt.Sprintf(`{"ips":[],"blocks_this_hour":%d,"hour_key":"2026-10-04T12"}`, spent))
						opts := f.options()
						if live {
							opts = executeOptions(f, newFakeBlocks())
						}
						o := f.start(opts)
						before := ceiling(t, o)
						if before.Limit != 2000 || before.General.Used != spent || before.Reserved.Used != 0 {
							t.Fatalf("former default state = %+v", before)
						}
						var beforeCharges []admission.Charge
						if err := o.do(func() (err error) {
							_, beforeCharges, err = o.ledger.CeilingSnapshot()
							return err
						}); err != nil {
							t.Fatal(err)
						}
						cfg, err := config.LoadBytes([]byte(tc.yaml))
						if err != nil {
							t.Fatal(err)
						}
						f.host.set(func(h *fakeHost) { h.limit, h.source = cfg.AdmissionCeiling() })
						if via == "restart" {
							o.Stop()
							if err = f.db.Close(); err != nil {
								t.Fatal(err)
							}
							f.db, err = store.Open(f.statePath)
							if err != nil {
								t.Fatal(err)
							}
							t.Cleanup(func() { _ = f.db.Close() })
							opts.DB = f.db
							o = f.start(opts)
						} else if err := o.Reload(); err != nil {
							t.Fatal(err)
						}
						st := o.Status()
						if st.Owner.Error != "" || st.Owner.TickError != "" || !st.Ingress.Admitting || st.Owner.CeilingSource != tc.source {
							t.Fatalf("upgrade status: owner=%+v ingress=%+v", st.Owner, st.Ingress)
						}
						after := ceiling(t, o)
						general, reserved := admission.CeilingLanes(tc.limit)
						if after.Limit != tc.limit || after.General.Used != spent || after.Reserved.Used != 0 ||
							after.General.Units() != min(before.General.Units(), admission.BucketCap(general)) ||
							after.Reserved.Units() != min(before.Reserved.Units(), admission.BucketCap(reserved)) {
							t.Fatalf("upgrade changed spend or granted credit: before=%+v after=%+v", before, after)
						}
						if spent > tc.limit && (after.Budget(admission.LaneGeneral) != 0 || after.Budget(admission.LaneDirect) != 0) {
							t.Fatalf("over-limit spend permits more blocks: %+v", after)
						}
						if err := o.do(func() error {
							_, charges, err := o.ledger.CeilingSnapshot()
							if err == nil && !reflect.DeepEqual(charges, beforeCharges) {
								return fmt.Errorf("upgrade changed retained charges: before=%+v after=%+v", beforeCharges, charges)
							}
							return err
						}); err != nil {
							t.Fatal(err)
						}
					})
				}
			}
		}
	}
}
