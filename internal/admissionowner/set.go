package admissionowner

import (
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/health"
)

// readSet reads the temporary set for the turn's schedule and reservations
// (spec 5.6) when queued work may take a slot: the firewall's entries
// outside admission's records go to the ledger, which adds its own.
// Without an engine the ledger has no set and block work has no slot
// budget, as before; a failed read leaves it so and shows in status. The
// batch check that follows reads the same firewall state and holds
// execution when it fails too. One read-only snapshot names no member and
// changes nothing, so a preview owner reads the set as well.
func (o *Owner) readSet() error {
	o.set, o.setErr = nil, nil
	o.ledger.SetOccupants(nil)
	var engine BlockEngine
	if o.executable() {
		engine = o.opts.Blocks()
	}
	if engine == nil {
		return nil
	}
	if charged, err := o.ledger.HasChargedWork(); err != nil || !charged {
		return err
	}
	adm, err := engine.BlockAdmissionSnapshot(nil, nil)
	if o.setErr = err; err == nil {
		o.set = &adm
		o.ledger.SetOccupants(&admission.SetOccupancy{Limit: adm.Limit, Unclaimed: adm.Unclaimed, General: adm.Imported})
	}
	return nil
}

// clearSet forgets the set: a forecast turn models its own.
func (o *Owner) clearSet() {
	o.set, o.setErr = nil, nil
	o.ledger.SetOccupants(nil)
}

// setStatus combines the last scheduling turn's non-admission occupants
// with the current ledger holds. Engine admission rows are already counted
// by effects and must not be added again.
func setStatus(adm firewall.BlockAdmission, effects admission.EffectsStatus) *health.AdmissionSet {
	occ := admission.SetOccupancy{Limit: adm.Limit, Unclaimed: adm.Unclaimed, General: adm.Imported + effects.General, Reserved: effects.Reserved}
	slots := occ.Slots()
	return &health.AdmissionSet{
		Limit: adm.Limit, Unlimited: adm.Limit <= 0, Capacity: slots.Capacity,
		Unclaimed: adm.Unclaimed, Imported: adm.Imported, DrainSeconds: int64(adm.Drain / time.Second),
		General:  health.AdmissionDryRunPartition{Size: slots.General, Used: occ.General, Free: slots.FreeGeneral},
		Reserved: health.AdmissionDryRunPartition{Size: slots.Reserved, Used: occ.Reserved, Free: slots.FreeReserved},
	}
}
