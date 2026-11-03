package admissionowner

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

// A preview that takes the slot of a lower-priority automatic block counts
// as a previewed replacement in status, in all and over the last hour of
// process monotonic time. A preview into a free slot and work that waits
// count nothing.
func TestOwnerCountsPreviewedReplacements(t *testing.T) {
	withLiveExecution(t, false)
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.limit, blocks.temp, blocks.imported = 3, 2, 1
	blocks.imports = []firewall.BlockImport{{ID: "eff_" + strings.Repeat("ab", 16), IP: "192.0.2.60", ExpiresAt: f.host.wall.Add(time.Hour)}}
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.11")
	turn(t, o)
	if s := o.status().Owner; s.PreviewReplacements != 1 || s.PreviewReplacementsLastHour != 1 {
		t.Fatalf("after a funded preview: %d in all, %d in the last hour", s.PreviewReplacements, s.PreviewReplacementsLastHour)
	}
	queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.13")
	turn(t, o)
	if s := o.status().Owner; s.PreviewReplacements != 2 || s.PreviewReplacementsLastHour != 2 {
		t.Fatalf("two previews of one import: %d in all, %d in the last hour", s.PreviewReplacements, s.PreviewReplacementsLastHour)
	}
	blocks.set(func(b *fakeBlocks) { b.limit = 10 })
	queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.12")
	turn(t, o)
	if s := o.status().Owner; s.PreviewReplacements != 2 || s.PreviewReplacementsLastHour != 2 {
		t.Fatalf("free-slot preview counted: %d in all, %d in the last hour", s.PreviewReplacements, s.PreviewReplacementsLastHour)
	}
	mono.advance(time.Hour)
	if err := o.do(func() error { o.refreshStatus(); return nil }); err != nil {
		t.Fatal(err)
	}
	if s := o.status().Owner; s.PreviewReplacements != 2 || s.PreviewReplacementsLastHour != 0 {
		t.Fatalf("after free-slot previews and an hour: %d in all, %d in the last hour", s.PreviewReplacements, s.PreviewReplacementsLastHour)
	}
}

// A preview whose victim has the pick's own tier took the slot live
// admission would rotate out: it counts as a previewed rotation, never as
// a replacement of a lower-priority block, in all and over the last hour.
func TestOwnerCountsPreviewedRotations(t *testing.T) {
	withLiveExecution(t, false)
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	victim := admission.EvictionVictim{Action: admission.ActionID("eff_" + strings.Repeat("cd", 16)), Tier: highTier, Partition: admission.PartitionGeneral}
	setOwnerHook(t, o, &observeLedger, func(l *store.AdmissionLedger, id admission.CandidateID, lane admission.Lane, expiresAt time.Time) (admission.Candidate, admission.AttemptRecord, bool, admission.EvictionVictim, error) {
		c, a, granted, _, err := l.ObserveVictim(id, lane, expiresAt)
		return c, a, granted, victim, err
	})
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	turn(t, o)
	if s := o.status().Owner; s.PreviewRotations != 1 || s.PreviewRotationsLastHour != 1 || s.PreviewReplacements != 0 {
		t.Fatalf("an equal-tier preview: %+v", s)
	}
	queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.11")
	turn(t, o)
	if s := o.status().Owner; s.PreviewRotations != 1 || s.PreviewReplacements != 1 || s.PreviewReplacementsLastHour != 1 {
		t.Fatalf("a strictly higher preview: %+v", s)
	}
	mono.advance(time.Hour)
	if err := o.do(func() error { o.refreshStatus(); return nil }); err != nil {
		t.Fatal(err)
	}
	if s := o.status().Owner; s.PreviewRotations != 1 || s.PreviewRotationsLastHour != 0 {
		t.Fatalf("after an hour: %+v", s)
	}
}
