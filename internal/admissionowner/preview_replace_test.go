package admissionowner

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
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
