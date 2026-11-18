package admissionowner

import (
	"slices"
	"sync"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
)

// Status names the entries whose automatic IP blocks the configuration
// lets admission run, read at each refresh, since some of their switches
// change without a new policy. An owner without the firewall engine runs
// none and names none.
func TestOwnerStatusNamesItsBlockEntries(t *testing.T) {
	withTestRegistry(t)
	f := newOwnerFixture(t)
	var mu sync.Mutex
	entries := []admission.Entry{admission.EntryScan, admission.EntryIncident}
	p := dryPolicy(1)
	p.BlockEntries = func() []admission.Entry {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(entries)
	}
	o, _, _ := policyOwner(t, f, newFakeBlocks(), p)
	if got := o.status().Owner.BlockEntries; !slices.Equal(got, []string{"scan", "incident"}) {
		t.Fatalf("block entries = %q, want scan and incident", got)
	}
	mu.Lock()
	entries = []admission.Entry{admission.EntryScan}
	mu.Unlock()
	if got := o.status().Owner.BlockEntries; !slices.Equal(got, []string{"scan"}) {
		t.Fatalf("block entries after a config change = %q, want scan", got)
	}
	preview := previewOptions(f)
	preview.Policy = func() ExecutionPolicy { return p }
	o.Stop()
	if got := f.start(preview).status().Owner.BlockEntries; got != nil {
		t.Fatalf("an owner without the engine names %q", got)
	}
}
