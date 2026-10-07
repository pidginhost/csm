package admissionowner

import (
	"reflect"
	"slices"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
)

// Handoff from 1.4a: the daemon registers every producer of the table and
// seals the registry, so nothing registers later and the ledger opens. The
// owner keeps every producer's handle: it mints for all of them.
func TestRegistryCoversTheProducerTable(t *testing.T) {
	reg, producers, err := Registry()
	if err != nil {
		t.Fatal(err)
	}
	if !reg.Sealed() {
		t.Fatal("the registry is not sealed")
	}
	table := checks.ProducerTable()
	if len(table) == 0 {
		t.Fatal("the producer table is empty")
	}
	for _, p := range table {
		slices.Sort(p.Spec.Checks)
		slices.Sort(p.Spec.Claims)
		spec, ok := reg.Spec(p.Spec.ID)
		if !ok || !reflect.DeepEqual(spec, p.Spec) {
			t.Errorf("producer %s registered as %+v (%v), want %+v", p.Spec.ID, spec, ok, p.Spec)
		}
		if h := producers[p.Spec.ID]; h == nil || h.ID() != p.Spec.ID {
			t.Errorf("producer %s has no handle", p.Spec.ID)
		}
	}
	if len(producers) != len(table) {
		t.Errorf("%d handles for %d producers", len(producers), len(table))
	}
	for _, spec := range checks.DerivedEntries() {
		if got, ok := reg.Spec(spec.ID); !ok || got.Entry != spec.Entry {
			t.Errorf("derived entry %s registered as %+v (%v)", spec.ID, got, ok)
		}
	}
}
