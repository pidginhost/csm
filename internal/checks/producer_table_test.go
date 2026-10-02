package checks

import (
	"fmt"
	"slices"
	"sort"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
)

// Every producer in the table registers on the production policy, so the
// registry the daemon builds from it at start cannot refuse one.
func TestProducerTableRegistersOnProductionPolicy(t *testing.T) {
	reg, err := admission.NewRegistry(AdmissionPolicy)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ProducerTable() {
		if _, err := reg.Register(p.Spec); err != nil {
			t.Errorf("%s: %v", p.Spec.ID, err)
		}
	}
}

// The table publishes exactly the classified checks whose producers carry
// an address. A check that can carry evidence but has no producer, or a
// producer of a check without evidence, fails here.
func TestProducerTableCoversEveryAddressEvidenceCheck(t *testing.T) {
	published := map[string]bool{}
	for _, p := range ProducerTable() {
		for _, check := range p.Spec.Checks {
			published[check] = true
		}
	}
	var want, got []string
	for check := range evidencePolicy {
		if !slices.Contains(respondingWithoutAddress, check) {
			want = append(want, check)
		}
	}
	for check := range published {
		got = append(got, check)
	}
	sort.Strings(want)
	sort.Strings(got)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("published checks\n%v\nwant\n%v", got, want)
	}
}

// Each producer names one parser, a token admission accepts, and the
// lookup readers use returns it.
func TestProducerTableParsers(t *testing.T) {
	seen := map[admission.ProducerID]bool{}
	for _, p := range ProducerTable() {
		if seen[p.Spec.ID] {
			t.Errorf("%s listed twice", p.Spec.ID)
		}
		seen[p.Spec.ID] = true
		name := p.Parser.Name
		valid := len(name) > 0 && len(name) <= 64 && p.Parser.Version > 0
		for i := 0; i < len(name); i++ {
			valid = valid && name[i] >= 0x21 && name[i] <= 0x7e
		}
		if !valid {
			t.Errorf("%s: invalid parser %+v", p.Spec.ID, p.Parser)
		}
		if got, ok := ProducerParser(p.Spec.ID); !ok || got != p.Parser {
			t.Errorf("%s: lookup = %+v %v, want %+v", p.Spec.ID, got, ok, p.Parser)
		}
	}
	if _, ok := ProducerParser("no_such_producer"); ok {
		t.Error("an unknown producer has a parser")
	}
}

// Callers get a copy: changing it cannot change what the next caller sees.
func TestProducerTableIsACopy(t *testing.T) {
	first := ProducerTable()
	first[0].Spec.Checks[0] = "changed"
	first[0].Spec.Claims[0] = admission.ClaimRequestName
	first[0].Parser.Name = "changed"
	second := ProducerTable()
	if second[0].Spec.Checks[0] == "changed" || second[0].Parser.Name == "changed" || second[0].Spec.Claims[0] == admission.ClaimRequestName {
		t.Fatalf("table changed through a copy: %+v", second[0])
	}
}
