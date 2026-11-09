package admission

import (
	"strings"
	"testing"
)

// Parked findings keep these numbers: append, never renumber.
func TestAttributionVocabulary(t *testing.T) {
	want := []struct {
		kind Attribution
		n    uint8
		name string
	}{
		{AttributionUnknown, 0, "unknown"},
		{AttributionPeer, 1, "peer"},
		{AttributionHTTPPeer, 2, "http_peer"},
		{AttributionTrustedHTTPChain, 3, "trusted_http_chain"},
		{AttributionSocketDestination, 4, "socket_destination"},
		{AttributionDerived, 5, "derived"},
	}
	for _, w := range want {
		if uint8(w.kind) != w.n || w.kind.String() != w.name {
			t.Errorf("kind %d = %q, want %d %q", uint8(w.kind), w.kind.String(), w.n, w.name)
		}
		if w.kind.Valid() != (w.kind != AttributionUnknown) {
			t.Errorf("%s: Valid = %v", w.name, w.kind.Valid())
		}
	}
	if Attribution(6).Valid() || Attribution(6).String() != "attribution(6)" {
		t.Errorf("kind 6 = valid %v %q", Attribution(6).Valid(), Attribution(6).String())
	}
}

func TestAttributionSet(t *testing.T) {
	http := Attributions(AttributionHTTPPeer, AttributionTrustedHTTPChain)
	if !http.Has(AttributionHTTPPeer) || !http.Has(AttributionTrustedHTTPChain) || http.Has(AttributionPeer) {
		t.Fatalf("set %b membership is wrong", http)
	}
	if http.Has(AttributionUnknown) || AttributionSet(1).Has(AttributionUnknown) {
		t.Fatal("no set holds the unknown kind")
	}
	if !http.Valid() || !AttributionSet(0).Valid() {
		t.Fatal("a set of known kinds, or none, is valid")
	}
	for _, bad := range []AttributionSet{1, 1 << 6, 1 << 7} {
		if bad.Valid() {
			t.Errorf("set %b is valid", bad)
		}
	}
	if !Attributions(AttributionPeer).Within(Attributions(AttributionPeer, AttributionDerived)) ||
		Attributions(AttributionPeer, AttributionDerived).Within(Attributions(AttributionPeer)) || !AttributionSet(0).Within(0) {
		t.Fatal("Within is not subset")
	}
}

func TestRegisterRefusesAttributionOutsideTheCheckRow(t *testing.T) {
	reg := newRegistryWith(t, map[string]Policy{
		"ssh_brute": {Family: FamilySSH, Basis: BasisLocal, Attribution: Attributions(AttributionPeer)},
		"http_flood": {Family: FamilyHTTP, Basis: BasisLocal,
			Attribution: Attributions(AttributionHTTPPeer, AttributionTrustedHTTPChain)},
	})
	if _, err := reg.Register(ProducerSpec{ID: "sshd", Entry: EntryScan, Observation: ObservationLogCursor,
		Checks: []string{"ssh_brute"}, Attribution: Attributions(AttributionPeer)}); err != nil {
		t.Fatalf("declared kind inside the row: %v", err)
	}
	_, err := reg.Register(ProducerSpec{ID: "mixed", Entry: EntryScan, Observation: ObservationLogCursor,
		Checks: []string{"http_flood", "ssh_brute"}, Attribution: Attributions(AttributionHTTPPeer)})
	if err == nil || !strings.Contains(err.Error(), "attribution") {
		t.Fatalf("http_peer declared for ssh_brute registered: %v", err)
	}
	if _, err := reg.Register(ProducerSpec{ID: "proxy", Entry: EntryScan, Observation: ObservationLogCursor,
		Checks: []string{"http_flood"}, Attribution: Attributions(AttributionHTTPPeer, AttributionTrustedHTTPChain)}); err != nil {
		t.Fatalf("both HTTP kinds: %v", err)
	}
}

func TestRegisterRefusesAnUnknownAttribution(t *testing.T) {
	reg := newRegistryWith(t, map[string]Policy{
		"ssh_brute": {Family: FamilySSH, Basis: BasisLocal, Attribution: Attributions(AttributionPeer)},
	})
	for _, set := range []AttributionSet{1, 1 << 6} {
		if _, err := reg.Register(ProducerSpec{ID: "sshd", Entry: EntryScan, Observation: ObservationLogCursor,
			Checks: []string{"ssh_brute"}, Attribution: set}); err == nil {
			t.Errorf("set %b registered", set)
		}
	}
}

// A derived entry wraps roots others minted and declares no kind of its own.
func TestRegisterAcceptsAProducerWithoutAttribution(t *testing.T) {
	reg := newRegistryWith(t, map[string]Policy{
		"ssh_brute": {Family: FamilySSH, Basis: BasisLocal, Attribution: Attributions(AttributionPeer)},
	})
	if _, err := reg.Register(ProducerSpec{ID: "central", Entry: EntryCentral, Observation: ObservationEventSeq,
		Checks: []string{"ssh_brute"}}); err != nil {
		t.Fatal(err)
	}
	spec, _ := reg.Spec("central")
	if spec.Attribution != 0 {
		t.Fatalf("declared %b", spec.Attribution)
	}
}

func newRegistryWith(t *testing.T, policies map[string]Policy) *Registry {
	t.Helper()
	reg, err := NewRegistry(func(check string) (string, Policy, bool) {
		p, ok := policies[check]
		return check, p, ok
	})
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

// The policy lookup is outside admission; a row accepting a kind its family
// cannot carry, or an unknown kind, registers no producer.
func TestAttributionsPreservesInvalidKinds(t *testing.T) {
	for n := 0; n <= 255; n++ {
		kind := Attribution(n)
		if kind.Valid() {
			continue
		}
		if Attributions(kind).Valid() || Attributions(AttributionPeer, kind).Valid() {
			t.Errorf("invalid kind %d became a valid declaration", n)
		}
	}
}

func TestRegisterRefusesAPolicyAcceptingAKindOutsideItsFamily(t *testing.T) {
	for name, row := range map[string]AttributionSet{
		"http peer for ssh": Attributions(AttributionPeer, AttributionHTTPPeer),
		"unknown kind":      1,
		"kind past the end": 1 << 7,
		"missing kind":      0,
	} {
		reg := newRegistryWith(t, map[string]Policy{"ssh_brute": {Family: FamilySSH, Basis: BasisLocal, Attribution: row}})
		if _, err := reg.Register(ProducerSpec{ID: "sshd", Entry: EntryScan, Observation: ObservationLogCursor,
			Checks: []string{"ssh_brute"}}); err == nil {
			t.Errorf("%s: registered", name)
		}
	}
}
