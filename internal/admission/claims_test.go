package admission

import (
	"slices"
	"testing"
)

// ownerClaims turns a resolved owner back into the claim and the one-account
// inventory that resolve to exactly that owner, so fixtures can keep naming
// owners, retired generations included.
func ownerClaims(t testing.TB, o Owner) ([]Claim, *Inventory) {
	t.Helper()
	if o.IsHost() {
		return nil, nil
	}
	inv, err := NewInventory(map[string]uint64{o.account: o.generation}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return []Claim{{ClaimAccount, o.account}}, inv
}

func claimProducer(t *testing.T, kinds ...ClaimKind) *Producer {
	t.Helper()
	reg, err := NewRegistry(testLookup)
	if err != nil {
		t.Fatal(err)
	}
	p, err := reg.Register(ProducerSpec{ID: "claims", Entry: EntryScan, Observation: ObservationLogCursor, Checks: []string{"ssh_brute"}, Claims: kinds})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// A producer declares where its ownership claims come from. The declaration
// is a set of known kinds, stored sorted.
func TestRegisterValidatesClaimKinds(t *testing.T) {
	reg, _ := NewRegistry(testLookup)
	p, err := reg.Register(ProducerSpec{ID: "domains", Entry: EntryScan, Observation: ObservationLogCursor, Checks: []string{"http_scan"}, Claims: []ClaimKind{ClaimRequestName, ClaimDomain}})
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := reg.Spec(p.ID())
	if !slices.Equal(spec.Claims, []ClaimKind{ClaimDomain, ClaimRequestName}) {
		t.Fatalf("stored claims %v, want sorted domain and request name", spec.Claims)
	}
	spec.Claims[0] = ClaimAccount
	if again, _ := reg.Spec(p.ID()); again.Claims[0] != ClaimDomain {
		t.Fatal("a caller changed the registered claims through Spec")
	}
	for name, kinds := range map[string][]ClaimKind{
		"zero kind":     {0},
		"unknown kind":  {ClaimRequestName + 1},
		"repeated kind": {ClaimDomain, ClaimDomain},
	} {
		if _, err := reg.Register(ProducerSpec{ID: "bad", Entry: EntryScan, Observation: ObservationLogCursor, Checks: []string{"ssh_brute"}, Claims: kinds}); err == nil {
			t.Errorf("%s: registered", name)
		}
	}
}

// Mint resolves the owner itself from the finding's claims over the
// inventory; a claim of a kind the producer did not declare is refused, so a
// producer cannot launder a client-chosen name into a server-owned claim.
func TestMintResolvesOnlyDeclaredClaims(t *testing.T) {
	inv := testInventory(t)
	for _, c := range []struct {
		name     string
		declared []ClaimKind
		claims   []Claim
		inv      *Inventory
		want     string
		refused  bool
	}{
		{"domain claim", []ClaimKind{ClaimDomain}, []Claim{{ClaimDomain, "shop.bob.example"}}, inv, "acct:bob#2", false},
		{"account claim", []ClaimKind{ClaimAccount}, []Claim{{ClaimAccount, "alice"}}, inv, "acct:alice#1", false},
		{"request name never verifies", []ClaimKind{ClaimRequestName}, []Claim{{ClaimRequestName, "alice.example"}}, inv, "host", false},
		{"undeclared with no inventory", []ClaimKind{ClaimDomain}, []Claim{{ClaimAccount, "alice"}}, nil, "", true},
		{"mailbox never verifies", []ClaimKind{ClaimMailbox}, []Claim{{ClaimMailbox, "alice"}}, inv, "host", false},
		{"conflicting accounts", []ClaimKind{ClaimAccount, ClaimDomain}, []Claim{{ClaimAccount, "alice"}, {ClaimDomain, "bob.example"}}, inv, "host", false},
		{"no inventory", []ClaimKind{ClaimAccount}, []Claim{{ClaimAccount, "alice"}}, nil, "host", false},
		{"no claims", []ClaimKind{ClaimAccount}, nil, inv, "host", false},
		{"undeclared kind", []ClaimKind{ClaimDomain}, []Claim{{ClaimAccount, "alice"}}, inv, "", true},
		{"nothing declared", nil, []Claim{{ClaimDomain, "alice.example"}}, inv, "", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			in := sshInput(t)
			in.Claims, in.Inventory = c.claims, c.inv
			e, err := claimProducer(t, c.declared...).Mint(in)
			if c.refused {
				wantReason(t, c.name, err, ReasonPolicy)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := e.Owner().Key(); got != c.want {
				t.Fatalf("owner %s, want %s", got, c.want)
			}
		})
	}
}
