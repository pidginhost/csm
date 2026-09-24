package admission

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"
)

func testInventory(t *testing.T) *Inventory {
	t.Helper()
	inv, err := NewInventory(
		map[string]uint64{"alice": 1, "bob": 2},
		map[string]string{"alice.example": "alice", "bob.example": "bob", "shop.bob.example": "bob"},
	)
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func TestResolveVerifiesOnlyServerOwnedClaims(t *testing.T) {
	inv := testInventory(t)
	cases := []struct {
		name   string
		claims []Claim
		want   string
	}{
		{"no claim", nil, "host"},
		{"account", []Claim{{ClaimAccount, "alice"}}, "acct:alice#1"},
		{"unknown account", []Claim{{ClaimAccount, "mallory"}}, "host"},
		{"hosted domain", []Claim{{ClaimDomain, "Shop.Bob.Example."}}, "acct:bob#2"},
		{"foreign domain", []Claim{{ClaimDomain, "victim.example"}}, "host"},
		{"mailbox alone", []Claim{{ClaimMailbox, "user@alice.example"}}, "host"},
		{"host header alone", []Claim{{ClaimRequestName, "alice.example"}}, "host"},
		{"agreeing claims", []Claim{{ClaimAccount, "bob"}, {ClaimDomain, "bob.example"}}, "acct:bob#2"},
		{"unverifiable claim ignored", []Claim{{ClaimRequestName, "alice.example"}, {ClaimAccount, "bob"}}, "acct:bob#2"},
		{"two accounts", []Claim{{ClaimAccount, "alice"}, {ClaimDomain, "bob.example"}}, "host"},
		{"two accounts then agreement", []Claim{{ClaimAccount, "alice"}, {ClaimAccount, "bob"}, {ClaimAccount, "alice"}}, "host"},
	}
	for _, tc := range cases {
		if got := inv.Resolve(tc.claims...).Key(); got != tc.want {
			t.Errorf("%s: Resolve = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestOwnerCurrentDetectsRecreatedAccounts(t *testing.T) {
	inv := testInventory(t)
	alice := inv.Resolve(Claim{ClaimAccount, "alice"})
	recreated, err := NewInventory(map[string]uint64{"alice": 3, "bob": 2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	gone, _ := NewInventory(map[string]uint64{"bob": 2}, nil)
	if !inv.Current(alice) || recreated.Current(alice) || gone.Current(alice) {
		t.Error("Current does not track the owner's generation")
	}
	if !gone.Current(HostOwner()) {
		t.Error("the host owner is not current")
	}
}

func TestScopeKeys(t *testing.T) {
	inv := testInventory(t)
	if got := (Scope{Owner: inv.Resolve(Claim{ClaimAccount, "bob"}), Effect: EffectAddress}).Key(); got != "acct:bob#2/address" {
		t.Errorf("account scope key = %q", got)
	}
	if got := (Scope{Owner: HostOwner(), Effect: EffectService}).Key(); got != "host/service" {
		t.Errorf("host scope key = %q", got)
	}
}

func TestNewInventoryRejectsInconsistentInput(t *testing.T) {
	cases := map[string]struct {
		accounts map[string]uint64
		domains  map[string]string
	}{
		"zero generation":    {map[string]uint64{"alice": 0}, nil},
		"bad name":           {map[string]uint64{"a/b": 1}, nil},
		"dot name":           {map[string]uint64{"..": 1}, nil},
		"orphan domain":      {map[string]uint64{"alice": 1}, map[string]string{"x.example": "bob"}},
		"uncanonical domain": {map[string]uint64{"alice": 1}, map[string]string{"X.example": "alice"}},
		"empty domain":       {map[string]uint64{"alice": 1}, map[string]string{"": "alice"}},
	}
	for name, tc := range cases {
		if _, err := NewInventory(tc.accounts, tc.domains); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	src := map[string]uint64{"alice": 1}
	inv, _ := NewInventory(src, nil)
	src["mallory"] = 9
	if inv.Resolve(Claim{ClaimAccount, "mallory"}) != HostOwner() {
		t.Error("the inventory aliases its input map")
	}
}

func TestGenerationsNeverReuseAndTrackRecreation(t *testing.T) {
	g := NewGenerations()
	first, err := g.Observe([]string{"bob", "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if first["alice"] != 1 || first["bob"] != 2 {
		t.Fatalf("first observation = %v, want sorted assignment alice=1 bob=2", first)
	}
	same, _ := g.Observe([]string{"alice", "bob", "alice"})
	if same["alice"] != 1 || same["bob"] != 2 {
		t.Fatalf("a stable account changed generation: %v", same)
	}
	gone, _ := g.Observe([]string{"bob"})
	if _, ok := gone["alice"]; ok || gone["bob"] != 2 {
		t.Fatalf("removal = %v", gone)
	}
	back, _ := g.Observe([]string{"alice", "bob"})
	if back["alice"] != 3 {
		t.Fatalf("a recreated account reused generation %d", back["alice"])
	}
	back["alice"] = 99
	if again, _ := g.Observe([]string{"alice", "bob"}); again["alice"] != 3 {
		t.Error("Observe returns its internal map")
	}
	if _, err := g.Observe([]string{"ok", "bad/name"}); err == nil {
		t.Error("an invalid name was observed")
	}
}

func TestGenerationsRoundTripAndRefuseCorruption(t *testing.T) {
	g := NewGenerations()
	if _, err := g.Observe([]string{"alice", "bob"}); err != nil {
		t.Fatal(err)
	}
	data, err := g.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var restored Generations
	if err := restored.UnmarshalBinary(data); err != nil {
		t.Fatal(err)
	}
	next, _ := restored.Observe([]string{"alice", "carol"})
	if next["alice"] != 1 || next["carol"] != 3 {
		t.Fatalf("restored tracker = %v, want alice=1 carol=3", next)
	}
	flipped := append([]byte(nil), data...)
	flipped[2] ^= 1
	bodies := map[string][]byte{
		"truncated":          data[:4],
		"flipped":            flipped,
		"reused generation":  sealGenerations(t, `{"v":1,"next":3,"live":{"alice":1,"bob":1}}`),
		"generation >= next": sealGenerations(t, `{"v":1,"next":2,"live":{"alice":2}}`),
		"zero next":          sealGenerations(t, `{"v":1,"next":0,"live":{}}`),
		"null inventory":     sealGenerations(t, `{"v":1,"next":3,"live":null}`),
		"future version":     sealGenerations(t, `{"v":2,"next":1,"live":{}}`),
		"unknown field":      sealGenerations(t, `{"v":1,"next":1,"live":{},"x":1}`),
		"bad name":           sealGenerations(t, `{"v":1,"next":2,"live":{"a/b":1}}`),
		"trailing delimiter": sealGenerations(t, `{"v":1,"next":1,"live":{}}]`),
		"duplicate key":      sealGenerations(t, `{"v":1,"next":1,"next":2,"live":{}}`),
		"trailing value":     sealGenerations(t, `{"v":1,"next":1,"live":{}}{}`),
	}
	for name, b := range bodies {
		var g2 Generations
		if err := g2.UnmarshalBinary(data); err != nil {
			t.Fatal(err)
		}
		if err := g2.UnmarshalBinary(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
		after, err := g2.MarshalBinary()
		if err != nil || !bytes.Equal(after, data) {
			t.Errorf("%s: refused restore changed tracker: %v", name, err)
		}
	}
}

func TestUninitializedGenerationsRefuseUse(t *testing.T) {
	for _, names := range [][]string{nil, {"alice"}} {
		t.Run(strings.Join(names, ","), func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("uninitialized tracker panicked: %v", r)
				}
			}()
			var g Generations
			if _, err := g.Observe(names); err == nil {
				t.Error("uninitialized tracker accepted an observation")
			}
			if _, err := g.MarshalBinary(); err == nil {
				t.Error("uninitialized tracker encoded unusable state")
			}
			if g.next != 0 || g.live != nil {
				t.Error("refusal changed the uninitialized tracker")
			}
		})
	}
}

func TestOwnershipErrorsNeverEchoInput(t *testing.T) {
	const marker = "untrusted_marker"
	cases := map[string]func() error{
		"account": func() error {
			_, err := NewInventory(map[string]uint64{marker + "/": 1}, nil)
			return err
		},
		"domain spelling": func() error {
			_, err := NewInventory(nil, map[string]string{marker + ".EXAMPLE": "alice"})
			return err
		},
		"domain owner": func() error {
			_, err := NewInventory(nil, map[string]string{marker + ".example": "alice"})
			return err
		},
		"unknown field": func() error {
			return NewGenerations().UnmarshalBinary(sealGenerations(t, `{"v":1,"next":1,"live":{},"`+marker+`":1}`))
		},
		"wrong field type": func() error {
			return NewGenerations().UnmarshalBinary(sealGenerations(t, `{"v":1,"next":1,"live":{"`+marker+`":[]}}`))
		},
	}
	for name, call := range cases {
		if err := call(); err == nil || strings.Contains(err.Error(), marker) {
			t.Errorf("%s: expected a refusal without input text, got %v", name, err)
		}
	}
}

func sealGenerations(t *testing.T, body string) []byte {
	t.Helper()
	sum := sha256.Sum256([]byte(body))
	return append([]byte(body), sum[:8]...)
}

func TestGenerationsRefusalPreservesState(t *testing.T) {
	g := NewGenerations()
	if _, err := g.Observe([]string{"alice"}); err != nil {
		t.Fatal(err)
	}
	before, err := g.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err = g.UnmarshalBinary(sealGenerations(t, `{"v":1,"next":0,"live":{}}`)); err == nil {
		t.Fatal("corrupt tracker accepted")
	}
	if _, err = g.Observe([]string{"bob", "bad/name"}); err == nil {
		t.Fatal("invalid observation accepted")
	}
	after, err := g.MarshalBinary()
	if err != nil || string(after) != string(before) {
		t.Fatalf("refusal changed tracker: %v", err)
	}
	if err = g.UnmarshalBinary(sealGenerations(t, `{"v":1,"next":18446744073709551615,"live":{"alice":1}}`)); err != nil {
		t.Fatal(err)
	}
	before, err = g.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = g.Observe([]string{"bob"}); err == nil {
		t.Fatal("exhausted generation counter accepted")
	}
	after, err = g.MarshalBinary()
	if err != nil || string(after) != string(before) {
		t.Fatalf("counter exhaustion changed tracker: %v", err)
	}
}

func TestClaimValuesAreFrozen(t *testing.T) {
	for name, pair := range map[string][2]uint8{"ClaimAccount": {uint8(ClaimAccount), 1}, "ClaimDomain": {uint8(ClaimDomain), 2}, "ClaimMailbox": {uint8(ClaimMailbox), 3}, "ClaimRequestName": {uint8(ClaimRequestName), 4}} {
		if pair[0] != pair[1] {
			t.Errorf("%s = %d, frozen at %d", name, pair[0], pair[1])
		}
	}
}
