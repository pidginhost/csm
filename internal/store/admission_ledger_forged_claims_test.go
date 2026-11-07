package store

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// Claims a detector read from attacker-controlled text cannot mint scopes:
// a flood naming accounts the server does not own, across checks, lands in
// the one host scope, so a real account's work keeps its turn (spec 7.1,
// queue overflow: ownership cannot be forged; other scopes keep shares).
func TestAdmissionLedgerForgedClaimsShareOneScope(t *testing.T) {
	f := newLedgerFixture(t)
	f.refresh([]string{"alice", "bob", "zoe"}, nil)
	f.begin()
	scopes := map[string]bool{}
	for i := 0; i < 6; i++ {
		producer, check := f.ssh, "ssh_brute"
		var intel *admission.IntelRef
		if i%2 == 1 {
			producer, check = f.rep, "reputation"
			intel = &admission.IntelRef{Source: "feed", Expires: f.wall.Add(30 * time.Hour)}
		}
		target := fmt.Sprintf("192.0.2.%d", 20+i)
		e, err := producer.Mint(admission.EvidenceInput{
			Check: check, FindingID: "0123456789abcdef", Severity: admission.SeverityCritical,
			Observation: admission.ObservationRef{Stream: "log:" + string(producer.ID()), Cursor: fmt.Sprintf("forged=%d", i), Version: 1},
			ObservedAt:  f.wall, Parser: admission.ParserRef{Name: "fixture", Version: 1}, Target: f.target(target),
			Claims:    []admission.Claim{{Kind: admission.ClaimAccount, Value: fmt.Sprintf("ghost%d", i)}},
			Inventory: f.l.Inventory(), Intel: intel,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !e.Owner().IsHost() {
			t.Fatalf("a forged claim minted owner %s", e.Owner().Key())
		}
		req := f.request(target, e.ID())
		req.Episode, req.Generation = admission.EpisodeID{}, 0
		r := f.arrive(admission.Arrival{Request: req, Evidence: e})[0]
		if r.Err != nil || !r.Created {
			t.Fatalf("forged arrival %d = %+v", i, r)
		}
		c := f.candidateOf(r.Candidate)
		if !c.Scope.Owner.IsHost() {
			t.Fatalf("a forged claim minted owner %s", c.Scope.Key())
		}
		scopes[c.Scope.Key()] = true
	}
	if len(scopes) != 1 {
		t.Fatalf("forged claims made %d scopes: %v", len(scopes), scopes)
	}
	// Keep both scopes backlogged in each class. The account scope sorts
	// first, so its first pick alone cannot prove rotation past the flood.
	owner := f.owner("zoe")
	zoe := f.fill(3, evidenceSpec{owner: owner, severity: admission.SeverityCritical})
	zoe = append(zoe, f.fill(3, evidenceSpec{producer: f.rep, check: "reputation", owner: owner, severity: admission.SeverityCritical})...)
	turns := map[admission.Class][]string{}
	for range 12 {
		picks := f.schedule(oneEach)
		if len(picks) != 1 {
			t.Fatalf("picks = %+v", picks)
		}
		pick := picks[0]
		turns[pick.Tier.Class] = append(turns[pick.Tier.Class], f.scopeOf(pick.ID))
		if _, _, _, err := f.l.Reserve(picks[0].ID, picks[0].Lane, f.wall.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	accountScope := (admission.Scope{Owner: owner, Effect: admission.KindBlockIP.Effect()}).Key()
	hostScope := (admission.Scope{Owner: admission.HostOwner(), Effect: admission.KindBlockIP.Effect()}).Key()
	want := []string{accountScope, hostScope, accountScope, hostScope, accountScope, hostScope}
	for _, class := range []admission.Class{admission.ClassC1, admission.ClassC2} {
		if !slices.Equal(turns[class], want) {
			t.Fatalf("%s scope turns = %v, want %v", class, turns[class], want)
		}
	}
	for _, id := range zoe {
		if c := f.candidateOf(id); c.State != admission.StateReserved || c.Attempts != 1 {
			t.Fatalf("real account was not admitted: %+v", c)
		}
	}
	if used := f.ceilingState().General.Used; used != 12 || f.attemptRows() != 12 {
		t.Fatalf("forged flood charges=%d attempts=%d, want 12 each", used, f.attemptRows())
	}
}
