package store

import (
	"fmt"
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
	// zoe's scope sorts after any forged account would, so only one shared
	// forged scope leaves her a turn within two picks.
	zoe := f.fill(1, evidenceSpec{owner: f.owner("zoe"), severity: admission.SeverityCritical})[0]
	served := false
	for range 2 {
		picks := f.schedule(oneEach)
		if len(picks) != 1 {
			t.Fatalf("picks = %+v", picks)
		}
		served = served || picks[0].ID == zoe
		if _, _, _, err := f.l.Reserve(picks[0].ID, picks[0].Lane, f.wall.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if !served {
		t.Fatal("a real account's work waited behind the forged flood's second turn")
	}
	if c := f.candidateOf(zoe); c.State != admission.StateReserved || c.Attempts != 1 {
		t.Fatalf("real account was not admitted: %+v", c)
	}
	if used := f.ceilingState().General.Used; used != 2 || f.attemptRows() != 2 {
		t.Fatalf("forged flood charges=%d attempts=%d, want 2 each", used, f.attemptRows())
	}
}
