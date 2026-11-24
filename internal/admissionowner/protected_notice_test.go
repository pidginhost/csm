package admissionowner

import (
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
)

func TestOwnerProtectedBlockNotice(t *testing.T) {
	for _, refusal := range []firewall.BlockRefusal{firewall.BlockRefusedProtected, firewall.BlockRefusedAllowed} {
		for _, phase := range []string{"check", "final apply"} {
			t.Run(string(refusal)+"/"+phase, func(t *testing.T) {
				p := withTestRegistry(t)
				f := newOwnerFixture(t)
				blocks := newFakeBlocks()
				const ip = "192.0.2.10"
				if phase == "check" {
					blocks.refuse[ip] = refusal
				} else {
					blocks.results[ip] = firewall.BlockResult{Effect: firewall.BlockFailed}
				}
				o := f.start(executeOptions(f, blocks))
				mono := heldMono(t, o)
				id, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, ip)
				if phase == "final apply" {
					for seq := uint32(1); seq < admission.MaxAttempts; seq++ {
						turn(t, o)
						wait := admission.RetryBackoff(seq)
						mono.advance(wait)
						f.host.advance(wait)
					}
					blocks.set(func(b *fakeBlocks) {
						b.results[ip] = firewall.BlockResult{Effect: firewall.BlockFailed, Refusal: refusal}
					})
				}
				turn(t, o)
				c := candidate(t, o, id)
				if phase == "check" {
					if c.State != admission.StateRefused || c.Reason != admission.ReasonProtected || c.Attempts != 0 {
						t.Fatalf("refused candidate = %+v", c)
					}
				} else if c.State != admission.StateFailed || c.Attempts != admission.MaxAttempts {
					t.Fatalf("final attempt = %+v", c)
				}
				status := ledgerStatus(t, o)
				n := status.Notices
				if n.Error != "" || !n.LastCriticalGap.IsZero() || len(n.Records) != 1 {
					t.Fatalf("notices = %+v, want only the protected refusal", n)
				}
				r := n.Records[0]
				if r.Kind != admission.NoticeWithheld.String() || r.Reason != admission.ReasonProtected.String() ||
					r.Check != "ssh_brute" || r.Effect != admission.EffectAddress.String() || r.Count != 1 {
					t.Fatalf("withheld notice = %+v", r)
				}
			})
		}
	}
}
