package admissionowner

import (
	"errors"
	"reflect"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
)

// An isolated retry cannot hide other picks from an apply probe's checks.
// Refusals end, the first accepted pick runs alone, and other accepts wait.
func TestOwnerApplyProbeChecksPicksBesideIsolatedRetry(t *testing.T) {
	for _, refuseRetry := range []bool{false, true} {
		name := "accepted_retry"
		if refuseRetry {
			name = "refused_retry"
		}
		t.Run(name, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			blocks.reject = 1
			o := f.start(executeOptions(f, blocks))
			mono := heldMono(t, o)
			ids := map[string]admission.CandidateID{}
			for _, ip := range []string{"192.0.2.10", "192.0.2.11"} {
				ids[ip], _ = queuedAt(t, o, p, f.host, admission.SeverityHigh, ip)
			}
			if err := o.do(o.turn); err != nil {
				t.Fatal(err)
			}
			if n := isolatedCount(t, o); n != 2 {
				t.Fatalf("isolated retries = %d, want 2", n)
			}

			// One retry fails in transport while its peer stays isolated.
			blocks.set(func(b *fakeBlocks) { b.applyErr = errors.New("transport unavailable") })
			mono.advance(admission.RetryBackoff(1))
			f.host.advance(admission.RetryBackoff(1))
			if err := o.do(o.turn); err != nil {
				t.Fatal(err)
			}
			if n := isolatedCount(t, o); n != 1 || executionHeld(t, o) == "" {
				t.Fatalf("isolated retries = %d, held = %q", n, executionHeld(t, o))
			}
			retryIP := ""
			for ip, id := range ids {
				if candidate(t, o, id).Attempts == 1 {
					retryIP = ip
				}
			}
			if retryIP == "" {
				t.Fatal("missing untouched isolated retry")
			}
			for _, ip := range []string{"192.0.2.12", "192.0.2.13", "192.0.2.14"} {
				ids[ip], _ = queuedAt(t, o, p, f.host, admission.SeverityHigh, ip)
			}
			blocks.set(func(b *fakeBlocks) {
				b.applyErr = nil
				b.refuse["192.0.2.14"] = firewall.BlockRefusedProtected
				if refuseRetry {
					b.refuse[retryIP] = firewall.BlockRefusedProtected
				}
			})
			before := map[string]admission.Candidate{}
			for ip, id := range ids {
				before[ip] = candidate(t, o, id)
			}
			mono.advance(firstProbeWait)
			f.host.advance(firstProbeWait)
			if err := o.do(o.turn); err != nil {
				t.Fatal(err)
			}
			checks, applies := blocks.calls()
			if len(checks) != 3 || len(checks[2]) != 4 {
				t.Fatalf("probe checks = %v, want all four ready picks", checks)
			}
			firstAccepted := ""
			for _, member := range checks[2] {
				refused := member.IP == "192.0.2.14" || (refuseRetry && member.IP == retryIP)
				if !refused && firstAccepted == "" {
					firstAccepted = member.IP
				}
			}
			if firstAccepted == "" || len(applies) != 3 || len(applies[2]) != 1 || applies[2][0].IP != firstAccepted {
				t.Fatalf("probe applies = %v, want only %s", applies, firstAccepted)
			}
			for ip, id := range ids {
				got := candidate(t, o, id)
				switch {
				case ip == "192.0.2.14" || (refuseRetry && ip == retryIP):
					if got.State != admission.StateRefused || got.Reason != admission.ReasonProtected || got.Attempts != before[ip].Attempts {
						t.Errorf("refused pick %s = %+v", ip, got)
					}
				case ip == firstAccepted:
					if got.State != admission.StateVerified || got.Attempts != before[ip].Attempts+1 {
						t.Errorf("probe member %s = %+v", ip, got)
					}
				default:
					if !reflect.DeepEqual(got, before[ip]) {
						t.Errorf("waiting pick %s changed: before %+v, after %+v", ip, before[ip], got)
					}
				}
			}
			if held := executionHeld(t, o); held != "" {
				t.Fatalf("applied probe kept its hold: %q", held)
			}
		})
	}
}
