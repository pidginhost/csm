package incident

import (
	"net"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestIncidentBlockRetainsTriggeringFindingIdentity(t *testing.T) {
	for _, spray := range []bool{false, true} {
		t.Run(map[bool]string{false: "incident", true: "spray"}[spray], func(t *testing.T) {
			calls := 0
			var capturedID string
			c, f := blockLifecycleCorrelator(t, spray, func(_, _ string, _ time.Duration, id string) bool { calls++; capturedID = id; return true })
			id, _, err := c.OnFinding(f)
			if err != nil {
				t.Fatal(err)
			}
			inc, ok := c.Get(id)
			if !ok || calls != 1 {
				t.Fatalf("incident block was not requested: id=%s calls=%d", id, calls)
			}
			want := alert.FindingID(f)
			if capturedID != want {
				t.Errorf("block callback lost source identity: %q, want %s", capturedID, want)
			}
			if len(inc.Timeline) == 0 || inc.Timeline[len(inc.Timeline)-1].FindingID != want {
				t.Fatal("incident discarded the triggering audit identity")
			}
		})
	}
}

func TestIncidentBlockAttributesEquivalentIPSpellings(t *testing.T) {
	for _, spray := range []bool{false, true} {
		for _, sourceIP := range []string{"2001:0db8::10", "::ffff:192.0.2.10"} {
			t.Run(map[bool]string{false: "incident", true: "spray"}[spray]+"/"+sourceIP, func(t *testing.T) {
				calls := 0
				var capturedID string
				c, f := blockLifecycleCorrelator(t, spray, func(_, _ string, _ time.Duration, id string) bool { calls++; capturedID = id; return true })
				inc, ok := c.Get("inc_ladder")
				if !ok {
					t.Fatal("missing restored incident")
				}
				canonicalIP := net.ParseIP(sourceIP).String()
				inc.CorrelationKey = &Key{RemoteIP: canonicalIP}
				if spray {
					// Spray bindings retain the source spelling across restart.
					inc.CorrelationKey.RemoteIP = sourceIP
				}
				inc.Timeline[0].RemoteIP = canonicalIP
				c.Restore([]Incident{inc})
				f.SourceIP = sourceIP
				_, _, err := c.OnFinding(f)
				if err != nil || calls != 1 {
					t.Fatalf("block calls=%d error=%v", calls, err)
				}
				if want := alert.FindingID(f); capturedID != want {
					t.Errorf("equivalent IP spelling lost source identity: got %q, want %s", capturedID, want)
				}
			})
		}
	}
}
