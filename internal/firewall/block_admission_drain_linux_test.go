//go:build linux

package firewall

import (
	"testing"
	"time"

	"github.com/google/nftables"
)

// Both families must report time left at the end of collection, including
// member checks. A wall-clock step must not change a kernel timeout.
func TestBlockAdmissionSnapshotAgesDrain(t *testing.T) {
	for _, tc := range []struct {
		name       string
		checkDelay time.Duration
		wallStep   time.Duration
		unknown    bool
		want       time.Duration
	}{
		{name: "second family", want: 8 * time.Second},
		{name: "member check", checkDelay: 3 * time.Second, want: 5 * time.Second},
		{name: "second family drains last", checkDelay: 3 * time.Second, want: 7 * time.Second},
		{name: "wall back", checkDelay: 3 * time.Second, wallStep: -time.Hour, want: 5 * time.Second},
		{name: "wall forward", checkDelay: 3 * time.Second, wallStep: time.Hour, want: 5 * time.Second},
		{name: "elapsed", checkDelay: 10 * time.Second, want: 0},
		{name: "unknown", checkDelay: 10 * time.Second, unknown: true, want: -time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newBatchFixture(t, FirewallState{})
			clock := &leaseSteps{wall: f.at, elapsed: f.at}
			f.e.leaseClock, f.e.expiryClock = clock.read, func() time.Time { return clock.wall }
			f.live["203.0.113.90"] = time.Minute
			f.live["2001:db8::90"] = time.Minute
			f.expires["203.0.113.90"] = 10 * time.Second
			f.expires["2001:db8::90"] = 6 * time.Second
			if tc.name == "second family drains last" {
				f.expires["203.0.113.90"], f.expires["2001:db8::90"] = 3*time.Second, 10*time.Second
			}
			if tc.unknown {
				f.expires["203.0.113.90"] = 0
			}
			dump := f.e.liveBlockedDump
			f.e.liveBlockedDump = func(set *nftables.Set) ([]nftables.SetElement, error) {
				if set == f.e.setBlocked6 {
					clock.advance(2 * time.Second)
				}
				return dump(set)
			}
			checks := 0
			f.e.localAddrsLookup = func() ([]string, error) {
				checks++
				clock.advance(tc.checkDelay)
				clock.step(tc.wallStep)
				return nil, nil
			}
			got, err := f.e.BlockAdmissionSnapshot([]BlockMember{f.member("act_new", "203.0.113.91")}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if checks != 1 || len(got.Answers) != 1 || got.Answers[0].Refusal != "" {
				t.Fatalf("member checks = %d, answers = %+v", checks, got.Answers)
			}
			if got.Temporary != 2 || got.Unclaimed != 2 || got.Admission != 0 || got.Imported != 0 || got.Drain != tc.want {
				t.Fatalf("snapshot = %+v; want two unclaimed occupants, drain %s", got, tc.want)
			}
		})
	}
}
