package daemon

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// A crack after at least the per-address brute-force threshold of failures on
// its mailbox is marked as guessed, across spellings of the address; fewer
// failures look like an owner mistyping.
func TestMailCrackMarksBruteForce(t *testing.T) {
	for _, tc := range []struct {
		name     string
		spelling []string
		want     bool
	}{
		{"two failures", []string{"198.51.100.20", "198.51.100.20"}, false},
		{"below threshold", []string{"198.51.100.20", "198.51.100.20", "198.51.100.20", "198.51.100.20"}, false},
		{"at threshold", []string{"198.51.100.20", "198.51.100.20", "198.51.100.20", "198.51.100.20", "198.51.100.20"}, true},
		{"spellings combined", []string{"198.51.100.20", "198.51.100.20", "198.51.100.20", "::ffff:198.51.100.20", "::ffff:198.51.100.20"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := &staticClock{t: time.Now().UTC().Truncate(time.Second)}
			tr := newTestMailTracker(t, clock)
			for _, ip := range tc.spelling {
				tr.Record(ip, "user@example.com")
				clock.advance(time.Second)
			}
			f := findCheck(tr.recordSuccessAt("198.51.100.20", "user@example.com", clock.Now(), knownCustomerIMAP, true), "mail_account_compromised")
			if f == nil || f.Severity != alert.Critical || f.BruteForced != tc.want {
				t.Fatalf("crack = %s, want Critical with BruteForced %v", fmt.Sprint(f), tc.want)
			}
		})
	}
}
