package incident

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// Response findings record what CSM did, not what an attacker did. Keying one
// on a remote IP lets CSM's own output re-enter the decision path: the
// auto-block chokepoint started setting SourceIP on its findings, and that
// alone was enough to open an incident on the IP that had just been blocked,
// which the incident hand-off could then ask to block again.
//
// auto_response and challenge_route do not carry SourceIP today, so they are
// inert by accident rather than by rule. Pin the rule, because adding
// SourceIP to them later is an obvious-looking improvement that would
// silently rebuild the loop.
func TestKeyForIgnoresResponseFindings(t *testing.T) {
	for _, check := range []string{
		"auto_block",
		"auto_response",
		"challenge_route",
		"reputation_quota_exhausted",
		"threat_feed_stale",
	} {
		t.Run(check, func(t *testing.T) {
			f := alert.Finding{
				Check:     check,
				Severity:  alert.Critical,
				Message:   "response action recorded",
				SourceIP:  "203.0.113.7",
				CPUser:    "acct1",
				Domain:    "example.com",
				Timestamp: time.Unix(1_700_000_000, 0),
			}
			if key := KeyFor(f); !key.IsEmpty() {
				t.Errorf("KeyFor(%s) = %+v, want an empty key so the correlator ignores it", check, key)
			}
		})
	}
}

// The guard must stay narrow: a real detection finding on the same IP still
// has to correlate, or suppressing response noise would blind the correlator.
func TestKeyForStillCorrelatesDetectionFindings(t *testing.T) {
	f := alert.Finding{
		Check:     "wp_login_bruteforce",
		Severity:  alert.Critical,
		Message:   "brute force from 203.0.113.7",
		SourceIP:  "203.0.113.7",
		Timestamp: time.Unix(1_700_000_000, 0),
	}
	key := KeyFor(f)
	if key.IsEmpty() {
		t.Fatal("a detection finding must still produce a correlation key")
	}
	if key.RemoteIP != "203.0.113.7" {
		t.Errorf("RemoteIP = %q, want the attacker IP", key.RemoteIP)
	}
}
