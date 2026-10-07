package admissionowner

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/challenge"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

type funnelBlocker struct{ addresses []string }

func (b *funnelBlocker) BlockIP(ip, _ string, _ time.Duration) error {
	b.addresses = append(b.addresses, ip)
	return nil
}
func (*funnelBlocker) UnblockIP(string) error { return nil }
func (*funnelBlocker) IsBlocked(string) bool  { return false }

func TestFunnelHandsTheOwnerCanonicalAddressEvidence(t *testing.T) {
	for _, challenged := range []bool{false, true} {
		t.Run(map[bool]string{false: "block", true: "challenge"}[challenged], func(t *testing.T) {
			fixture := newOwnerFixture(t)
			opts := respondOptions(fixture)
			opts.ScheduleEvery = time.Hour
			o := fixture.start(opts)
			receiver, ok := any(o).(checks.ResponseAdmission)
			if !ok {
				t.Fatal("owner does not implement the response funnel")
			}
			checks.SetResponseAdmission(receiver)
			t.Cleanup(func() { checks.SetResponseAdmission(nil) })
			blocker := &funnelBlocker{}
			checks.SetIPBlocker(blocker)
			t.Cleanup(func() { checks.SetIPBlocker(nil) })
			list := challenge.NewIPList(filepath.Join(t.TempDir(), "challenge.txt"))
			checks.SetChallengeIPList(list)
			t.Cleanup(func() { checks.SetChallengeIPList(nil) })
			dryRun := false
			cfg := &config.Config{StatePath: fixture.statePath}
			cfg.AutoResponse.Enabled, cfg.AutoResponse.BlockIPs, cfg.AutoResponse.DryRun = true, true, &dryRun
			cfg.Challenge.Enabled = challenged
			at := fixture.host.now()
			finding := alert.Finding{
				Check: "wp_login_bruteforce", Severity: alert.Critical, Timestamp: at,
				Message:     "WordPress login brute force from 192.0.2.20: 100 attempts",
				Observation: alert.Observation{Producer: string(checks.ProducerAccessLog), Stream: "access", Cursor: "offset=1", ObservedAt: at},
			}
			checks.ChallengeThenBlock(cfg, []alert.Finding{finding})
			if err := o.do(o.drain); err != nil {
				t.Fatal(err)
			}
			kind := admission.KindBlockIP
			if challenged {
				kind = admission.KindChallenge
				if !list.Contains("192.0.2.20") || len(blocker.addresses) != 0 {
					t.Fatalf("legacy list=%d blocks=%v", list.Count(), blocker.addresses)
				}
			} else if len(blocker.addresses) != 1 || blocker.addresses[0] != "192.0.2.20" {
				t.Fatalf("legacy blocks=%v", blocker.addresses)
			}
			queued := queuedCandidates(t, o)
			if len(queued) != 1 || queued[0].Key.Kind != kind || queued[0].Key.Target.Key() != "ip:192.0.2.20" || queued[0].FindingID != alert.FindingID(finding) {
				t.Fatalf("queued=%+v", queued)
			}
			if n := o.ingress.Stats().Counters.Count(admission.CountKey{Event: admission.EventRefused, Reason: admission.ReasonInvalid}); n != 0 {
				t.Fatalf("valid legacy address caused %d invalid refusals", n)
			}
		})
	}
}
