package admissionowner

import (
	"fmt"
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
	// The finding is an HTTP peer from a web server that logs it directly.
	prev := checks.CurrentHTTPRewrite()
	checks.SetHTTPRewrite(checks.HTTPRewrite{State: checks.RewriteNone})
	t.Cleanup(func() { checks.SetHTTPRewrite(prev) })
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
				Check: "wp_login_bruteforce", Severity: alert.Critical, Timestamp: at, SourceIP: "192.0.2.20",
				Attribution: admission.AttributionHTTPPeer,
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

// A victim named only in the message never becomes an admission target:
// the legacy path still reads the message, but
// admission refuses the finding its parser vouched for no address in.
func TestFunnelNeverAimsAdmissionAtMessageText(t *testing.T) {
	fixture := newOwnerFixture(t)
	opts := respondOptions(fixture)
	opts.ScheduleEvery = time.Hour
	o := fixture.start(opts)
	checks.SetResponseAdmission(o)
	t.Cleanup(func() { checks.SetResponseAdmission(nil) })
	blocker := &funnelBlocker{}
	checks.SetIPBlocker(blocker)
	t.Cleanup(func() { checks.SetIPBlocker(nil) })
	checks.SetChallengeIPList(nil)
	dryRun := false
	cfg := &config.Config{StatePath: fixture.statePath}
	cfg.AutoResponse.Enabled, cfg.AutoResponse.BlockIPs, cfg.AutoResponse.DryRun = true, true, &dryRun
	at := fixture.host.now()
	injected := alert.Finding{
		Check: "wp_login_bruteforce", Severity: alert.Critical, Timestamp: at,
		Message:     "WordPress login brute force from 198.51.100.66: 100 attempts",
		Observation: alert.Observation{Producer: string(checks.ProducerAccessLog), Stream: "access", Cursor: "offset=1", ObservedAt: at},
	}
	checks.ChallengeThenBlock(cfg, []alert.Finding{injected})
	if err := o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	if len(blocker.addresses) != 1 || blocker.addresses[0] != "198.51.100.66" {
		t.Fatalf("legacy blocks=%v; the test lost its premise", blocker.addresses)
	}
	if queued := queuedCandidates(t, o); len(queued) != 0 {
		t.Fatalf("admission queued %+v from message text", queued)
	}
	if n := o.ingress.Stats().Counters.Count(admission.CountKey{Event: admission.EventRefused, Reason: admission.ReasonAttribution}); n != 1 {
		t.Fatalf("attribution refusals = %d, want 1", n)
	}
}

// A spray's roots are the addresses it counted, as its tracker read them;
// its candidate is the prefix that holds them, through the mail subnet
// range entry.
func TestFunnelSprayQueuesItsPrefixOnAddressRoots(t *testing.T) {
	fixture := newOwnerFixture(t)
	opts := respondOptions(fixture)
	opts.ScheduleEvery = time.Hour
	o := fixture.start(opts)
	checks.SetResponseAdmission(o)
	t.Cleanup(func() { checks.SetResponseAdmission(nil) })
	checks.SetIPBlocker(&funnelBlocker{})
	t.Cleanup(func() { checks.SetIPBlocker(nil) })
	checks.SetChallengeIPList(nil)
	dryRun := false
	cfg := &config.Config{StatePath: fixture.statePath}
	cfg.AutoResponse.Enabled, cfg.AutoResponse.BlockIPs, cfg.AutoResponse.DryRun = true, true, &dryRun
	at := fixture.host.now()
	spray := alert.Finding{
		Check: "mail_subnet_spray", Severity: alert.Critical, Timestamp: at, CIDRs: []string{"198.51.100.0/24"},
		Message:     "Mail password spray from 198.51.100.0/24",
		Observation: alert.Observation{Producer: string(checks.ProducerMailLog), Stream: "maillog", Cursor: "crossing", ObservedAt: at},
	}
	for i := 1; i <= 3; i++ {
		spray.SprayConstituents = append(spray.SprayConstituents, alert.SprayConstituent{
			Address: fmt.Sprintf("198.51.100.%d", i), LastSeen: at,
			Observation: alert.Observation{Producer: string(checks.ProducerMailLog), Stream: "maillog", Cursor: fmt.Sprintf("line-%d", i), ObservedAt: at},
			Attribution: admission.AttributionPeer,
		})
	}
	checks.AutoBlockIPs(cfg, []alert.Finding{spray})
	if err := o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	queued := queuedCandidates(t, o)
	if len(queued) != 1 || queued[0].Key.Kind != admission.KindBlockSubnet || queued[0].Key.Target.Key() != "net:198.51.100.0/24" {
		t.Fatalf("queued=%+v", queued)
	}
	if n := o.ingress.Stats().Counters.Count(admission.CountKey{Event: admission.EventRefused, Reason: admission.ReasonAttribution}); n != 0 {
		t.Fatalf("%d attribution refusals", n)
	}
}
