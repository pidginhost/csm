package daemon

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/blockdigest"
	"github.com/pidginhost/csm/internal/challenge"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

// Use the actual routing notice: a hand-built summary fixture can supply
// an address that the producer forgot to keep.
func TestChallengeNoticeKeepsSummarySource(t *testing.T) {
	for _, source := range []string{"192.0.2.34", "[2001:db8::34]:443"} {
		t.Run(source, func(t *testing.T) {
			list := challenge.NewIPList(filepath.Join(t.TempDir(), "challenge_ips.txt"))
			previous := checks.GetChallengeIPList()
			checks.SetChallengeIPList(list)
			t.Cleanup(func() { checks.SetChallengeIPList(previous) })
			cfg := &config.Config{}
			cfg.Challenge.Enabled = true
			finding := alert.Finding{
				Check: "wp_login_bruteforce", SourceIP: source,
				Message: "WordPress brute force from 198.51.100.99",
			}
			want := checks.ExtractIPFromFinding(finding)
			actions := checks.ChallengeRouteIPs(cfg, []alert.Finding{finding})
			if len(actions) != 1 || !list.Contains(want) {
				t.Fatalf("actions = %+v, want one challenge for %s", actions, want)
			}

			var sent []blockdigest.WebhookPayload
			d := &Daemon{blockDigest: blockdigest.New(blockdigest.Options{
				Interval: time.Hour, SendOn: "any", MinBlock: 1, Location: time.UTC,
				WebhookSink: func(p blockdigest.WebhookPayload) error { sent = append(sent, p); return nil },
			})}
			d.noteSummary(cfg, actions)
			if !d.blockDigest.SendDue(time.Now().Add(25*time.Hour)) || len(sent) != 1 || sent[0].CSM.Summary == nil {
				t.Fatalf("summary webhooks = %+v, want one summary", sent)
			}
			summary := sent[0].CSM.Summary
			if summary.Checks["challenge_route"]["WARNING"] != 1 {
				t.Fatalf("challenge counts = %v, want one warning", summary.Checks)
			}
			if len(summary.Sources) != 1 || summary.Sources[0].IP != want || summary.Sources[0].Count != 1 {
				t.Fatalf("sources = %+v, want %s counted once", summary.Sources, want)
			}
		})
	}
}
