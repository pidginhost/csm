package checks

import (
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/firewall"
)

func TestFormRelayModeGatesFreshAndQueuedResponses(t *testing.T) {
	for _, mode := range []string{"", "observe", "enforce"} {
		for _, challenge := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/challenge=%v", mode, challenge), func(t *testing.T) {
				cfg := pendingTestConfig(t)
				cfg.EmailProtection.PHPRelay.IPRecipientMode = mode
				cfg.Challenge.Enabled = challenge
				blocker := &recordingIPBlocker{}
				applyBlockTestSetup(t, blocker)
				list := &mockIPList{ips: make(map[string]bool)}
				previous := GetChallengeIPList()
				SetChallengeIPList(list)
				t.Cleanup(func() { SetChallengeIPList(previous) })
				// A previous enforce cycle can leave work in the retry queue.
				saveBlockState(cfg.StatePath, &blockState{Pending: []pendingIP{{
					IP: "203.0.113.11", Check: "email_php_form_relay", Severity: alert.High, QueuedAt: time.Now(),
				}}})
				ChallengeThenBlock(cfg, []alert.Finding{
					{Check: "email_php_form_relay", Severity: alert.High, SourceIP: "203.0.113.10"},
					{Check: "email_php_form_relay_observed", Severity: alert.Critical, SourceIP: "203.0.113.12"},
					{Check: "wp_login_bruteforce", Severity: alert.High, SourceIP: "198.51.100.1"},
				})
				if list.ips["203.0.113.12"] || slices.Contains(blocker.blocked, "203.0.113.12") {
					t.Fatal("observed finding aimed a response")
				}
				if mode != "enforce" {
					if list.ips["203.0.113.10"] || slices.Contains(blocker.blocked, "203.0.113.10") || slices.Contains(blocker.blocked, "203.0.113.11") {
						t.Fatalf("observe mode acted on enforce history: challenged %v, blocked %v", list.ips, blocker.blocked)
					}
				} else if challenge != list.ips["203.0.113.10"] || !challenge != slices.Contains(blocker.blocked, "203.0.113.10") {
					t.Fatalf("enforce response changed: challenged %v, blocked %v", list.ips, blocker.blocked)
				}
				if mode == "enforce" && !slices.Contains(blocker.blocked, "203.0.113.11") {
					t.Fatal("enforce retry was dropped")
				}
				if challenge != list.ips["198.51.100.1"] || !challenge != slices.Contains(blocker.blocked, "198.51.100.1") {
					t.Fatal("unrelated response did not run")
				}
				if got := loadBlockState(cfg.StatePath).Pending; len(got) != 0 {
					t.Fatalf("pending work remains: %+v", got)
				}
			})
		}
	}
}

func TestFormRelayModeGatesAdmissionAndDerivedBlocks(t *testing.T) {
	for _, mode := range []string{"", "observe", "enforce"} {
		for _, check := range []string{"email_php_form_relay", "email_php_form_relay_observed"} {
			t.Run(mode+"/"+check, func(t *testing.T) {
				cfg := pendingTestConfig(t)
				cfg.EmailProtection.PHPRelay.IPRecipientMode = mode
				cfg.Challenge.Enabled = true
				cfg.Reputation.Central.Enabled = true
				cfg.Reputation.Central.Action = "block_if_local_corroborated"
				cfg.Incidents.AutoBlock.Enabled = true
				cfg.Incidents.AutoBlock.BlockAtSeverity = "high"
				cfg.Incidents.SpraySuppression.Enabled = true
				cfg.Incidents.SpraySuppression.BlockAtSeverity = "high"
				want := mode == "enforce" && check == "email_php_form_relay"
				for _, entry := range []admission.Entry{admission.EntryScan, admission.EntryChallengeTimeout, admission.EntryIncident, admission.EntryIncidentSpray, admission.EntryCentral} {
					if got := AutomaticResponseAllowed(cfg, admission.KindBlockIP, entry, check); got != want {
						t.Errorf("%s block allowed = %v, want %v", entry, got, want)
					}
				}
				for _, entry := range []admission.Entry{admission.EntryScan, admission.EntryCentral} {
					if got := AutomaticResponseAllowed(cfg, admission.KindChallenge, entry, check); got != want {
						t.Errorf("%s challenge allowed = %v, want %v", entry, got, want)
					}
				}
				blocker := &recordingIPBlocker{}
				applyBlockTestSetup(t, blocker)
				result, err := ApplyBlock(cfg, ApplyBlockRequest{
					IP: "203.0.113.10", Check: check, Source: BlockSourceChallenge,
					Entry: admission.EntryChallengeTimeout, TTL: time.Hour,
				})
				if want {
					if err != nil || !slices.Equal(blocker.blocked, []string{"203.0.113.10"}) {
						t.Fatalf("enforce block = %+v, %v, blocked %v", result, err, blocker.blocked)
					}
				} else if !errors.Is(err, ErrAutoBlockDisabled) || result.Outcome != firewall.BlockOutcomeNoop || len(blocker.blocked) != 0 {
					t.Fatalf("observe block = %+v, %v, blocked %v", result, err, blocker.blocked)
				}
			})
		}
	}
}

func TestFormRelayObservedReplayAimsNoResponse(t *testing.T) {
	h := newReplayHarness(t, 10, replayT0, blockState{}, nil)
	h.cfg.EmailProtection.PHPRelay.IPRecipientMode = "enforce"
	step := h.run(replayT0,
		alert.Finding{Check: "email_php_form_relay_observed", Severity: alert.High, Message: "client: 203.0.113.10"},
		alert.Finding{Check: "email_php_form_relay", Severity: alert.High, Message: "client: 203.0.113.11"},
	)
	if len(step.live) != 0 || len(step.model.BlockedIPs) != 0 || step.model.ChallengeSkipped != 1 || !slices.Equal(step.challenged, []string{"203.0.113.11"}) {
		t.Fatalf("replay response = %+v, want only the enforce client challenged", step)
	}
	for _, producer := range ProducerTable() {
		if slices.Contains(producer.Spec.Checks, "email_php_form_relay_observed") {
			t.Fatalf("observed check can mint evidence through %s", producer.Spec.ID)
		}
	}
	for _, entry := range DerivedEntries() {
		if slices.Contains(entry.Checks, "email_php_form_relay_observed") {
			t.Fatalf("observed check can reach derived response %s", entry.ID)
		}
	}
}

func TestFormRelayReplayMatchesMode(t *testing.T) {
	for _, mode := range []string{"observe", "enforce"} {
		for _, challenge := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/challenge=%v", mode, challenge), func(t *testing.T) {
				h := newReplayHarness(t, 10, replayT0, blockState{}, nil)
				h.cfg.EmailProtection.PHPRelay.IPRecipientMode = mode
				h.cfg.Challenge.Enabled = challenge
				step := h.run(replayT0, alert.Finding{Check: "email_php_form_relay", Severity: alert.High, Message: "client: 203.0.113.10"})
				wantBlock, wantChallenge := 0, 0
				if mode == "enforce" {
					if challenge {
						wantChallenge = 1
					} else {
						wantBlock = 1
					}
				}
				if len(step.live) != wantBlock || len(step.model.BlockedIPs) != wantBlock || len(step.challenged) != wantChallenge || step.model.ChallengeSkipped != wantChallenge {
					t.Fatalf("replay disagrees with mode: %+v", step)
				}
			})
		}
	}
}
