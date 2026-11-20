package daemon

import (
	"bytes"
	"errors"
	"log"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/challenge"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/incident"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/reporting"
)

// An incident block admission takes counts as requested, so the correlator
// latches it once instead of asking again on every merge, and no legacy
// block is applied.
func TestIncidentBlockAdmissionTakesIsRequested(t *testing.T) {
	cfg, b := applyWiringSetup(t)
	a := withRecordingAdmission(t)
	a.executes = true
	d := New(cfg, nil, nil, "")
	requested, err := d.applyIncidentBlock("203.0.113.98", "CSM incident: brute force", time.Hour, "fid", incident.PreparedRoot{}, admission.EntryIncident)
	if !requested || err != nil || len(b.calls) != 0 {
		t.Fatalf("applyIncidentBlock = %v, %v, legacy calls %+v; want requested with no legacy block", requested, err, b.calls)
	}
}

// Central intel and challenge timeouts treat a block admission takes as an
// expected outcome, not a failure to log.
func TestBlocksAdmissionTakesAreExpectedRefusals(t *testing.T) {
	err := errors.Join(checks.ErrBlockTakenByAdmission)
	if !isCentralBlockRefusal(err) {
		t.Fatal("central intel logs a block admission takes as a failure")
	}
	if !isExpectedEscalationRefusal(err) {
		t.Fatal("challenge escalation logs a block admission takes as a failure")
	}
}

// A taken timeout consumes the expired challenge without reporting a
// legacy escalation or retaining a challenge for another attempt.
func TestTakenTimeoutLeavesNoLegacyEscalation(t *testing.T) {
	cfg, b := applyWiringSetup(t)
	a := withRecordingAdmission(t)
	a.executes = true
	d := New(cfg, nil, nil, "")
	d.ipList = challenge.NewIPList(filepath.Join(t.TempDir(), "challenge_ips.txt"))
	const ip = "203.0.113.99"
	d.ipList.Add(ip, "wp brute", -time.Minute)
	live, noop := checks.ChallengeEscalatedCount(firewall.BlockOutcomeLive), checks.ChallengeEscalatedCount(firewall.BlockOutcomeNoop)
	output := captureAppliedBlockStderr(t, func() { d.escalateExpiredChallenges(time.Hour) })
	if calls := a.got(); len(calls) != 1 || calls[0].target != ip || calls[0].via != admission.EntryChallengeTimeout {
		t.Fatalf("timeout did not hand off exactly once: %+v", calls)
	}
	if len(b.calls) != 0 || len(blockedTrackerIPs(t, cfg.StatePath)) != 0 {
		t.Fatal("taken timeout left legacy block evidence")
	}
	if checks.ChallengeEscalatedCount(firewall.BlockOutcomeLive) != live || checks.ChallengeEscalatedCount(firewall.BlockOutcomeNoop) != noop {
		t.Fatal("taken timeout counted a legacy escalation")
	}
	if output != "" {
		t.Fatalf("taken timeout logged: %s", output)
	}
	if d.ipList.Contains(ip) || len(d.ipList.ExpiredEntries()) != 0 {
		t.Fatal("taken timeout left a challenge entry")
	}
	d.escalateExpiredChallenges(time.Hour)
	if len(a.got()) != 1 {
		t.Fatal("taken timeout was handed off again")
	}
}

// A challenge routed without a root keeps the refusal that left it
// rootless, so its timeout is answered by the same rule as a direct block:
// an address Apache or nginx may have rewritten still gets the legacy block,
// and any other refusal, LiteSpeed's included, is final, counted once more
// for the timeout.
func TestChallengeTimeoutAnswersTheRoutingRefusal(t *testing.T) {
	for _, tc := range []struct {
		name   string
		server platform.WebServer
		cause  admission.Cause
		legacy bool
	}{
		{"rewritten", platform.WSApache, admission.CauseRewrittenLog, true},
		{"rewritten by litespeed", platform.WSLiteSpeed, admission.CauseRewrittenLog, false},
		{"no observation", platform.WSApache, admission.CauseNoObservation, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checks.SetHTTPRewrite(checks.HTTPRewrite{State: checks.RewriteActive, Server: tc.server})
			t.Cleanup(func() { checks.SetHTTPRewrite(checks.HTTPRewrite{State: checks.RewriteNone}) })
			cfg, b := applyWiringSetup(t)
			a := withRecordingAdmission(t)
			a.executes = true
			d := New(cfg, nil, nil, "")
			d.ipList = challenge.NewIPList(filepath.Join(t.TempDir(), "challenge_ips.txt"))
			const ip = "203.0.113.73"
			refusal := &admission.Error{Reason: admission.ReasonAttribution, Cause: tc.cause}
			d.ipList.AddWithRoot(ip, "wp brute", -time.Minute, "fid", "wp_login_bruteforce", admission.Evidence{}, refusal)
			output := captureAppliedBlockStderr(t, func() { d.escalateExpiredChallenges(time.Hour) })
			if len(a.got()) != 0 {
				t.Fatalf("a refused root was answered again: %+v", a.got())
			}
			a.mu.Lock()
			refusals := append([]derivedRefusal(nil), a.refusals...)
			a.mu.Unlock()
			if len(refusals) != 1 || refusals[0] != (derivedRefusal{admission.KindBlockIP, "wp_login_bruteforce", admission.EntryChallengeTimeout, admission.ReasonAttribution}) {
				t.Fatalf("timeout refusals = %+v, want one for the routed check", refusals)
			}
			if tc.legacy {
				if len(b.calls) != 1 || b.calls[0].ip != ip {
					t.Fatalf("legacy calls = %+v, want the block of %s", b.calls, ip)
				}
				return
			}
			if len(b.calls) != 0 || len(blockedTrackerIPs(t, cfg.StatePath)) != 0 || output != "" {
				t.Fatalf("a refused timeout left legacy work: calls %+v, log %q", b.calls, output)
			}
		})
	}
}

// The central queue finishes an admission-owned block without loss,
// legacy evidence or a success/failure log.
func TestTakenCentralBlockFinishesQueue(t *testing.T) {
	cfg, b := applyWiringSetup(t)
	a := withRecordingAdmission(t)
	a.executes = true
	d := New(cfg, nil, nil, "")
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(previous) })
	consumer := newCentralActionConsumer(d.stopCh, 1, time.Hour, nil, d.performCentralAction)
	const ip = "203.0.113.100"
	if !consumer.enqueue(centralQueuedAction{decision: reporting.DecisionBlock, ip: ip}) {
		t.Fatal("central action was not enqueued")
	}
	consumer.process(<-consumer.queue.Items())
	if calls := a.got(); len(calls) != 1 || calls[0].target != ip || calls[0].via != admission.EntryCentral {
		t.Fatalf("central did not hand off exactly once: %+v", calls)
	}
	if len(b.calls) != 0 || len(blockedTrackerIPs(t, cfg.StatePath)) != 0 {
		t.Fatal("taken central block left legacy block evidence")
	}
	if got := consumer.QueueStatuses(time.Now())["actions"]; got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != 0 {
		t.Fatalf("taken central block was not finished: %+v", got)
	}
	if output.Len() != 0 {
		t.Fatalf("taken central block logged: %s", output.String())
	}
}
