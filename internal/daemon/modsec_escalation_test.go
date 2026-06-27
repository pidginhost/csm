package daemon

import (
	"sync"
	"testing"
	"time"
)

// recordModSecEvent escalation semantics (confidence-gated). See
// docs/superpowers/specs/2026-06-27-modsec-escalation-fp-options.md.

func resetModSecCounters() {
	modsecBlockCount = sync.Map{}
	modsecDedup = sync.Map{}
}

func TestRecordModSecEvent_LowConfOnly_NoBanButBurst(t *testing.T) {
	resetModSecCounters()
	defer resetModSecCounters()
	now := time.Now()
	win := 10 * time.Minute
	// hits=3 normal bar, backstop=30. Three low-confidence blocks of the same
	// rule (the checkout FP) must NOT ban, but must emit one visibility burst.
	var lastBurst, anyEscalate bool
	for i := 0; i < 3; i++ {
		out := recordModSecEvent("203.0.113.10", now.Add(time.Duration(i)*time.Second), 210710, modsecConfLow, true, 3, 30, win)
		if out.escalate {
			anyEscalate = true
		}
		lastBurst = out.lowConfBurst
	}
	if anyEscalate {
		t.Fatal("low-confidence-only burst must not escalate to a ban at the normal bar")
	}
	if !lastBurst {
		t.Fatal("low-confidence-only burst at the normal bar must emit a visibility finding")
	}
}

func TestRecordModSecEvent_LowConfBackstop_Escalates(t *testing.T) {
	resetModSecCounters()
	defer resetModSecCounters()
	now := time.Now()
	win := 10 * time.Minute
	// Backstop=5 for the test. Same low-confidence rule on the same URI 5x must
	// escalate via the backstop even with no high/unknown evidence.
	escalated := false
	for i := 0; i < 5; i++ {
		out := recordModSecEvent("203.0.113.11", now.Add(time.Duration(i)*time.Second), 210710, modsecConfLow, true, 3, 5, win)
		if out.escalate {
			escalated = true
		}
	}
	if !escalated {
		t.Fatal("low-confidence-only burst must escalate once it reaches the backstop count")
	}
}

func TestRecordModSecEvent_SameHighConfRule_EscalatesAtNormalBar(t *testing.T) {
	resetModSecCounters()
	defer resetModSecCounters()
	now := time.Now()
	win := 10 * time.Minute
	// Three denies of ONE high-confidence rule (no diversity) must escalate.
	out1 := recordModSecEvent("203.0.113.12", now, 210381, modsecConfHigh, true, 3, 30, win)
	out2 := recordModSecEvent("203.0.113.12", now.Add(time.Second), 210381, modsecConfHigh, true, 3, 30, win)
	out3 := recordModSecEvent("203.0.113.12", now.Add(2*time.Second), 210381, modsecConfHigh, true, 3, 30, win)
	if out1.escalate || out2.escalate {
		t.Fatal("must not escalate before reaching the hit count")
	}
	if !out3.escalate {
		t.Fatal("three high-confidence denies of the same rule must escalate at the normal bar")
	}
}

func TestRecordModSecEvent_UnknownDeny_EscalatesAndGaps(t *testing.T) {
	resetModSecCounters()
	defer resetModSecCounters()
	now := time.Now()
	win := 10 * time.Minute
	out1 := recordModSecEvent("203.0.113.13", now, 211500, modsecConfUnknown, true, 3, 30, win)
	if !out1.classifierGap {
		t.Fatal("first unknown blocking deny must raise a classifier-gap finding")
	}
	out2 := recordModSecEvent("203.0.113.13", now.Add(time.Second), 211500, modsecConfUnknown, true, 3, 30, win)
	if out2.classifierGap {
		t.Fatal("same unknown rule in the same window must not re-raise classifier-gap")
	}
	out3 := recordModSecEvent("203.0.113.13", now.Add(2*time.Second), 211500, modsecConfUnknown, true, 3, 30, win)
	if !out3.escalate {
		t.Fatal("unknown blocking denies are escalation-eligible at the normal bar")
	}
}

func TestRecordModSecEvent_UnknownWarningCountsAsEvidence(t *testing.T) {
	resetModSecCounters()
	defer resetModSecCounters()
	now := time.Now()
	win := 10 * time.Minute
	ip := "203.0.113.25"

	out := recordModSecEvent(ip, now, 211999, modsecConfUnknown, false, 3, 30, win)
	if !out.classifierGap {
		t.Fatal("first unknown warning must raise a classifier-gap finding")
	}
	if out.escalate {
		t.Fatal("unknown warning alone must not escalate without blocking denies")
	}
	recordModSecEvent(ip, now.Add(time.Second), 949110, modsecConfLow, true, 3, 30, win)
	recordModSecEvent(ip, now.Add(2*time.Second), 949110, modsecConfLow, true, 3, 30, win)
	out = recordModSecEvent(ip, now.Add(3*time.Second), 949110, modsecConfLow, true, 3, 30, win)
	if !out.escalate {
		t.Fatal("unknown warning evidence plus a low-confidence deny burst must escalate")
	}
}

func TestRecordModSecEvent_MixedBurst_HighEvidenceEscalates(t *testing.T) {
	resetModSecCounters()
	defer resetModSecCounters()
	now := time.Now()
	win := 10 * time.Minute
	// Two low-confidence + one high-confidence deny reaching the hit count must
	// escalate at the normal bar because high-confidence evidence is present.
	recordModSecEvent("203.0.113.14", now, 210710, modsecConfLow, true, 3, 30, win)
	recordModSecEvent("203.0.113.14", now.Add(time.Second), 214930, modsecConfLow, true, 3, 30, win)
	out := recordModSecEvent("203.0.113.14", now.Add(2*time.Second), 210381, modsecConfHigh, true, 3, 30, win)
	if !out.escalate {
		t.Fatal("a burst containing high-confidence evidence must escalate at the normal bar")
	}
}

func TestRecordModSecEvent_HighConfWarningCountsAsEvidence(t *testing.T) {
	resetModSecCounters()
	defer resetModSecCounters()
	now := time.Now()
	win := 10 * time.Minute
	// A high-confidence WARNING (non-block, e.g. a specific attack rule logged
	// before the anomaly-threshold deny) adds high evidence to the window, so a
	// later low-confidence anomaly-threshold deny burst escalates at the normal
	// bar instead of only via the backstop.
	recordModSecEvent("203.0.113.15", now, 210381, modsecConfHigh, false /*warning*/, 3, 30, win)
	recordModSecEvent("203.0.113.15", now.Add(time.Second), 214930, modsecConfLow, true, 3, 30, win)
	recordModSecEvent("203.0.113.15", now.Add(2*time.Second), 214930, modsecConfLow, true, 3, 30, win)
	out := recordModSecEvent("203.0.113.15", now.Add(3*time.Second), 214930, modsecConfLow, true, 3, 30, win)
	if !out.escalate {
		t.Fatal("high-confidence warning evidence plus a low-confidence deny burst must escalate at the normal bar")
	}
}

func TestRecordModSecEvent_HighConfWarningAloneNoBan(t *testing.T) {
	resetModSecCounters()
	defer resetModSecCounters()
	now := time.Now()
	win := 10 * time.Minute
	// Warnings are not blocking denies; they never count toward the deny total,
	// so a stream of high-confidence warnings with no actual block must not ban.
	var escalated bool
	for i := 0; i < 5; i++ {
		out := recordModSecEvent("203.0.113.16", now.Add(time.Duration(i)*time.Second), 210381, modsecConfHigh, false, 3, 30, win)
		if out.escalate {
			escalated = true
		}
	}
	if escalated {
		t.Fatal("high-confidence warnings with no blocking deny must not escalate")
	}
}

func TestRecordModSecEvent_PerIPIsolation(t *testing.T) {
	resetModSecCounters()
	defer resetModSecCounters()
	now := time.Now()
	win := 10 * time.Minute
	recordModSecEvent("203.0.113.17", now, 210381, modsecConfHigh, true, 3, 30, win)
	recordModSecEvent("203.0.113.18", now, 210381, modsecConfHigh, true, 3, 30, win)
	out := recordModSecEvent("203.0.113.17", now.Add(time.Second), 210381, modsecConfHigh, true, 3, 30, win)
	if out.escalate {
		t.Fatal("counters must be isolated per IP; 2 denies on one IP must not escalate")
	}
}

func TestRecordModSecEvent_RearmsWhenWindowFallsBelowThresholdBeforeAppend(t *testing.T) {
	resetModSecCounters()
	defer resetModSecCounters()
	now := time.Unix(1_700_000_000, 0)
	win := 10 * time.Minute
	ip := "203.0.113.19"
	recordModSecEvent(ip, now, 210381, modsecConfHigh, true, 3, 30, win)
	recordModSecEvent(ip, now.Add(time.Minute), 210381, modsecConfHigh, true, 3, 30, win)
	out := recordModSecEvent(ip, now.Add(2*time.Minute), 210381, modsecConfHigh, true, 3, 30, win)
	if !out.escalate {
		t.Fatal("initial high-confidence burst did not escalate")
	}

	// At 11m the first event has left the 10m window, so the pre-append window
	// has only two blocks. The new event reaches the bar again and must re-emit.
	out = recordModSecEvent(ip, now.Add(11*time.Minute), 210381, modsecConfHigh, true, 3, 30, win)
	if !out.escalate {
		t.Fatal("renewed burst after dropping below threshold must re-escalate")
	}
}

func TestRecordModSecEvent_LowBurstDoesNotSpamAroundThreshold(t *testing.T) {
	resetModSecCounters()
	defer resetModSecCounters()
	now := time.Unix(1_700_000_000, 0)
	win := 10 * time.Minute
	ip := "203.0.113.20"
	recordModSecEvent(ip, now, 210710, modsecConfLow, true, 3, 30, win)
	recordModSecEvent(ip, now.Add(time.Minute), 210710, modsecConfLow, true, 3, 30, win)
	out := recordModSecEvent(ip, now.Add(2*time.Minute), 210710, modsecConfLow, true, 3, 30, win)
	if !out.lowConfBurst {
		t.Fatal("initial low-confidence burst did not emit visibility finding")
	}

	out = recordModSecEvent(ip, now.Add(11*time.Minute), 210710, modsecConfLow, true, 3, 30, win)
	if out.lowConfBurst {
		t.Fatal("low-confidence burst must not re-emit while the active window only oscillates around hits")
	}
}

func TestRecordModSecEvent_LowBurstReemitsAfterWindowDrains(t *testing.T) {
	resetModSecCounters()
	defer resetModSecCounters()
	now := time.Unix(1_700_000_000, 0)
	win := 10 * time.Minute
	ip := "203.0.113.24"
	recordModSecEvent(ip, now, 210710, modsecConfLow, true, 3, 30, win)
	recordModSecEvent(ip, now.Add(time.Minute), 210710, modsecConfLow, true, 3, 30, win)
	out := recordModSecEvent(ip, now.Add(2*time.Minute), 210710, modsecConfLow, true, 3, 30, win)
	if !out.lowConfBurst {
		t.Fatal("initial low-confidence burst did not emit visibility finding")
	}

	recordModSecEvent(ip, now.Add(13*time.Minute), 210710, modsecConfLow, true, 3, 30, win)
	recordModSecEvent(ip, now.Add(14*time.Minute), 210710, modsecConfLow, true, 3, 30, win)
	out = recordModSecEvent(ip, now.Add(15*time.Minute), 210710, modsecConfLow, true, 3, 30, win)
	if !out.lowConfBurst {
		t.Fatal("low-confidence burst must re-emit after the prior window fully drains")
	}
}

func TestRecordModSecEvent_SustainedSourceRearmsAfterBlockExpiry(t *testing.T) {
	resetModSecCounters()
	defer resetModSecCounters()
	now := time.Unix(1_700_000_000, 0)
	win := 2 * time.Hour
	rearm := time.Hour
	ip := "203.0.113.21"
	recordModSecEventWithRearm(ip, now, 210381, modsecConfHigh, true, 3, 30, win, rearm)
	recordModSecEventWithRearm(ip, now.Add(time.Second), 210381, modsecConfHigh, true, 3, 30, win, rearm)
	out := recordModSecEventWithRearm(ip, now.Add(2*time.Second), 210381, modsecConfHigh, true, 3, 30, win, rearm)
	if !out.escalate {
		t.Fatal("initial sustained source escalation did not fire")
	}
	out = recordModSecEventWithRearm(ip, now.Add(30*time.Minute), 210381, modsecConfHigh, true, 3, 30, win, rearm)
	if out.escalate {
		t.Fatal("sustained source must not spam duplicate escalations before block expiry")
	}
	out = recordModSecEventWithRearm(ip, now.Add(time.Hour+3*time.Second), 210381, modsecConfHigh, true, 3, 30, win, rearm)
	if !out.escalate {
		t.Fatal("sustained source must refresh escalation after block expiry")
	}
}

func TestRecordModSecEvent_LowBackstopRearmsBelowBackstopBeforeAppend(t *testing.T) {
	resetModSecCounters()
	defer resetModSecCounters()
	now := time.Unix(1_700_000_000, 0)
	win := 10 * time.Minute
	ip := "203.0.113.22"
	var out modsecEscalationOutcome
	for i := 0; i < 5; i++ {
		out = recordModSecEvent(ip, now.Add(time.Duration(i)*time.Minute), 210710, modsecConfLow, true, 3, 5, win)
	}
	if !out.escalate {
		t.Fatal("initial low-confidence backstop escalation did not fire")
	}

	// The first event aged out, so the pre-append window is below the backstop
	// while still above the normal low-confidence visibility threshold.
	out = recordModSecEvent(ip, now.Add(11*time.Minute), 210710, modsecConfLow, true, 3, 5, win)
	if !out.escalate {
		t.Fatal("low-confidence backstop must re-arm after dropping below backstop")
	}
}

func TestEvictModSecState_ResetsLowBackstopLatchBelowBackstop(t *testing.T) {
	resetModSecCounters()
	defer resetModSecCounters()
	now := time.Unix(1_700_000_000, 0)
	win := 10 * time.Minute
	ip := "203.0.113.23"
	for i := 0; i < 5; i++ {
		recordModSecEvent(ip, now.Add(time.Duration(i)*time.Minute), 210710, modsecConfLow, true, 3, 5, win)
	}

	evictModSecStateWithLowConf(now.Add(11*time.Minute), 3, 5, win)
	val, ok := modsecBlockCount.Load(ip)
	if !ok {
		t.Fatal("counter should remain with four recent low-confidence blocks")
	}
	ctr := val.(*modsecIPCounter)
	ctr.mu.Lock()
	defer ctr.mu.Unlock()
	if ctr.escalated {
		t.Fatal("eviction must re-arm escalation once low-confidence count drops below backstop")
	}
	if len(ctr.events) != 4 {
		t.Fatalf("recent events = %d, want 4", len(ctr.events))
	}
}
