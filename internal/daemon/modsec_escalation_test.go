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
