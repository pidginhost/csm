package incident

import (
	"strings"
	"testing"
	"time"
)

func TestAppendCappedFingerprint_PreservesHeadAndTail(t *testing.T) {
	var fps []string
	for i := 0; i < maxIncidentFindings*2; i++ {
		fps = appendCappedFingerprint(fps, "fp-"+strings.Repeat("x", i%5))
	}
	if len(fps) > maxIncidentFindings+1 {
		t.Errorf("fingerprint slice grew past cap: len=%d, cap=%d", len(fps), maxIncidentFindings)
	}
	hasGap := false
	for _, fp := range fps {
		if strings.HasPrefix(fp, "...truncated:") {
			hasGap = true
			break
		}
	}
	if !hasGap {
		t.Error("expected truncation marker in capped fingerprint slice")
	}
}

func TestAppendCappedTimeline_PreservesHeadAndTail(t *testing.T) {
	var events []IncidentEvent
	for i := 0; i < maxIncidentTimeline*3; i++ {
		events = appendCappedTimeline(events, IncidentEvent{
			Time:  time.Unix(int64(i), 0),
			Kind:  "finding",
			Check: "probe",
		})
	}
	if len(events) > maxIncidentTimeline+1 {
		t.Errorf("timeline grew past cap: len=%d, cap=%d", len(events), maxIncidentTimeline)
	}
	hasTruncated := false
	for _, ev := range events {
		if ev.Kind == "truncated" {
			hasTruncated = true
			break
		}
	}
	if !hasTruncated {
		t.Error("expected truncated marker event in capped timeline")
	}
	// The earliest event must be preserved (incident-opening context)
	// and the most recent event must be preserved (current activity).
	if events[0].Time.Unix() != 0 {
		t.Errorf("first event time = %v, want 0 (incident-opening context lost)", events[0].Time.Unix())
	}
	last := events[len(events)-1].Time.Unix()
	if last != int64(maxIncidentTimeline*3-1) {
		t.Errorf("last event time = %d, want %d (most recent activity lost)", last, maxIncidentTimeline*3-1)
	}
}

func TestAppendCappedFingerprint_BelowCapIsIdentity(t *testing.T) {
	var fps []string
	for i := 0; i < 10; i++ {
		fps = appendCappedFingerprint(fps, "fp")
	}
	if len(fps) != 10 {
		t.Errorf("below-cap append produced len=%d, want 10", len(fps))
	}
}
