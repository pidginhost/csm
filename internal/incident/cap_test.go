package incident

import (
	"strconv"
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

func TestAppendCappedFingerprint_TruncationCountAccumulates(t *testing.T) {
	var fps []string
	total := maxIncidentFindings * 2
	for i := 0; i < total; i++ {
		fps = appendCappedFingerprint(fps, "fp-"+strconv.Itoa(i))
	}

	count, markers := fingerprintTruncationCountForTest(t, fps)
	if markers != 1 {
		t.Fatalf("truncation markers = %d, want 1", markers)
	}
	if want := total - maxIncidentFindings; count != want {
		t.Fatalf("truncation count = %d, want %d", count, want)
	}
}

func TestAppendCappedTimeline_TruncationCountAccumulates(t *testing.T) {
	var events []IncidentEvent
	total := maxIncidentTimeline * 3
	for i := 0; i < total; i++ {
		events = appendCappedTimeline(events, IncidentEvent{
			Time:  time.Unix(int64(i), 0),
			Kind:  "finding",
			Check: "probe",
		})
	}

	count, markers := timelineTruncationCountForTest(t, events)
	if markers != 1 {
		t.Fatalf("truncation markers = %d, want 1", markers)
	}
	if want := total - maxIncidentTimeline; count != want {
		t.Fatalf("truncation count = %d, want %d", count, want)
	}
}

func fingerprintTruncationCountForTest(t *testing.T, fps []string) (int, int) {
	t.Helper()
	const prefix = "...truncated:"
	count := 0
	markers := 0
	for _, fp := range fps {
		if !strings.HasPrefix(fp, prefix) {
			continue
		}
		markers++
		rest := strings.TrimPrefix(fp, prefix)
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			t.Fatalf("truncation marker has no count: %q", fp)
		}
		n, err := strconv.Atoi(fields[0])
		if err != nil {
			t.Fatalf("truncation count parse failed for %q: %v", fp, err)
		}
		count += n
	}
	return count, markers
}

func timelineTruncationCountForTest(t *testing.T, events []IncidentEvent) (int, int) {
	t.Helper()
	count := 0
	markers := 0
	for _, ev := range events {
		if ev.Kind != "truncated" {
			continue
		}
		markers++
		fields := strings.Fields(ev.Message)
		if len(fields) == 0 {
			t.Fatalf("truncation marker has no count: %+v", ev)
		}
		n, err := strconv.Atoi(fields[0])
		if err != nil {
			t.Fatalf("truncation count parse failed for %+v: %v", ev, err)
		}
		count += n
	}
	return count, markers
}
