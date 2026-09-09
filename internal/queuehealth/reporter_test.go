package queuehealth

import (
	"testing"
	"time"
)

func TestReporterBoundsOverloadRemindersAndReportsRecoveryOnce(t *testing.T) {
	now := time.Unix(1000, 0)
	r := Reporter{}
	states := map[string]Status{"findings.ingest": {Status: "ok"}}
	if got := r.Events(now, states); len(got) != 0 {
		t.Fatalf("healthy startup emitted events: %+v", got)
	}
	states["findings.ingest"] = Status{Status: "degraded", Reason: "dropped_work", DroppedTotal: 3}
	got := r.Events(now.Add(time.Second), states)
	if len(got) != 1 || got[0].Name != "findings.ingest" || got[0].Recovered || got[0].Current.DroppedTotal != 3 {
		t.Fatalf("first overload evidence = %+v", got)
	}
	for sec := 2; sec < 301; sec++ {
		if reminder := r.Events(now.Add(time.Duration(sec)*time.Second), states); len(reminder) != 0 {
			t.Fatalf("overload reminder before five minutes at %ds: %+v", sec, reminder)
		}
	}
	if reminder := r.Events(now.Add(301*time.Second), states); len(reminder) != 1 || reminder[0].Recovered {
		t.Fatalf("missing bounded overload reminder: %+v", reminder)
	}
	states["findings.ingest"] = Status{Status: "ok", DroppedTotal: 3}
	got = r.Events(now.Add(302*time.Second), states)
	if len(got) != 1 || !got[0].Recovered || got[0].Current.DroppedTotal != 3 {
		t.Fatalf("recovery lost cumulative evidence: %+v", got)
	}
	if got := r.Events(now.Add(303*time.Second), states); len(got) != 0 {
		t.Fatalf("repeated recovery notification: %+v", got)
	}
}

func TestReporterHandlesIndependentQueuesInStableOrder(t *testing.T) {
	now := time.Unix(1000, 0)
	r := Reporter{}
	states := map[string]Status{"z": {Status: "degraded"}, "a": {Status: "degraded"}, "healthy": {Status: "ok"}}
	got := r.Events(now, states)
	if len(got) != 2 || got[0].Name != "a" || got[1].Name != "z" {
		t.Fatalf("expected precisely both affected queues in stable order: %+v", got)
	}
	states["z"] = Status{Status: "ok"}
	got = r.Events(now.Add(time.Second), states)
	if len(got) != 1 || got[0].Name != "z" || !got[0].Recovered {
		t.Fatalf("one queue's recovery changed another's incident: %+v", got)
	}
}
