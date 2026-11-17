package store

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// destinationApplied verifies a block of target whose root is a
// destination finding of severity.
func (f *ledgerFixture) destinationApplied(target string, severity admission.Severity) admission.CandidateID {
	f.t.Helper()
	root := f.published(evidenceSpec{producer: f.c2, check: "c2_connection", target: target, cursor: "c2=" + target, severity: severity})
	_, id := f.enqueue(f.request(target, root))
	_, a, granted, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil || !granted {
		f.t.Fatalf("reserve %s: %v %v", target, granted, err)
	}
	if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
		f.t.Fatal(err)
	}
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionApplied); err != nil {
		f.t.Fatal(err)
	}
	return id
}

// A verified block of a Critical destination raises the partial-containment
// record: outbound-only traffic still leaves. The response ran, so the
// record is no gap: the Critical summary and the doctor's gap row stay as
// they were.
func TestAdmissionLedgerPartialContainmentNotice(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.destinationApplied("203.0.113.80", admission.SeverityCritical)
	key := admission.PartialContainmentKey("c2_connection", admission.EffectAddress)
	got := f.notices()
	if r := got[key]; r.Count != 1 || len(r.Examples) != 1 || r.Examples[0].Candidate != id {
		t.Fatalf("partial record = %+v", r)
	}
	if got[criticalSummary].Count != 0 {
		t.Fatalf("a partial containment counted as a Critical gap: %+v", got[criticalSummary])
	}
	s := f.l.Status()
	if !s.Notices.LastCriticalGap.IsZero() {
		t.Fatalf("last Critical gap = %v, want none", s.Notices.LastCriticalGap)
	}
	for _, row := range admission.DoctorChecks(&s, nil, f.wall, true) {
		if row.Name == "admission response gaps" && row.Status != admission.DoctorOK {
			t.Fatalf("doctor gap row = %+v", row)
		}
	}
}

// Only a Critical destination root raises it; a verified inbound block
// raises none.
func TestAdmissionLedgerPartialContainmentNeedsACriticalDestination(t *testing.T) {
	f := newLedgerFixture(t)
	f.destinationApplied("203.0.113.81", admission.SeverityHigh)
	other := f.reservedAt("192.0.2.81", f.wall.Add(time.Hour))
	if _, _, _, err := f.l.Execute(other.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.l.Finish(other.Attempt.ID, admission.DispositionApplied); err != nil {
		t.Fatal(err)
	}
	for key, r := range f.notices() {
		if key.Partial() || (key.Reason == admission.ReasonUnsupportedContainment && r.Count > 0) {
			t.Fatalf("partial record raised: %+v", r)
		}
	}
}

// Overflow shares a withheld record but must not turn a successful block
// into an outage. Repeated destinations use one hourly delivery record.
func TestAdmissionLedgerPartialContainmentBoundedAndOverflow(t *testing.T) {
	for _, overflow := range []bool{false, true} {
		t.Run(map[bool]string{false: "keyed", true: "overflow"}[overflow], func(t *testing.T) {
			f := newLedgerFixture(t)
			if overflow {
				f.adjustStorage(func(s *admission.StorageState) { s.NoticeRecords = admission.MaxNoticeRecords })
			}
			f.destinationApplied("203.0.113.82", admission.SeverityCritical)
			key := admission.PartialContainmentKey("c2_connection", admission.EffectAddress)
			if overflow {
				key = admission.OverflowKey(admission.NoticeWithheld)
			}
			first := f.notices()[key]
			if first.Count != 1 {
				t.Fatalf("first notice = %+v", first)
			}
			if err := f.l.AckNotices([]admission.NoticeAck{{Key: key, First: first.First, Count: first.Count}}); err != nil {
				t.Fatal(err)
			}
			records := len(f.notices())
			f.destinationApplied("203.0.113.83", admission.SeverityCritical)
			f.destinationApplied("203.0.113.84", admission.SeverityCritical)
			got := f.notices()
			if len(got) != records || got[key].Count != 3 || got[criticalSummary].Count != 0 {
				t.Fatalf("repeated notices: records=%d want=%d record=%+v summary=%+v", len(got), records, got[key], got[criticalSummary])
			}
			st := f.l.Status()
			if !st.Notices.LastCriticalGap.IsZero() {
				t.Fatalf("partial events set a gap: %+v", st.Notices)
			}
			for _, row := range admission.DoctorChecks(&st, nil, f.wall, true) {
				if row.Name == "admission response gaps" && row.Status != admission.DoctorOK {
					t.Fatalf("partial events changed doctor: %+v", row)
				}
			}
			assertDue := func(want bool) {
				t.Helper()
				due, err := f.l.PendingNotices()
				if err != nil {
					t.Fatal(err)
				}
				count := 0
				for _, r := range due {
					if r.Key == key {
						count++
					}
				}
				if (count == 1) != want || count > 1 {
					t.Fatalf("notice deliveries=%d, due=%v", count, want)
				}
			}
			assertDue(false)
			f.tickAt(f.wall.Add(time.Hour - time.Nanosecond))
			assertDue(false)
			f.tickAt(f.wall.Add(time.Nanosecond))
			assertDue(true)
			id := f.criticalQueued()
			if _, err := f.l.Terminate(id, admission.ReasonPolicy); err != nil {
				t.Fatal(err)
			}
			if got := f.notices()[criticalSummary]; got.Count != 1 {
				t.Fatalf("real gap after partial events = %+v", got)
			}
		})
	}
}
