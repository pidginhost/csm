package state

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

func TestRearmAbsentDedupFindingsPreservesOtherBaselines(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	resolved := alert.Finding{Check: "coverage", DedupKey: "resolved"}
	persistent := alert.Finding{Check: "coverage", DedupKey: "persistent"}
	ordinary := alert.Finding{Check: "coverage", Message: "ordinary baseline"}
	unrelated := alert.Finding{Check: "other", DedupKey: "resolved"}
	all := []alert.Finding{resolved, persistent, ordinary, unrelated}
	st.SetBaseline(all)
	st.RearmAbsentDedupFindings([]string{"coverage"}, []alert.Finding{persistent})
	got := st.FilterNew(all)
	if len(got) != 1 || got[0].Key() != resolved.Key() {
		t.Fatalf("re-armed findings = %+v, want only resolved condition", got)
	}
}

func TestRearmAbsentDedupFindingsKeepsAlertedConditionReminder(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	// Deep scans do not cover every file each cycle, so a coverage gap can be
	// absent for one run and back the next. An alerted, undismissed condition
	// keeps its daily reminder instead of alerting again on every return.
	gap := alert.Finding{Check: "coverage", DedupKey: "gap"}
	st.Update([]alert.Finding{gap})
	st.MarkAlerted([]alert.Finding{gap})
	st.RearmAbsentDedupFindings([]string{"coverage"}, nil)
	if got := st.FilterNew([]alert.Finding{gap}); len(got) != 0 {
		t.Fatalf("returning undismissed condition re-alerted: %+v", got)
	}
}

func TestRearmDismissedFindingsLeavesAlertedEntries(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	alerted := alert.Finding{Check: "coverage", DedupKey: "alerted"}
	dismissed := alert.Finding{Check: "coverage", DedupKey: "dismissed"}
	// SetBaseline replaces the whole entry set, so the dismissal is recorded
	// before the alerted condition.
	st.SetBaseline([]alert.Finding{dismissed})
	st.Update([]alert.Finding{alerted})
	st.MarkAlerted([]alert.Finding{alerted})
	st.RearmDismissedFindings([]string{alerted.Key(), dismissed.Key()})
	got := st.FilterNew([]alert.Finding{alerted, dismissed})
	if len(got) != 1 || got[0].Key() != dismissed.Key() {
		t.Fatalf("got %+v, want only the dismissed condition re-armed", got)
	}
}
