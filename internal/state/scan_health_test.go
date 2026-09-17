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
