package state

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

func TestPendingFindingsKeepDatabaseCause(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cause := alert.Cause{Check: "db_siteurl_hijack", FindingID: "0123456789abcdef"}
	f := alert.Finding{Check: "local_threat_score", Severity: alert.Critical, SourceIP: "192.0.2.12", Cause: &cause}
	if err := st.AppendPendingFindings([]alert.Finding{f}); err != nil {
		t.Fatal(err)
	}
	if err := st.ReplayPendingFindings(func(got []alert.Finding) {
		if len(got) != 1 || got[0].Cause == nil || *got[0].Cause != cause {
			t.Fatalf("replayed findings = %+v, want the database cause", got)
		}
	}); err != nil {
		t.Fatal(err)
	}
	withoutCause := f
	withoutCause.Cause = nil
	if pendingIdentity([]alert.Finding{f}) == pendingIdentity([]alert.Finding{withoutCause}) {
		t.Fatal("pending batch identity ignores the database cause")
	}
}
