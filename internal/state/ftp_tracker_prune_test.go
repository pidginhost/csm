package state

import (
	"testing"
	"time"
)

func TestUnderscoreRawKeySurvivesUpdatePruning(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	st.SetRaw("_ftp_fail_tracker", "{}")
	st.SetRaw("ftp_fail_tracker_control", "{}")

	old := time.Now().Add(-48 * time.Hour)
	st.entries["_ftp_fail_tracker"].LastSeen = old
	st.entries["ftp_fail_tracker_control"].LastSeen = old

	st.Update(nil)
	if _, ok := st.GetRaw("_ftp_fail_tracker"); !ok {
		t.Fatal("underscore-prefixed FTP tracker key must survive Store.Update")
	}
	if _, ok := st.GetRaw("ftp_fail_tracker_control"); ok {
		t.Fatal("non-underscore control key should have been pruned")
	}
}
