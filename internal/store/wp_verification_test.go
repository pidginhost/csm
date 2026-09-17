package store

import (
	"testing"
	"time"
)

func TestWPVerificationPersistsAttemptsAndRecovery(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	paths := map[string]string{"/home/alice/site": "alice"}
	fail := map[string]WPVerificationResult{"/home/alice/site": {State: "unverified", Reason: "checksum service unavailable"}}
	update := func(when time.Time, results map[string]WPVerificationResult) {
		t.Helper()
		if updateErr := db.UpdateWPVerification("core", when, "", paths, results, true); updateErr != nil {
			t.Fatal(updateErr)
		}
	}
	update(at, fail)
	if closeErr := db.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	db, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	update(at, fail) // The same scan's second consumer must not count twice.
	rows, err := db.WPVerification("core")
	if err != nil || rows["/home/alice/site"].Failures != 1 {
		t.Fatalf("reopen or duplicate cycle lost the streak: %+v %v", rows, err)
	}
	update(at.Add(time.Hour), fail)
	rows, err = db.WPVerification("core")
	if err != nil || rows["/home/alice/site"].Failures != 2 {
		t.Fatalf("second cycle not recorded: %+v %v", rows, err)
	}
	update(at.Add(2*time.Hour), map[string]WPVerificationResult{"/home/alice/site": {State: "verified"}})
	update(at.Add(time.Hour), fail) // A late older scan must not undo recovery.
	rows, err = db.WPVerification("core")
	if err != nil || rows["/home/alice/site"].State != "verified" || rows["/home/alice/site"].Failures != 0 {
		t.Fatalf("recovery overwritten: %+v %v", rows, err)
	}
}

func TestWPVerificationPrunesOnlyCompletedDiscoveryScope(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	at := time.Now()
	paths := map[string]string{"/home/alice/site": "alice", "/home/bob/site": "bob"}
	results := map[string]WPVerificationResult{"/home/alice/site": {State: "unverified"}, "/home/bob/site": {State: "verified"}}
	if updateErr := db.UpdateWPVerification("plugins", at, "", paths, results, true); updateErr != nil {
		t.Fatal(updateErr)
	}
	if updateErr := db.UpdateWPVerification("plugins", at.Add(time.Hour), "", nil, nil, false); updateErr != nil {
		t.Fatal(updateErr)
	}
	rows, err := db.WPVerification("plugins")
	if err != nil || len(rows) != 2 {
		t.Fatalf("partial discovery erased coverage: %+v %v", rows, err)
	}
	if updateErr := db.UpdateWPVerification("plugins", at.Add(2*time.Hour), "alice", nil, nil, true); updateErr != nil {
		t.Fatal(updateErr)
	}
	rows, err = db.WPVerification("plugins")
	if err != nil || len(rows) != 1 || rows["/home/bob/site"].State != "verified" {
		t.Fatalf("scoped removal affected other account: %+v %v", rows, err)
	}
}

func TestWPVerificationClosedStoreReportsErrors(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if closeErr := db.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if _, err := db.WPVerification("core"); err == nil {
		t.Fatal("unreadable coverage reported empty")
	}
	if updateErr := db.UpdateWPVerification("core", time.Now(), "", nil, nil, true); updateErr == nil {
		t.Fatal("lost coverage update reported successful")
	}
}
