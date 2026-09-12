package store

import (
	"testing"
	"time"
)

func TestWPVerificationDiscoveryDoesNotDiscardPendingAttempt(t *testing.T) {
	for _, complete := range []bool{false, true} {
		for _, scope := range []string{"", "alice"} {
			t.Run(scope+"/"+map[bool]string{false: "partial", true: "complete"}[complete], func(t *testing.T) {
				db, err := Open(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				at := time.Now()
				paths := map[string]string{"/home/alice/site": "alice"}
				if updateErr := db.UpdateWPVerification("core", at.Add(time.Hour), scope, paths, nil, complete); updateErr != nil {
					t.Fatal(updateErr)
				}
				if updateErr := db.UpdateWPVerification("core", at, "", paths, map[string]WPVerificationResult{"/home/alice/site": {State: "verified"}}, true); updateErr != nil {
					t.Fatal(updateErr)
				}
				rows, err := db.WPVerification("core")
				row := rows["/home/alice/site"]
				if err != nil || row.State != "verified" || !row.AttemptAt.Equal(at) || !row.ObservedAt.Equal(at.Add(time.Hour)) {
					t.Fatalf("discovery discarded a completed attempt or moved backwards: %+v %v", row, err)
				}
			})
		}
	}
}

func TestWPVerificationOrdersOverlappingAttempts(t *testing.T) {
	for _, states := range [][]string{{"unverified", "unverified", "unverified"}, {"unverified", "verified", "unverified"}, {"unverified", "unverified", "verified"}} {
		for _, order := range [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
			db, err := Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			at := time.Now()
			paths := map[string]string{"/home/alice/site": "alice"}
			for _, index := range append(order, order...) {
				scope := ""
				if index == 1 {
					scope = "alice"
				}
				if updateErr := db.UpdateWPVerification("core", at.Add(time.Duration(index)*time.Hour), scope, paths, map[string]WPVerificationResult{"/home/alice/site": {State: states[index]}}, true); updateErr != nil {
					t.Fatal(updateErr)
				}
			}
			wantFailures := 2
			if states[1] == "verified" {
				wantFailures = 1
			}
			if states[2] == "verified" {
				wantFailures = 0
			}
			rows, err := db.WPVerification("core")
			row := rows["/home/alice/site"]
			if err != nil || row.State != states[2] || row.Failures != wantFailures || !row.AttemptAt.Equal(at.Add(2*time.Hour)) {
				t.Errorf("states=%v arrival=%v: wrong latest result or streak: %+v %v", states, order, row, err)
			}
		}
	}
}

func TestWPVerificationRemovedSiteRejectsOldAttemptsAfterRediscovery(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	at := time.Now()
	paths := map[string]string{"/home/alice/site": "alice"}
	result := map[string]WPVerificationResult{"/home/alice/site": {State: "unverified"}}
	for _, step := range []struct {
		tick    int
		paths   map[string]string
		results map[string]WPVerificationResult
	}{
		{0, paths, result},
		{2, nil, nil},
		{1, paths, result}, // An older scan cannot resurrect a removed site.
		{3, paths, nil},
		{1, paths, result}, // Nor attach the old failure to its replacement.
	} {
		if updateErr := db.UpdateWPVerification("core", at.Add(time.Duration(step.tick)*time.Hour), "alice", step.paths, step.results, true); updateErr != nil {
			t.Fatal(updateErr)
		}
	}
	rows, err := db.WPVerification("core")
	if err != nil || len(rows) != 1 || rows["/home/alice/site"].State != "" || rows["/home/alice/site"].Failures != 0 {
		t.Fatalf("removed history leaked into replacement installation: %+v %v", rows, err)
	}
}
