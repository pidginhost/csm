package store

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func countHistoryDecodes(t *testing.T) *int {
	t.Helper()
	n := 0
	old := decodeHistoryEntry
	decodeHistoryEntry = func(v []byte, f *alert.Finding) error {
		n++
		return old(v, f)
	}
	t.Cleanup(func() { decodeHistoryEntry = old })
	return &n
}

// Counting matches for the page total walks the filtered range. Entries whose
// stored bytes cannot match the severity, check or search filter are skipped
// without decoding them.
func TestFilteredHistorySkipsEntriesThatCannotMatch(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	var findings []alert.Finding
	for i := 0; i < 1000; i++ {
		findings = append(findings, alert.Finding{Timestamp: now.Add(-time.Duration(i) * time.Second), Severity: alert.Warning, Check: "perf_memory", Message: fmt.Sprintf("noise %d", i)})
	}
	findings = append(findings,
		alert.Finding{Timestamp: now, Severity: alert.Critical, Check: "webshell", Message: "needle one"},
		alert.Finding{Timestamp: now, Severity: alert.Critical, Check: "webshell", Message: "needle two"},
	)
	writeFindings(t, db, findings)

	decodes := countHistoryDecodes(t)
	cases := []struct {
		name     string
		severity int
		search   string
		checks   map[string]bool
	}{
		{"severity", int(alert.Critical), "", nil},
		{"check", -1, "", map[string]bool{"webshell": true}},
		{"search", -1, "NEEDLE", nil},
	}
	for _, tc := range cases {
		*decodes = 0
		got, total := db.ReadHistoryFilteredWithChecks(50, 0, "", "", tc.severity, tc.search, tc.checks)
		if total != 2 || len(got) != 2 {
			t.Fatalf("%s: total=%d len=%d, want the two needles", tc.name, total, len(got))
		}
		if *decodes > 10 {
			t.Errorf("%s: decoded %d entries to find 2", tc.name, *decodes)
		}
	}
}

// JSON escapes some characters in stored text ("<" becomes <). A search
// for text containing them must still find it.
func TestFilteredHistorySearchFindsEscapedText(t *testing.T) {
	db := openTestDB(t)
	writeFindings(t, db, []alert.Finding{
		{Timestamp: time.Now(), Severity: alert.High, Check: "webshell", Message: `Found <?php eval("x") & more`},
	})
	for _, term := range []string{"<?php", `eval("x")`, "& more"} {
		if _, total := db.ReadHistoryFilteredWithChecks(10, 0, "", "", -1, term, nil); total != 1 {
			t.Errorf("search %q found %d, want 1", term, total)
		}
	}
}
