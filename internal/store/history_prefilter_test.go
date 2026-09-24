package store

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	bolt "go.etcd.io/bbolt"
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

func TestHistoryPrefilterPreservesDecodedMatches(t *testing.T) {
	db := openTestDB(t)
	for _, raw := range []string{
		`{"severity":1,"check":"webshell","message":"Kelvin \u212a and \u006eEEDLE"}`,
		`{"severity":1,"check":"web\u0073hell","message":"needle"}`,
		`{ "severity" : 1, "check" : "webshell", "message" : "needle" }`,
		`{"Severity":1,"CHECK":"webshell","MESSAGE":"needle"}`,
		`{"\u0073everity":1,"check":"webshell","message":"needle"}`,
		`{"severity":0,"Severity":1,"check":"old","Check":"webshell","message":"needle"}`,
		`{"severity":-0,"check":"","message":"needle"}`,
		`{"severity":null,"check":null,"message":"needle"}`,
		`{"message":"needle"}`,
	} {
		t.Run(raw, func(t *testing.T) {
			var f alert.Finding
			if err := json.Unmarshal([]byte(raw), &f); err != nil {
				t.Fatal(err)
			}
			if err := db.bolt.Update(func(tx *bolt.Tx) error {
				return tx.Bucket([]byte("history")).Put([]byte(TimeKey(time.Now(), 0)), []byte(raw))
			}); err != nil {
				t.Fatal(err)
			}
			for _, query := range []struct {
				severity int
				search   string
				checks   map[string]bool
			}{
				{int(f.Severity), "", nil},
				{-1, "", map[string]bool{f.Check: true}},
				{-1, "needle", nil},
			} {
				if !historyPrefilter(query.severity, query.search, query.checks)([]byte(raw)) {
					t.Errorf("prefilter excluded a decoded match: %+v", query)
				}
			}
		})
	}
	// The production reader must also return escaped matches and their count.
	rows, total := db.ReadHistoryFilteredWithChecks(20, 0, "", "", 1, "needle", map[string]bool{"webshell": true})
	if total != 6 || len(rows) != 6 {
		t.Fatalf("got %d rows, total=%d, want all 6 matching persisted rows", len(rows), total)
	}
}

func FuzzHistoryPrefilterConservative(f *testing.F) {
	for _, raw := range []string{
		`{"severity":1,"check":"webshell","message":"needle"}`,
		`{"severity":null,"check":"web\u0073hell","message":"\u006eEEDLE"}`,
		`{"Severity":2,"Check":"webshell","details":"Kelvin K and \u212a"}`,
		`{"severity":-0}`, `null`,
	} {
		f.Add(raw, "needle")
	}
	f.Fuzz(func(t *testing.T, raw, search string) {
		var finding alert.Finding
		if json.Unmarshal([]byte(raw), &finding) != nil {
			return
		}
		checks := map[string]bool{finding.Check: true}
		if !historyPrefilter(int(finding.Severity), "", checks)([]byte(raw)) {
			t.Fatal("prefilter rejected matching severity/check")
		}
		lower := strings.ToLower(search)
		if containsLower(finding.Check, lower) || containsLower(finding.Message, lower) || containsLower(finding.Details, lower) {
			if !historyPrefilter(-1, lower, nil)([]byte(raw)) {
				t.Fatal("prefilter rejected matching search")
			}
		}
	})
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

func TestFilteredHistoryPrefiltersWarningSeverity(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	findings := make([]alert.Finding, 1000)
	for i := range findings {
		findings[i] = alert.Finding{Timestamp: now, Severity: alert.High, Check: "webshell"}
	}
	findings = append(findings, alert.Finding{Timestamp: now, Severity: alert.Warning, Check: "perf_memory"})
	writeFindings(t, db, findings)
	decodes := countHistoryDecodes(t)
	rows, total := db.ReadHistoryFiltered(10, 0, "", "", int(alert.Warning), "")
	if len(rows) != 1 || total != 1 || *decodes > 10 {
		t.Fatalf("rows=%d total=%d decodes=%d; want one warning without decoding the high-severity rows", len(rows), total, *decodes)
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
