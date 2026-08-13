package checks

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/mysqlclient"
)

// wpConfigMockOS returns a mockOS that serves one wp-config.php for the
// given account so findCredsForAccount resolves a database and prefix.
func wpConfigMockOS(t *testing.T, account, dbName string) *mockOS {
	t.Helper()
	body := "<?php\n" +
		"define( 'DB_NAME', '" + dbName + "' );\n" +
		"define( 'DB_USER', 'wpuser' );\n" +
		"define( 'DB_PASSWORD', 'x' );\n" +
		"define( 'DB_HOST', 'localhost' );\n" +
		"$table_prefix = 'wp_';\n"
	want := "/home/" + account + "/public_html/wp-config.php"
	return &mockOS{
		glob: func(string) ([]string, error) { return nil, nil },
		open: func(path string) (*os.File, error) {
			if path != want {
				return nil, os.ErrNotExist
			}
			f, err := os.CreateTemp(t.TempDir(), "wpconfig")
			if err != nil {
				return nil, err
			}
			if _, err := f.WriteString(body); err != nil {
				_ = f.Close()
				return nil, err
			}
			if _, err := f.Seek(0, 0); err != nil {
				_ = f.Close()
				return nil, err
			}
			return f, nil
		},
	}
}

// stubRootQuery installs a root-query interceptor returning rows for any
// query whose text contains one of the given fragments.
func stubRootQuery(t *testing.T, rowsFor map[string][]string) {
	t.Helper()
	mysqlclient.SetRootQueryForTest(func(_ context.Context, _ string, query string, _ ...any) ([]string, error) {
		for fragment, rows := range rowsFor {
			if strings.Contains(query, fragment) {
				return rows, nil
			}
		}
		return nil, nil
	})
	t.Cleanup(func() { mysqlclient.SetRootQueryForTest(nil) })
}

// A post containing "cialis" only inside the word "specialist" is NOT
// spam. The SQL LIKE pre-filter matches it, so the Go-side word-boundary
// test is the only thing standing between a live news site and having its
// articles deleted. This is the zepcontro production case: 41k published
// posts, "medic specialist oftalmolog", zero real pharma spam.
func TestDBDeleteSpam_SkipsSubstringOnlyMatches(t *testing.T) {
	withMockOS(t, wpConfigMockOS(t, "newssite", "news_wp"))
	stubRootQuery(t, map[string][]string{
		"%cialis%": {
			"101\tmedic specialist oftalmolog explains the procedure",
			"102\tKPMG promoveaza mai multi specialisti in functiile de Partener",
		},
		"%pharma%": {
			"103\ta pharmaceutical trial reported new results",
		},
	})

	res := DBDeleteSpam("newssite", true)

	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}
	if res.Message != "No spam posts found" {
		t.Fatalf("substring-only matches must not be reported as spam; got message %q details %v",
			res.Message, res.Details)
	}
}

// The word-boundary fix must not blind the cleaner to real spam.
func TestDBDeleteSpam_StillDetectsRealSpam(t *testing.T) {
	withMockOS(t, wpConfigMockOS(t, "hacked", "hacked_wp"))
	stubRootQuery(t, map[string][]string{
		"%cialis%": {
			"201\tbuy cialis online no prescription cheap",
			"202\tmedic specialist oftalmolog",
		},
		"%viagra%": {
			"203\tgeneric viagra fast shipping",
		},
	})

	res := DBDeleteSpam("hacked", true)

	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}
	if res.Message != "PREVIEW: Would delete 2 spam posts" {
		t.Fatalf("expected exactly 2 real spam posts in preview; got message %q details %v",
			res.Message, res.Details)
	}
}

// Some keywords are real spam indicators but are also ordinary words in
// legitimate journalism: "Pharma" in a conference name, "betting" in
// business coverage of a licensed bookmaker. Word boundaries do not
// separate those cases, so they must never authorise a DELETE on their
// own. The scanner still flags them for human review; only the
// destructive path is restricted.
func TestDBDeleteSpam_WeakKeywordsDoNotAuthoriseDeletion(t *testing.T) {
	withMockOS(t, wpConfigMockOS(t, "business", "biz_wp"))
	stubRootQuery(t, map[string][]string{
		"%pharma%":  {"401\tUrmeaza conferinta ZF Health and Pharma Summit"},
		"%betting%": {"402\tSacha Dragic on the betting industry going global"},
	})

	res := DBDeleteSpam("business", true)

	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}
	if res.Message != "No spam posts found" {
		t.Fatalf("weak keywords alone must not schedule a deletion; got %q details %v",
			res.Message, res.Details)
	}
}

// The weak-keyword restriction must not disable the scanner's view of
// them: every pattern the scanner uses stays in dbSpamPatterns, and only
// a documented subset is marked deletable.
func TestDBSpamPatterns_DeletionPolicy(t *testing.T) {
	want := map[string]bool{
		"viagra":        true,
		"cialis":        true,
		"pharma":        false,
		"betting":       false,
		"casino-":       true,
		"buy-cheap-":    true,
		"free-download": true,
		"crack-serial":  true,
	}
	seen := map[string]bool{}
	for _, sp := range dbSpamPatterns {
		deletable, ok := want[sp.keyword]
		if !ok {
			t.Errorf("unexpected spam pattern %q", sp.keyword)
			continue
		}
		seen[sp.keyword] = true
		if sp.deletable != deletable {
			t.Errorf("pattern %q: deletable = %v, want %v", sp.keyword, sp.deletable, deletable)
		}
	}
	for k := range want {
		if !seen[k] {
			t.Errorf("pattern %q missing from dbSpamPatterns; scanner coverage lost", k)
		}
	}
}

// A post matching two spam patterns is one post, not two. The old
// implementation summed per-pattern COUNT(*) results, inflating the
// preview count and misleading the operator about deletion scope.
func TestDBDeleteSpam_CountsEachPostOnce(t *testing.T) {
	withMockOS(t, wpConfigMockOS(t, "dupes", "dupes_wp"))
	stubRootQuery(t, map[string][]string{
		"%cialis%": {"301\tbuy cialis and viagra together"},
		"%viagra%": {"301\tbuy cialis and viagra together"},
	})

	res := DBDeleteSpam("dupes", true)

	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}
	if res.Message != "PREVIEW: Would delete 1 spam post" {
		t.Fatalf("a post matching two patterns must count once; got %q details %v",
			res.Message, res.Details)
	}
	details := strings.Join(res.Details, "\n")
	if !strings.Contains(details, "counts overlap") {
		t.Fatalf("overlapping per-keyword counts must be labelled; got %v", res.Details)
	}
	if !strings.Contains(details, "1 unique post") {
		t.Fatalf("details must state the deduplicated total; got %v", res.Details)
	}
}

func TestDBDeleteSpam_UsesUnicodeWordBoundaries(t *testing.T) {
	withMockOS(t, wpConfigMockOS(t, "unicode", "unicode_wp"))
	stubRootQuery(t, map[string][]string{
		"%cialis%": {
			"501\tșcialisă is one longer Unicode word",
			"502\t药cialis店 is one longer Unicode word",
		},
	})

	res := DBDeleteSpam("unicode", true)

	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}
	if res.Message != "No spam posts found" {
		t.Fatalf("Unicode substring-only matches must not be deletable; got %q details %v",
			res.Message, res.Details)
	}
}

func TestDBDeleteSpam_RequiresRightBoundaryForWordEndingPatterns(t *testing.T) {
	withMockOS(t, wpConfigMockOS(t, "suffixes", "suffixes_wp"))
	stubRootQuery(t, map[string][]string{
		"%free-download%": {"511\ta free-downloadable guide"},
		"%crack-serial%":  {"512\tcrack-serialization format notes"},
	})

	res := DBDeleteSpam("suffixes", true)

	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}
	if res.Message != "No spam posts found" {
		t.Fatalf("patterns ending in a word character need a right boundary; got %q details %v",
			res.Message, res.Details)
	}
}

func TestDBDeleteSpam_QueryFailureDoesNotReportNoSpam(t *testing.T) {
	withMockOS(t, wpConfigMockOS(t, "queryfail", "queryfail_wp"))
	mysqlclient.SetRootQueryForTest(func(_ context.Context, _ string, query string, _ ...any) ([]string, error) {
		if strings.Contains(query, "%cialis%") {
			return nil, errors.New("connection lost")
		}
		return nil, nil
	})
	t.Cleanup(func() { mysqlclient.SetRootQueryForTest(nil) })

	res := DBDeleteSpam("queryfail", true)

	if res.Success {
		t.Fatalf("query failure must fail closed, got %+v", res)
	}
	if res.Message != `Failed to query spam posts for "cialis": connection lost` {
		t.Fatalf("query failure must be visible to the operator; got %q", res.Message)
	}
}

func TestDBDeleteSpam_DeleteFailureDoesNotReportSuccess(t *testing.T) {
	withMockOS(t, wpConfigMockOS(t, "deletefail", "deletefail_wp"))
	stubRootQuery(t, map[string][]string{
		"%cialis%": {"521\tbuy cialis online"},
	})

	var statements []string
	mysqlclient.SetRootExecForTest(func(_ context.Context, _ string, stmt string, _ ...any) (int64, error) {
		statements = append(statements, stmt)
		if strings.Contains(stmt, "WHERE ID IN") {
			return 0, errors.New("server rejected delete")
		}
		return 1, nil
	})
	t.Cleanup(func() { mysqlclient.SetRootExecForTest(nil) })

	res := DBDeleteSpam("deletefail", false)

	if res.Success {
		t.Fatalf("failed DELETE must not report success, got %+v", res)
	}
	wantMessage := "Spam cleanup failed after deleting 0 spam posts: delete posts: server rejected delete"
	if res.Message != wantMessage {
		t.Fatalf("delete error must be reported without claiming success; got %q, want %q",
			res.Message, wantMessage)
	}
	if len(statements) != 3 {
		t.Fatalf("expected metadata, revision, and post DELETE attempts, got %d: %v", len(statements), statements)
	}
}

func TestDBDeleteSpam_StopsAtFirstFailedDeleteStatement(t *testing.T) {
	tests := []struct {
		name        string
		failureCall int
		wantAction  string
	}{
		{name: "metadata", failureCall: 1, wantAction: "delete post metadata"},
		{name: "revisions", failureCall: 2, wantAction: "delete post revisions"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withMockOS(t, wpConfigMockOS(t, "stopfail", "stopfail_wp"))
			stubRootQuery(t, map[string][]string{
				"%cialis%": {"523\tbuy cialis online"},
			})

			calls := 0
			mysqlclient.SetRootExecForTest(func(_ context.Context, _ string, _ string, _ ...any) (int64, error) {
				calls++
				if calls == tc.failureCall {
					return 0, errors.New("write failed")
				}
				return 1, nil
			})
			t.Cleanup(func() { mysqlclient.SetRootExecForTest(nil) })

			res := DBDeleteSpam("stopfail", false)

			if res.Success {
				t.Fatalf("failed DELETE must not report success, got %+v", res)
			}
			if calls != tc.failureCall {
				t.Fatalf("cleanup continued after failed statement: got %d calls, want %d", calls, tc.failureCall)
			}
			if !strings.Contains(res.Message, tc.wantAction+": write failed") {
				t.Fatalf("message %q does not identify failed action %q", res.Message, tc.wantAction)
			}
		})
	}
}

func TestDBDeleteSpam_ReportsRowsActuallyDeleted(t *testing.T) {
	withMockOS(t, wpConfigMockOS(t, "affected", "affected_wp"))
	stubRootQuery(t, map[string][]string{
		"%cialis%": {
			"525\tbuy cialis online",
			"526\tcheap cialis here",
		},
	})

	mysqlclient.SetRootExecForTest(func(_ context.Context, _ string, stmt string, _ ...any) (int64, error) {
		if strings.Contains(stmt, "WHERE ID IN") {
			return 1, nil
		}
		return 2, nil
	})
	t.Cleanup(func() { mysqlclient.SetRootExecForTest(nil) })

	res := DBDeleteSpam("affected", false)

	if !res.Success {
		t.Fatalf("successful DELETE must succeed, got %+v", res)
	}
	wantMessage := "Deleted 1 spam post and its metadata; 1 candidate was not deleted"
	if res.Message != wantMessage {
		t.Fatalf("message must use the affected-row count and disclose unmatched candidates; got %q, want %q",
			res.Message, wantMessage)
	}
}

func TestDBDeleteSpam_DecodesControlsWithoutDesynchronisingRows(t *testing.T) {
	withMockOS(t, wpConfigMockOS(t, "controls", "controls_wp"))
	stubRootQuery(t, map[string][]string{
		"%cialis%": {"531\tfirst line\\ncialis online\\tfirst post"},
		"%viagra%": {"532\tsecond line\\tviagra online"},
	})

	res := DBDeleteSpam("controls", true)

	if !res.Success || res.Message != "PREVIEW: Would delete 2 spam posts" {
		t.Fatalf("batch-escaped controls must preserve boundaries and candidate rows; got %+v", res)
	}
}

func TestDBDeleteSpam_NullTitleStillLeavesMatchableContent(t *testing.T) {
	withMockOS(t, wpConfigMockOS(t, "nulltitle", "nulltitle_wp"))
	usedConcatWS := false
	mysqlclient.SetRootQueryForTest(func(_ context.Context, _ string, query string, _ ...any) ([]string, error) {
		if strings.Contains(query, "%cialis%") {
			usedConcatWS = strings.Contains(query, "CONCAT_WS(' ', post_title, post_content)")
			return []string{"541\tbuy cialis online"}, nil
		}
		return nil, nil
	})
	t.Cleanup(func() { mysqlclient.SetRootQueryForTest(nil) })

	res := DBDeleteSpam("nulltitle", true)

	if !usedConcatWS {
		t.Fatal("candidate query must use CONCAT_WS so a NULL title does not null the content")
	}
	if !res.Success || res.Message != "PREVIEW: Would delete 1 spam post" {
		t.Fatalf("content must remain matchable when title is NULL; got %+v", res)
	}
}

func TestDBDeleteSpam_DoesNotReconstructKeywordsAcrossHTMLTags(t *testing.T) {
	withMockOS(t, wpConfigMockOS(t, "splittag", "splittag_wp"))
	stubRootQuery(t, map[string][]string{
		"%cialis%": {"551\tbuy c<i>ialis</i> online"},
	})

	res := DBDeleteSpam("splittag", true)

	if !res.Success || res.Message != "No spam posts found" {
		t.Fatalf("split-tag text is a safe false negative for the destructive path; got %+v", res)
	}
}
