package checks

import (
	"context"
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
	if !strings.Contains(res.Message, "2") {
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
func TestDBSpamPatterns_WeakKeywordsStillScanned(t *testing.T) {
	want := map[string]bool{"pharma": false, "betting": false, "viagra": true, "cialis": true}
	seen := map[string]bool{}
	for _, sp := range dbSpamPatterns {
		if deletable, ok := want[sp.keyword]; ok {
			seen[sp.keyword] = true
			if sp.deletable != deletable {
				t.Errorf("pattern %q: deletable = %v, want %v", sp.keyword, sp.deletable, deletable)
			}
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
	if strings.Contains(res.Message, "2") {
		t.Fatalf("a post matching two patterns must count once; got %q details %v",
			res.Message, res.Details)
	}
	if !strings.Contains(res.Message, "1") {
		t.Fatalf("expected a single spam post; got %q details %v", res.Message, res.Details)
	}
}
