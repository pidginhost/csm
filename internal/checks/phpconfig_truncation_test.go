package checks

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// "Could not finish scanning PHP configuration files below <root>" reads like a
// transient read error, so a walk that stopped because it ran out of allowance
// looked the same as one that hit an unreadable directory. On a real account
// the per-root ceiling was reached every single day and roughly half the
// directories were never looked at, silently. The reason has to say which bound
// stopped it, how far it got, and which setting raises it.

func TestPHPIniIncompleteReasonNamesTheBudgetAndTheSetting(t *testing.T) {
	b := &phpIniWalkBudget{dirs: 10000, entries: 4211}
	b.limitHit = true

	reason := phpIniIncompleteReason("/home/example/public_html", b)

	for _, want := range []string{
		"/home/example/public_html",
		strconv.Itoa(10000),
		"php_config_walk_max_dirs",
	} {
		if !strings.Contains(reason, want) {
			t.Errorf("reason %q does not mention %q", reason, want)
		}
	}
}

func TestPHPIniIncompleteReasonDistinguishesUnreadableEntries(t *testing.T) {
	b := &phpIniWalkBudget{dirs: 12, entries: 30}

	reason := phpIniIncompleteReason("/home/example/public_html", b)

	if strings.Contains(reason, "php_config_walk_max_dirs") {
		t.Errorf("reason %q blames the budget for a walk that never reached it", reason)
	}
	if !strings.Contains(reason, "/home/example/public_html") {
		t.Errorf("reason %q does not name the root", reason)
	}
}

// The walk must record that a ceiling stopped it, otherwise the reason cannot
// tell the two causes apart.
func TestWalkRecordsThatTheDirectoryCeilingStoppedIt(t *testing.T) {
	withWalkLimits(t, 3, 1000)
	root := filepath.Join(t.TempDir(), "r")
	makeDirTree(t, root, 8)

	budget := &phpIniWalkBudget{}
	_, complete := collectPHPIniFilesWithBudget(context.Background(), root, -1, budget)

	if complete {
		t.Fatal("walk reported complete despite exceeding the directory ceiling")
	}
	if !budget.limitHit {
		t.Error("walk did not record that a configured ceiling stopped it")
	}
}

// The operator-set ceiling has to reach the walk. Carrying it on the budget
// rather than mutating the package var keeps concurrent per-account scans from
// overwriting each other's limit.
func TestWalkHonoursPerBudgetDirectoryLimit(t *testing.T) {
	withWalkLimits(t, 100000, 1000000)
	root := filepath.Join(t.TempDir(), "r")
	makeDirTree(t, root, 8)

	budget := &phpIniWalkBudget{maxDirs: 3}
	_, complete := collectPHPIniFilesWithBudget(context.Background(), root, -1, budget)

	if complete {
		t.Fatal("walk ignored the budget's own directory limit and used the package default")
	}
	if !budget.limitHit {
		t.Error("walk did not record that the budget limit stopped it")
	}
}
