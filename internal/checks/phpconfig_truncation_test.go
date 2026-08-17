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
	b.limitKind = walkLimitDirs

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
	if budget.limitKind == walkLimitNone {
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
	if budget.limitKind == walkLimitNone {
		t.Error("walk did not record that the budget limit stopped it")
	}
}

// Two different ceilings can stop the walk, and they are raised by two
// different settings. A root with few directories but a very large number of
// entries hits the entry ceiling; naming the directory setting there sends the
// operator to a knob that will not help.
func TestPHPIniIncompleteReasonNamesTheEntryCeiling(t *testing.T) {
	b := &phpIniWalkBudget{dirs: 3340, entries: 250001}
	b.limitKind = walkLimitEntries

	reason := phpIniIncompleteReason("/home/example/public_html", b)

	if !strings.Contains(reason, "php_config_walk_max_entries") {
		t.Errorf("reason %q does not name the entry setting", reason)
	}
	if strings.Contains(reason, "php_config_walk_max_dirs") {
		t.Errorf("reason %q blames the directory setting for an entry-ceiling stop", reason)
	}
	if !strings.Contains(reason, strconv.Itoa(250001)) {
		t.Errorf("reason %q does not report how many entries were examined", reason)
	}
}

func TestWalkRecordsWhichCeilingStoppedIt(t *testing.T) {
	root := filepath.Join(t.TempDir(), "r")
	makeDirTree(t, root, 12)

	budget := &phpIniWalkBudget{maxEntries: 4}
	_, complete := collectPHPIniFilesWithBudget(context.Background(), root, -1, budget)

	if complete {
		t.Fatal("walk reported complete despite exceeding the entry ceiling")
	}
	if budget.limitKind != walkLimitEntries {
		t.Errorf("limitKind = %v, want the entry ceiling", budget.limitKind)
	}
}
