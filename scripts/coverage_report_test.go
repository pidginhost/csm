package scripts

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The published coverage profile belongs to a release tag, while the docs
// workflow runs on whatever main commit the mirror pushed. A file the release
// covered can be gone from main, and go tool cover cannot render a profile
// without the sources it names.

const coverageFixtureSource = `package cov

func Covered() int {
	return 1
}
`

func gitInDir(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// releasedThenDeletedRepo builds a module whose v1.0.0 tag has two files and
// whose HEAD has deleted one of them, and returns the repo and a profile that
// names both files.
func releasedThenDeletedRepo(t *testing.T) (repo, profile string) {
	t.Helper()
	repo = t.TempDir()
	files := map[string]string{
		"go.mod":  "module example.com/cov\n\ngo 1.21\n",
		"kept.go": coverageFixtureSource,
		"gone.go": strings.Replace(coverageFixtureSource, "Covered", "Removed", 1),
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(repo, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	gitInDir(t, repo, "init", "-q")
	gitInDir(t, repo, "add", ".")
	gitInDir(t, repo, "commit", "-q", "-m", "release")
	gitInDir(t, repo, "tag", "v1.0.0")
	gitInDir(t, repo, "rm", "-q", "gone.go")
	gitInDir(t, repo, "commit", "-q", "-m", "drop a file")

	profile = filepath.Join(t.TempDir(), "coverage.out")
	body := "mode: set\nexample.com/cov/kept.go:3.21,5.2 1 1\nexample.com/cov/gone.go:3.21,5.2 1 0\n"
	if err := os.WriteFile(profile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return repo, profile
}

func runCoverageReport(t *testing.T, repo, profile, tag, outDir string) (string, int) {
	t.Helper()
	script, err := filepath.Abs("coverage-report.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(script, profile, tag, outDir)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "GOFLAGS=", "GOTOOLCHAIN=local",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("running coverage-report.sh: %v\n%s", err, out)
		}
		code = exitErr.ExitCode()
	}
	return string(out), code
}

func TestCoverageReportRendersFromTheProfilesReleaseSources(t *testing.T) {
	repo, profile := releasedThenDeletedRepo(t)
	outDir := t.TempDir()

	out, code := runCoverageReport(t, repo, profile, "v1.0.0", outDir)
	if code != 0 {
		t.Fatalf("coverage-report.sh exited %d:\n%s", code, out)
	}
	html, err := os.ReadFile(filepath.Join(outDir, "coverage.html"))
	if err != nil {
		t.Fatalf("coverage.html not written: %v", err)
	}
	if !strings.Contains(string(html), "example.com/cov/gone.go") {
		t.Error("coverage.html does not include the file deleted after the release")
	}
	funcs, err := os.ReadFile(filepath.Join(outDir, "coverage-func.txt"))
	if err != nil {
		t.Fatalf("coverage-func.txt not written: %v", err)
	}
	if !strings.Contains(string(funcs), "total:") || !strings.Contains(string(funcs), "50.0%") {
		t.Errorf("function summary lacks the 50%% total:\n%s", funcs)
	}
	if entries, err := os.ReadDir(filepath.Join(repo, ".git", "worktrees")); err == nil && len(entries) != 0 {
		t.Errorf("temporary worktree left registered: %d entries", len(entries))
	}
}

func TestCoverageReportFailsForAnUnknownTag(t *testing.T) {
	repo, profile := releasedThenDeletedRepo(t)
	if _, code := runCoverageReport(t, repo, profile, "v9.9.9", t.TempDir()); code == 0 {
		t.Fatal("coverage-report.sh succeeded for a tag that does not exist")
	}
}
