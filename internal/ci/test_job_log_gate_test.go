package ci

import (
	"os"
	"strings"
	"testing"
)

// The test job's verbose transcript passed GitLab's 4 MB log cap long before
// the suite ended, so a failing test showed only as a script failure. Without
// -v, go test prints each failing test's output and one line per package.
func TestTestJobKeepsFailuresInTheLog(t *testing.T) {
	data, err := os.ReadFile("../../.gitlab-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	runs := 0
	for _, line := range strings.Split(gitlabJobBlock(t, string(data), "test"), "\n") {
		if !strings.Contains(line, "go test ") {
			continue
		}
		runs++
		for _, field := range strings.Fields(line) {
			if field == "-v" || strings.HasPrefix(field, "-v=") || field == "-test.v" {
				t.Errorf("test job runs a verbose suite, which overflows the job log: %s", strings.TrimSpace(line))
			}
		}
	}
	if runs == 0 {
		t.Fatal("test job runs no go test command")
	}
}
