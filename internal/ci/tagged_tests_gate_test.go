package ci

import (
	"os"
	"strings"
	"testing"
)

// The yara-tagged attribution tests are compiled by lint:tagged but no
// untagged job can execute them; the clean-corpus job runs on the builder
// image that links yara-x, so it must run them or their evidence is only
// that they compile.
func TestCleanCorpusJobExecutesTaggedAttributionTests(t *testing.T) {
	data, err := os.ReadFile("../../.gitlab-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	gate := gitlabJobBlock(t, string(data), "test:clean-corpus")
	var tagged string
	for _, line := range strings.Split(gate, "\n") {
		if strings.Contains(line, "go test") && strings.Contains(line, "-tags yara") {
			tagged = line
		}
	}
	if tagged == "" {
		t.Fatal("clean corpus job has no yara-tagged go test line")
	}
	for _, want := range []string{"./internal/checks", "./internal/daemon", "FindingAttributesByPath", "-count=1", "-v"} {
		if !strings.Contains(tagged, want) {
			t.Errorf("tagged test line missing %q: %s", want, tagged)
		}
	}
}
