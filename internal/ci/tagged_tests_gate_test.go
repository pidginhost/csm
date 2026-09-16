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
		if strings.HasPrefix(strings.TrimSpace(line), "- ") && strings.Contains(line, "go test") && strings.Contains(line, "FindingAttributesByPath") {
			tagged = line
		}
	}
	if tagged == "" {
		t.Fatal("clean corpus job has no yara-tagged go test line")
	}
	for _, want := range []string{"./internal/checks", "./internal/daemon", "FindingAttributesByPath", "-tags yara", "-count=1", "-v"} {
		if !strings.Contains(tagged, want) {
			t.Errorf("tagged test line missing %q: %s", want, tagged)
		}
	}
}

func TestCleanCorpusJobExecutesRuleScanBudget(t *testing.T) {
	data, err := os.ReadFile("../../.gitlab-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	gate := gitlabJobBlock(t, string(data), "test:clean-corpus")
	for _, want := range []string{"${CSM_BUILDER_IMAGE}:${CSM_BUILDER_TAG}", `CGO_ENABLED: "1"`, "resource_group: heavy-tests"} {
		if !strings.Contains(gate, want) {
			t.Errorf("scan budget job missing %q", want)
		}
	}
	var command string
	for _, line := range strings.Split(gate, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "- ") && strings.Contains(line, "go test") && strings.Contains(line, "TestShippedRulesScanWithinBudget") {
			command = line
		}
	}
	for _, want := range []string{"pkg-config --libs --static yara_x_capi", "-tags yara", "./internal/yara", "-count=1", "-v", "RuleScanBudget"} {
		if !strings.Contains(command, want) {
			t.Errorf("scan budget command missing %q: %s", want, command)
		}
	}
}
