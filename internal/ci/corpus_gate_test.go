package ci

import (
	"os"
	"strings"
	"testing"
)

func TestCleanCorpusGateIsRequired(t *testing.T) {
	data, err := os.ReadFile("../../.gitlab-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	ci := string(data)
	gate := gitlabJobBlock(t, ci, "test:clean-corpus")
	for _, want := range []string{"${CSM_BUILDER_IMAGE}:${CSM_BUILDER_TAG}", "scripts/clean-corpus-test.sh", "when: always", "corpus-results/"} {
		if !strings.Contains(gate, want) {
			t.Errorf("clean corpus job missing %q", want)
		}
	}
	for _, disallowed := range []string{"allow_failure: true", "when: manual", "rules:"} {
		if strings.Contains(gate, disallowed) {
			t.Errorf("corpus job can be skipped: %s", disallowed)
		}
	}
	// Publishing has explicit DAG dependencies, so stage order alone cannot gate it.
	for _, job := range []string{"publish:linux-amd64", "release:github"} {
		if !strings.Contains(gitlabJobBlock(t, ci, job), "test:clean-corpus") {
			t.Errorf("%s can bypass clean corpus", job)
		}
	}
}
