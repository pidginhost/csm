package ci

import (
	"os"
	"strings"
	"testing"
)

func TestProductionTagsAndKernelGateAreRequired(t *testing.T) {
	data, err := os.ReadFile("../../.gitlab-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	ci := string(data)
	for _, name := range []string{"test:production", "test:kernel"} {
		job := gitlabJobBlock(t, ci, name)
		for _, prohibited := range []string{"allow_failure: true", "when: manual", "rules:"} {
			if strings.Contains(job, prohibited) {
				t.Errorf("%s can be skipped: %s", name, prohibited)
			}
		}
		if !strings.Contains(job, "when: always") || !strings.Contains(job, "production-results/") {
			t.Errorf("%s does not preserve execution evidence", name)
		}
		for _, publisher := range []string{"publish", "release:github"} {
			block := gitlabJobBlock(t, ci, publisher)
			if !strings.Contains(block, "job: "+name) {
				t.Errorf("%s bypasses %s", publisher, name)
			}
			if rule := strings.Index(block, "- if: $CI_COMMIT_TAG =~ /^v/"); rule >= 0 && strings.Contains(block[rule:], "needs:") && !strings.Contains(block[rule:], "job: "+name) {
				t.Errorf("tag %s bypasses %s", publisher, name)
			}
		}
	}
	job := gitlabJobBlock(t, ci, "test:production")
	if !strings.Contains(job, "scripts/production-tests.sh") || !strings.Contains(job, "${CSM_BUILDER_IMAGE}:${CSM_BUILDER_TAG}") {
		t.Fatal("production gate does not use the shipped engine")
	}
	job = gitlabJobBlock(t, ci, "test:kernel")
	if !strings.Contains(job, "scripts/go-linux.sh") || !strings.Contains(job, "scripts/systemd-account-roots-test.sh") {
		t.Fatal("kernel gate does not boot an isolated service")
	}
}
