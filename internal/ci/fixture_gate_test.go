package ci

import (
	"os"
	"strings"
	"testing"
)

func TestFixturePrivacyGateIsRequired(t *testing.T) {
	data, err := os.ReadFile("../../.gitlab-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	ci := string(data)
	job := gitlabJobBlock(t, ci, "check-fixtures")
	if !strings.Contains(job, "scripts/check-fixtures.sh") {
		t.Fatal("fixture scanner is not executed")
	}
	for _, skip := range []string{"allow_failure: true", "when: manual", "rules:"} {
		if strings.Contains(job, skip) {
			t.Fatalf("fixture job can be skipped: %s", skip)
		}
	}
	for _, name := range []string{"publish:linux-amd64", "release:github"} {
		block := gitlabJobBlock(t, ci, name)
		if !strings.Contains(block, "job: check-fixtures") {
			t.Errorf("%s bypasses fixture gate", name)
		}
		if rule := strings.Index(block, "- if: $CI_COMMIT_TAG =~ /^v/"); rule >= 0 && strings.Contains(block[rule:], "needs:") && !strings.Contains(block[rule:], "job: check-fixtures") {
			t.Errorf("tag %s bypasses fixture gate", name)
		}
	}
}
