package ci

import (
	"os"
	"strings"
	"testing"
)

func TestReleaseRequiresCPanelBeforePublication(t *testing.T) {
	data, err := os.ReadFile("../../.gitlab-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	ci := string(data)
	preflight := gitlabJobBlock(t, ci, "release-preflight")
	if !strings.Contains(preflight, "stage: .pre") || !strings.Contains(preflight, "bash scripts/ci-cpanel-preflight.sh") {
		t.Fatal("release does not fail early on missing cPanel image")
	}
	integration := gitlabJobBlock(t, ci, "integration")
	if strings.Contains(integration, "releasing with Alma+Ubuntu integration only") {
		t.Fatal("release can omit cPanel")
	}
	if !strings.Contains(integration, "bash scripts/ci-cpanel-preflight.sh") {
		t.Fatal("integration can bypass preflight")
	}
	publish := gitlabJobBlock(t, ci, "publish:linux-amd64")
	tagRule := strings.Index(publish, "- if: $CI_COMMIT_TAG =~ /^v/")
	if tagRule < 0 || !strings.Contains(publish[tagRule:], "job: integration") || !strings.Contains(publish[tagRule:], "job: release-preflight") {
		t.Fatal("tag publication can bypass required integration or preflight")
	}
	for _, want := range []string{"scripts/ci-cpanel-package-test.sh", "dist/cpanel-package.log", "dist/cpanel-release.json"} {
		if !strings.Contains(integration, want) {
			t.Errorf("integration missing %s", want)
		}
	}
	// Without a licensed image the release still has to state, in its own
	// retained evidence, that the primary target was not exercised.
	if !strings.Contains(integration, `cpanel_coverage:"absent"`) {
		t.Error("a release without cPanel coverage does not record the gap in its evidence")
	}
}
