package ci

import (
	"os"
	"strings"
	"testing"
)

// The dashboard's JavaScript tests run through scripts/uitest, which skips
// when node is absent. The Go CI images carried no node, so those tests never
// ran in CI and a broken bulk-action or incident page shipped green. The test
// job must provide node and require it, so a missing runtime fails instead of
// passing as a quiet skip.
func TestTestJobRequiresNodeForUITests(t *testing.T) {
	data, err := os.ReadFile("../../.gitlab-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	job := gitlabJobBlock(t, string(data), "test")
	for _, want := range []string{"${CSM_CI_TOOLS_IMAGE}:${CSM_CI_TOOLS_TAG}", `CSM_REQUIRE_NODE: "1"`} {
		if !strings.Contains(job, want) {
			t.Errorf("test job missing %q", want)
		}
	}

	image, err := os.ReadFile("../../build/Dockerfile.ci-tools")
	if err != nil {
		t.Fatal(err)
	}
	// A pinned official image, not the distribution package: Debian's node in
	// the Go base image is past upstream end of life.
	if !strings.Contains(string(image), "COPY --from=node:24.") || !strings.Contains(string(image), "/usr/local/bin/node /usr/local/bin/node") {
		t.Error("ci-tools image does not install node from a pinned node 24 image")
	}
}
