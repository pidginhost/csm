package ci

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepoPublishProtectsYaraForgeMirror(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", ".gitlab-ci.yml"))
	if err != nil {
		t.Fatalf("read .gitlab-ci.yml: %v", err)
	}
	ci := string(body)

	repoPublish := gitlabJobBlock(t, ci, "repo:publish")
	for _, want := range []string{
		"rsync -avz --delete --filter 'P /yara-forge/***' \\",
		"dist/repo-out/ \\",
		`"${MIRROR_USER}@${MIRROR_HOST}:${MIRROR_PATH}"`,
	} {
		if !strings.Contains(repoPublish, want) {
			t.Fatalf("repo:publish missing %q", want)
		}
	}
	if strings.Contains(repoPublish, "--exclude '/yara-forge/'") {
		t.Fatal("repo:publish must use a receiver-side protect filter, not a source-side exclude")
	}

	yaraMirror := gitlabJobBlock(t, ci, "yara-forge-mirror")
	if !strings.Contains(yaraMirror, `"${MIRROR_USER}@${MIRROR_HOST}:/yara-forge/"`) {
		t.Fatal("yara-forge-mirror remote path changed without updating repo:publish protection")
	}
}

func TestReleaseCriticalJobsAreBlocking(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", ".gitlab-ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	ci := string(body)
	for _, job := range []string{"integration", "deploy:github", "release:github"} {
		block := gitlabJobBlock(t, ci, job)
		if strings.Contains(block, "allow_failure: true") {
			t.Errorf("%s remains non-blocking", job)
		}
	}
	for _, job := range []string{"build:linux-arm64", "package:linux-arm64"} {
		block := gitlabJobBlock(t, ci, job)
		if !strings.Contains(block, "if: $CI_COMMIT_TAG =~ /^v/\n      allow_failure: false") {
			t.Errorf("%s does not make tag builds blocking", job)
		}
	}
	release := gitlabJobBlock(t, ci, "release:github")
	if strings.Contains(release, "optional: true") {
		t.Fatal("release:github has optional build, package, signing, or integration dependencies")
	}
	if !strings.Contains(release, "UPLOAD_RESP=$(curl -fsS -X POST") {
		t.Fatal("release asset upload must fail the job on an HTTP error")
	}
	preflight := strings.Index(release, "Required release asset missing")
	create := strings.Index(release, "Creating GitHub release")
	if preflight < 0 || create < 0 || preflight > create {
		t.Fatal("release asset preflight must pass before a GitHub release is created")
	}
	sign := gitlabJobBlock(t, ci, "sign:artifacts")
	if !strings.Contains(sign, "CSM_SIGNING_KEY is required for tag releases") {
		t.Fatal("tag signing job does not require the release signing key")
	}
	integration := gitlabJobBlock(t, ci, "integration")
	if strings.Contains(integration, "gocovmerge $PROFILES > dist/merged-coverage.out || true") {
		t.Fatal("integration coverage merge still suppresses failure")
	}
	// cPanel integration runs when a cPanel image is configured; tag releases
	// fall back to the Alma+Ubuntu matrix (with a warning) rather than blocking
	// when no image is set. The provisioning and assertion machinery must still
	// be present so cPanel is exercised whenever an image is available.
	for _, want := range []string{
		"releasing with Alma+Ubuntu integration only",
		`--image "$INTEGRATION_CPANEL_IMAGE"`,
		`CPANEL_PACKAGE="${INTEGRATION_CPANEL_PACKAGE:-cloudv-1}"`,
		`TEST_HOSTS="$TEST_HOSTS $CPANEL_IP:cpanel"`,
		`test -x /usr/local/cpanel/cpanel`,
		`test ! -e /opt/csm/csm`,
		"dist/integ-cpanel.out",
	} {
		if !strings.Contains(integration, want) {
			t.Errorf("tag integration job missing expected cPanel handling: %q", want)
		}
	}
}

func gitlabJobBlock(t *testing.T, ci, name string) string {
	t.Helper()

	lines := strings.Split(ci, "\n")
	inJob := false
	var out strings.Builder
	for _, line := range lines {
		if line == name+":" {
			inJob = true
			continue
		}
		if !inJob {
			continue
		}
		if isTopLevelYAMLKey(line) {
			break
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	if !inJob {
		t.Fatalf("%s job not found", name)
	}
	return out.String()
}

func isTopLevelYAMLKey(line string) bool {
	if line == "" || strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
		return false
	}
	return strings.HasSuffix(line, ":")
}
