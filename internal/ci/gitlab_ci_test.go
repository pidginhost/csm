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
	verifiedCleanup := strings.Index(integration, `if ! ./scripts/ci-delete-server.sh "$ALMA_ID" "$UBUNTU_ID" "$CPANEL_ID"; then`)
	afterScript := strings.Index(integration, "  after_script:")
	if verifiedCleanup < 0 || afterScript < 0 || verifiedCleanup > afterScript {
		t.Fatal("integration must run verified cleanup in script so a leak fails the job")
	}
	if strings.Contains(integration[:afterScript], "phctl compute server delete") {
		t.Fatal("integration script still uses unverified fire-and-forget cleanup")
	}
	// Tags require cPanel; main may run the optional image when configured.
	for _, want := range []string{
		"bash scripts/ci-cpanel-preflight.sh",
		`--image "$INTEGRATION_CPANEL_IMAGE"`,
		`CPANEL_PACKAGE="${INTEGRATION_CPANEL_PACKAGE:-cloudv-2}"`,
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

// publish:linux-arm64 carries none of the release gates itself. It inherits
// them by depending on publish:linux-amd64, which is also what serialises the
// stale-"latest" delete against these uploads. If that edge is ever dropped,
// arm64 would publish ungated, so assert the chain rather than trusting it.
func TestArmPublishInheritsReleaseGates(t *testing.T) {
	data, err := os.ReadFile("../../.gitlab-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	arm := gitlabJobBlock(t, string(data), "publish:linux-arm64")
	if !strings.Contains(arm, "job: publish:linux-amd64") {
		t.Fatal("publish:linux-arm64 must depend on publish:linux-amd64 or it publishes without the release gates")
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

func TestReleaseGithubRendersNotesThroughTheChangelogScript(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", ".gitlab-ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	release := gitlabJobBlock(t, string(body), "release:github")

	if !strings.Contains(release, `BODY=$(./scripts/release-notes.sh CHANGELOG.md "${VERSION}" "${TAG}" pidginhost/csm)`) {
		t.Fatal("release:github must render the release body with scripts/release-notes.sh")
	}
	if strings.Contains(release, `sed -n "/^## \[${VERSION}\]/`) {
		t.Fatal("release:github still extracts the changelog inline instead of using the tested script")
	}
	// A changelog the script cannot read has to fail the job. Publishing a
	// placeholder body leaves a public release page with no notes on it.
	if strings.Contains(release, `BODY="Release ${TAG}"`) {
		t.Fatal("release:github must not fall back to a placeholder body")
	}

	script := filepath.Join("..", "..", "scripts", "release-notes.sh")
	info, err := os.Stat(script)
	if err != nil {
		t.Fatalf("stat release-notes.sh: %v", err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("release-notes.sh is not executable (mode %v)", info.Mode().Perm())
	}
}

// The integration job installs the freshly built .deb on a stock Ubuntu cloud
// image. Those images ship with unmet dependencies of their own -- one broke
// the v3.36.0 release pipeline with packagekit and multipath-tools absent
// while packagekit-tools and ubuntu-server depended on them -- so the image is
// repaired in its own command. Folding --fix-broken into the CSM install would
// also repair a dependency defect in our own package, which is the failure
// this job exists to catch.
func TestIntegrationRepairsTheImageBeforeInstallingCSM(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", ".gitlab-ci.yml"))
	if err != nil {
		t.Fatalf("read .gitlab-ci.yml: %v", err)
	}
	integration := gitlabJobBlock(t, string(body), "integration")

	repair := "apt-get update -qq && apt-get -y -qq --fix-broken install"
	if !strings.Contains(integration, repair) {
		t.Fatalf("integration must repair the Ubuntu image before installing; want a command containing %q", repair)
	}
	install := "apt-get install -y /tmp/csm.deb"
	if !strings.Contains(integration, install) {
		t.Fatalf("integration must install the built package; want %q", install)
	}
	for _, line := range strings.Split(integration, "\n") {
		if strings.Contains(line, install) && strings.Contains(line, "fix-broken") {
			t.Fatalf("the CSM install must not carry --fix-broken; a broken dependency in our own package has to fail the job: %s", strings.TrimSpace(line))
		}
	}
	if strings.Index(integration, repair) > strings.Index(integration, install) {
		t.Fatal("the image repair must run before the CSM install")
	}
}
