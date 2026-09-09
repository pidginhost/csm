package ci

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
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

// Execute the YAML-decoded shell through both SSH quoting layers. Substring
// checks also accept commented-out commands and cannot prove that an apt
// failure stops the job or that repair and installation use separate sessions.
func TestIntegrationRepairsTheImageBeforeInstallingCSM(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", ".gitlab-ci.yml"))
	if err != nil {
		t.Fatalf("read .gitlab-ci.yml: %v", err)
	}
	var config struct {
		Integration struct {
			Script []string `yaml:"script"`
		} `yaml:"integration"`
	}
	if err := yaml.Unmarshal(body, &config); err != nil {
		t.Fatalf("decode .gitlab-ci.yml: %v", err)
	}
	if len(config.Integration.Script) != 1 {
		t.Fatal("expected one integration script block")
	}
	script := config.Integration.Script[0]
	start := strings.Index(script, `scp "$DEB" phuser@"$UBUNTU_IP":/tmp/csm.deb`)
	if start < 0 {
		t.Fatal("Ubuntu package upload boundary not found")
	}
	end := strings.Index(script[start:], `if [ -n "$CPANEL_ID" ]; then`)
	if end < 0 {
		t.Fatal("cPanel package installation boundary not found")
	}
	// Keep the job's actual shell options so dropping errexit is observable.
	options, _, _ := strings.Cut(script, "\n")
	install := options + "\n" + script[start:start+end] + "\nprintf 'done\\n' >> \"$APT_TRACE\"\n"

	const commands = `#!/bin/bash
set -eu
case "${0##*/}" in
  scp)
    [[ $# == 2 && "$1" == "$DEB" && "$2" == "phuser@$UBUNTU_IP:/tmp/csm.deb" ]]
    ;;
  ssh)
    [[ $# == 2 && "$1" == "phuser@$UBUNTU_IP" ]]
    printf 'ssh\n' >> "$APT_TRACE"
    exec /bin/sh -c "$2"
    ;;
  sudo)
    [[ $# == 3 && "$1" == bash && "$2" == -c ]]
    exec "$@"
    ;;
  apt-get)
    case "$*" in
      'update -qq') phase=update; argc=2 ;;
      '-y -qq --fix-broken install') phase=repair; argc=4 ;;
      'install -y /tmp/csm.deb') phase=install; argc=3 ;;
      *) printf 'unexpected apt arguments: %s\n' "$*" >&2; exit 99 ;;
    esac
    [[ $# == "$argc" ]]
    printf '%s\n' "$phase" >> "$APT_TRACE"
    [[ "$phase" != "$FAIL_PHASE" ]] || exit 100
    if [[ "$phase" == repair ]]; then
      printf 'healthy' > "$IMAGE_STATE"
    elif [[ "$phase" == install && "$(cat "$IMAGE_STATE")" != healthy ]]; then
      exit 100
    fi
    ;;
  *) exit 99 ;;
esac
`
	const repaired = "ssh\nupdate\nrepair\nssh\ninstall\n"
	for _, tc := range []struct {
		name      string
		image     string
		failPhase string
		wantTrace string
		wantExit  int
	}{
		{"healthy_image", "healthy", "", repaired + "done\n", 0},
		{"broken_image", "broken", "", repaired + "done\n", 0},
		{"update_failure", "broken", "update", "ssh\nupdate\n", 100},
		{"repair_failure", "broken", "repair", "ssh\nupdate\nrepair\n", 100},
		{"package_dependency_failure", "healthy", "install", repaired, 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, name := range []string{"scp", "ssh", "sudo", "apt-get"} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(commands), 0700); err != nil {
					t.Fatal(err)
				}
			}
			state := filepath.Join(dir, "state")
			if err := os.WriteFile(state, []byte(tc.image), 0600); err != nil {
				t.Fatal(err)
			}
			trace := filepath.Join(dir, "trace")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", "-c", install)
			cmd.Env = append(os.Environ(),
				"PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
				"UBUNTU_IP=192.0.2.24", "DEB=/artifacts with spaces/csm.deb",
				"IMAGE_STATE="+state, "APT_TRACE="+trace, "FAIL_PHASE="+tc.failPhase,
			)
			out, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("Ubuntu package installation timed out: %s", out)
			}
			if err != nil && cmd.ProcessState == nil {
				t.Fatalf("start shell: %v: %s", err, out)
			}
			if got := cmd.ProcessState.ExitCode(); got != tc.wantExit {
				t.Errorf("installation exit = %d, want %d: %s", got, tc.wantExit, out)
			}
			got, err := os.ReadFile(trace)
			if err != nil {
				t.Fatalf("read apt trace: %v", err)
			}
			if string(got) != tc.wantTrace {
				t.Errorf("command trace = %q, want %q", got, tc.wantTrace)
			}
		})
	}
}
