package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func pagesCoverageStep(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile("../.github/workflows/pages.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct {
				Name string `yaml:"name"`
				Run  string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(body, &workflow); err != nil {
		t.Fatal(err)
	}
	for _, step := range workflow.Jobs["build"].Steps {
		if step.Name == name && step.Run != "" {
			return step.Run
		}
	}
	t.Fatalf("Pages workflow has no runnable step %q", name)
	return ""
}

func TestPagesCoverageDownloadPropagatesFailures(t *testing.T) {
	const curlStub = `#!/usr/bin/env bash
set -eu
for arg in "$@"; do
  case "$arg" in
    https://api.github.com/repos/pidginhost/csm/releases\?per_page=10)
      printf '%s\n' "$CSM_TEST_RELEASES"
      exit "$CSM_TEST_RELEASES_EXIT"
      ;;
    https://github.com/pidginhost/csm/releases/download/v1.1.0/merged-coverage.out)
      exit 22
      ;;
    https://github.com/pidginhost/csm/releases/download/v1.0.0/merged-coverage.out)
      printf '%s\n' "$CSM_TEST_PROFILE" > coverage.out
      exit 0
      ;;
  esac
done
echo 'unexpected curl request' >&2
exit 2
`
	const releases = `[{"tag_name":"v1.1.0"},{"tag_name":"v1.0.0"}]`
	const profile = "mode: set\nexample.com/cov/kept.go:3.21,5.2 1 1"
	step := pagesCoverageStep(t, "Download coverage profile from latest release")
	for _, tc := range []struct {
		name         string
		releases     string
		releasesExit string
		profile      string
		wantSuccess  bool
	}{
		{"previous release", releases, "0", profile, true},
		{"release API transfer failed", releases, "18", profile, false},
		{"release response parsing failed", `[{"tag_name":"v1.0.0"},{}]`, "0", profile, false},
		{"no release assets", `[{"tag_name":"v1.1.0"}]`, "0", profile, false},
		{"invalid profile", releases, "0", "invalid profile", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			binDir := t.TempDir()
			if err := os.WriteFile(filepath.Join(binDir, "curl"), []byte(curlStub), 0o700); err != nil {
				t.Fatal(err)
			}
			envFile := filepath.Join(dir, "github-env")
			if err := os.WriteFile(envFile, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			// GitHub's default shell enables errexit but does not enable pipefail.
			cmd := exec.Command("bash", "-e", "-c", step)
			cmd.Dir = dir
			cmd.Env = cleanEnv("PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
				"GH_TOKEN=", "GITHUB_ENV="+envFile, "CSM_TEST_RELEASES="+tc.releases,
				"CSM_TEST_RELEASES_EXIT="+tc.releasesExit, "CSM_TEST_PROFILE="+tc.profile)
			out, err := cmd.CombinedOutput()
			if (err == nil) != tc.wantSuccess {
				t.Fatalf("download step error = %v, want success = %v:\n%s", err, tc.wantSuccess, out)
			}
			env, err := os.ReadFile(envFile)
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantSuccess {
				if string(env) != "COVERAGE_TAG=v1.0.0\n" {
					t.Errorf("coverage tag environment = %q, want previous release", env)
				}
				got, err := os.ReadFile(filepath.Join(dir, "coverage.out"))
				if err != nil || strings.TrimSpace(string(got)) != profile {
					t.Errorf("downloaded profile = %q, error = %v", got, err)
				}
			} else if len(env) != 0 {
				t.Errorf("failed download exported a coverage tag: %q", env)
			}
		})
	}
}

func TestPagesCoverageRendersFromAShallowMirror(t *testing.T) {
	repo, profile := releasedThenDeletedRepo(t)
	gitInDir(t, repo, "tag", "-a", "-f", "-m", "release", "v1.0.0", "v1.0.0^{commit}")
	clone := filepath.Join(t.TempDir(), "mirror")
	gitInDir(t, repo, "clone", "--quiet", "--no-tags", "--depth=1", "file://"+filepath.ToSlash(repo), clone)

	for src, dst := range map[string]string{
		"coverage-report.sh": "scripts/coverage-report.sh",
		profile:              "coverage.out",
	} {
		body, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(clone, dst)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	step := pagesCoverageStep(t, "Generate HTML coverage report")
	cmd := exec.Command("bash", "-e", "-c", step)
	cmd.Dir = clone
	cmd.Env = cleanEnv("COVERAGE_TAG=v1.0.0", "GOFLAGS=", "GOTOOLCHAIN=local",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("rendering coverage in a shallow mirror: %v\n%s", err, out)
	}
	html, err := os.ReadFile(filepath.Join(clone, "coverage.html"))
	if err != nil || !strings.Contains(string(html), "example.com/cov/gone.go") {
		t.Errorf("report lacks the source deleted since the release: %v", err)
	}
	funcs, err := os.ReadFile(filepath.Join(clone, "coverage-func.txt"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(funcs)), "\n")
	total := strings.Fields(lines[len(lines)-1])
	if len(total) != 3 || total[0] != "total:" || total[1] != "(statements)" || total[2] != "50.0%" {
		t.Errorf("function summary lacks the release's 50%% total:\n%s", funcs)
	}
	if _, err := os.Stat(filepath.Join(clone, "gone.go")); !os.IsNotExist(err) {
		t.Errorf("renderer changed the main checkout: stat error = %v", err)
	}
}
