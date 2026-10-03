package ci

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// The test job's verbose transcript passed GitLab's 4 MB log cap long before
// the suite ended, so a failing test showed only as a script failure. Without
// -v, go test prints each failing test's output and one line per package.
func TestTestJobKeepsFailuresInTheLog(t *testing.T) {
	data, err := os.ReadFile("../../.gitlab-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Variables map[string]string `yaml:"variables"`
		Test      struct {
			Script    []string          `yaml:"script"`
			Variables map[string]string `yaml:"variables"`
		} `yaml:"test"`
	}
	if err := yaml.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	goFlags, ok := config.Test.Variables["GOFLAGS"]
	if !ok {
		goFlags = config.Variables["GOFLAGS"]
	}
	if err := checkTestJobLog(t, strings.Join(config.Test.Script, "\n"), "GOFLAGS="+goFlags); err != nil {
		t.Fatal(err)
	}
}

func checkTestJobLog(t *testing.T, script string, env ...string) error {
	t.Helper()
	// Let the shell decode quoting and continuations. Only the test command's
	// arguments matter here; compilation and coverage conversion are stubbed.
	const probe = `#!/bin/sh
set -f
[ "$1" = test ] || exit 0
printf 'test\000' >> "$CSM_TEST_GO_RUNS"
printf '%s\000' ${GOFLAGS:-} "$@" >> "$CSM_TEST_GO_RUNS"
for arg in "$@"; do
  case "$arg" in
    -coverprofile=*) : > "${arg#-coverprofile=}" ;;
  esac
done
`
	dir := t.TempDir()
	for name, contents := range map[string]string{
		"go":                probe,
		"gocover-cobertura": "#!/bin/sh\ncat\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0700); err != nil {
			return err
		}
	}
	runs := filepath.Join(dir, "runs")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-ec", script)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "GOFLAGS=", "CSM_TEST_GO_RUNS="+runs)
	cmd.Env = append(cmd.Env, env...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("test job log gate: %w: %s", err, out)
	}
	args, err := os.ReadFile(runs)
	if os.IsNotExist(err) {
		return fmt.Errorf("test job runs no go test command")
	} else if err != nil {
		return err
	}
	for _, arg := range strings.Split(string(args), "\x00") {
		// GOFLAGS permits each flag to be enclosed in single or double quotes.
		arg = strings.Trim(arg, "\"'")
		name, value, hasValue := strings.Cut(arg, "=")
		if name != "-v" && name != "-test.v" {
			continue
		}
		verbose := true
		if hasValue {
			verbose, err = strconv.ParseBool(value)
		}
		if verbose || err != nil {
			return fmt.Errorf("test job runs a verbose suite, which overflows the job log: %s", arg)
		}
	}
	return nil
}

func TestTestJobLogGateChecksExecutedArguments(t *testing.T) {
	for _, tc := range []struct {
		name    string
		script  string
		wantErr bool
	}{
		{"quiet", "go test -race ./...", false},
		{"bare_verbose", "go test -v ./...", true},
		{"continued_verbose", "go test -race \\\n  -v ./...", true},
		{"quoted_verbose", "go test '-v' ./...", true},
		{"test_verbose_value", "go test -test.v=true ./...", true},
		{"disabled_verbose", "go test -v=false ./...", false},
		{"second_command_verbose", "go test ./internal/ci\ngo test -v ./...", true},
		{"ignored_verbose_failure", "go test -v ./... || true", true},
		{"command_verbose", "command go test -v ./...", true},
		{"comment_mentions_verbose", "# go test -v overflows the log\ngo test ./...", false},
		{"comment_only", "# go test ./...", true},
		{"echo_only", "echo 'go test ./...'", true},
		{"goflags_verbose", "GOFLAGS=-v go test ./...", true},
		{"quoted_goflags_verbose", "GOFLAGS=\"'-v'\" go test ./...", true},
		{"goflags_quiet", "GOFLAGS=-v=false go test ./...", false},
		{"env_verbose", "env GOFLAGS=-v go test ./...", true},
		{"nested_shell_verbose", "bash -ec 'go test -v ./...'", true},
		{"coverage_steps", "go test -coverprofile=coverage.out ./...\ngo tool cover -func=coverage.out | tail -1\ngocover-cobertura < coverage.out > coverage.xml", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkTestJobLog(t, tc.script)
			if (err != nil) != tc.wantErr {
				t.Fatalf("gate error = %v, want error = %v", err, tc.wantErr)
			}
		})
	}
}
