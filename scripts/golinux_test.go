package scripts

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// scripts/go-linux.sh runs Go work against a Linux container, which CSM needs
// because most of the daemon is //go:build linux (fanotify, nftables,
// spoolwatch) and cannot be tested on a macOS host at all.
//
// These tests pin the cache location. Sessions used to hand-roll the container
// invocation and point GOCACHE at a fresh directory under /tmp each time
// (csm-review-gocache, csm-codex-gocache, csm-go-build-1267, ...). None were
// reused, none were removed, and /private/tmp reached 283 GB of Go caches while
// every run still compiled from scratch. The path has to be derived and stable,
// and shared across the six worktrees under .claude/worktrees.

// runGoLinuxDry invokes the wrapper in dry-run mode, where it prints the
// container invocation instead of executing it. That keeps these tests honest
// without requiring a container runtime on the machine running `go test`.
func runGoLinuxDry(t *testing.T, cacheHome string, args ...string) (string, int) {
	t.Helper()

	root := repoRoot(t)
	cmd := exec.Command(filepath.Join(root, "scripts", "go-linux.sh"), args...)
	cmd.Env = append(os.Environ(),
		"GO_LINUX_DRY_RUN=1",
		"XDG_CACHE_HOME="+cacheHome,
	)

	out, err := cmd.CombinedOutput()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("run go-linux.sh: %v", err)
	}
	return string(out), code
}

func repoRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Dir(wd)
}

// goMinor reads the toolchain from go.mod, e.g. "1.27" from "go 1.27.0".
func goMinor(t *testing.T) string {
	t.Helper()

	f, err := os.Open(filepath.Join(repoRoot(t), "go.mod"))
	if err != nil {
		t.Fatalf("open go.mod: %v", err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && fields[0] == "go" {
			parts := strings.Split(fields[1], ".")
			if len(parts) >= 2 {
				return parts[0] + "." + parts[1]
			}
		}
	}
	t.Fatal("no go directive in go.mod")
	return ""
}

// goEnv reads a value from the host toolchain, e.g. GOMODCACHE.
func goEnv(t *testing.T, name string) string {
	t.Helper()

	out, err := exec.Command("go", "env", name).Output()
	if err != nil {
		t.Fatalf("go env %s: %v", name, err)
	}
	value := strings.TrimSpace(string(out))
	if value == "" {
		t.Fatalf("go env %s is empty", name)
	}
	return value
}

func TestGoLinuxDerivesAStableCachePathOutsideTheRepo(t *testing.T) {
	cacheHome := t.TempDir()

	first, code := runGoLinuxDry(t, cacheHome, "go", "test", "./...")
	if code != 0 {
		t.Fatalf("dry run exited %d: %s", code, first)
	}

	buildCache := filepath.Join(cacheHome, "csm-linux", "go-build")
	if !strings.Contains(first, buildCache) {
		t.Errorf("build cache is not at %s:\n%s", buildCache, first)
	}
	// The module cache holds only source and is platform independent, so the
	// container must reuse the host's rather than downloading its own. A
	// fresh empty module cache per repo is the same duplication that filled
	// /private/tmp, just relocated -- the host already holds ~1.3 GB.
	hostModCache := goEnv(t, "GOMODCACHE")
	if !strings.Contains(first, "-v "+hostModCache+":/gomodcache") {
		t.Errorf("host module cache %s is not reused:\n%s", hostModCache, first)
	}
	if strings.Contains(first, filepath.Join("csm-linux", "go-mod")) {
		t.Errorf("a second empty module cache is mounted alongside the host one:\n%s", first)
	}

	// The property that stops the /tmp blowup: a per-run suffix would make
	// two invocations disagree.
	second, _ := runGoLinuxDry(t, cacheHome, "go", "test", "./...")
	if first != second {
		t.Errorf("cache path is not stable across runs:\n%s\n%s", first, second)
	}

	// Inside the repo, each worktree would keep its own copy and the
	// duplication returns by another route.
	if strings.Contains(first, filepath.Join(repoRoot(t), ".cache")) {
		t.Errorf("cache is inside the repo; worktrees would not share it:\n%s", first)
	}
}

func TestGoLinuxMountsTheWorkspaceAndPinsTheToolchain(t *testing.T) {
	out, code := runGoLinuxDry(t, t.TempDir(), "go", "test", "./...")
	if code != 0 {
		t.Fatalf("dry run exited %d: %s", code, out)
	}

	if !strings.Contains(out, repoRoot(t)+":/src") {
		t.Errorf("repository root is not mounted at /src:\n%s", out)
	}
	if !strings.Contains(out, "-w /src") {
		t.Errorf("working directory is not /src:\n%s", out)
	}
	// An unpinned image would silently compile against a different Go than CI.
	if want := "golang:" + goMinor(t); !strings.Contains(out, want) {
		t.Errorf("image is not pinned to %s:\n%s", want, out)
	}
	if !strings.Contains(out, "go test") {
		t.Errorf("caller command was not forwarded:\n%s", out)
	}
}

// The linux-only daemon paths open fanotify and nftables handles. Without
// CAP_SYS_ADMIN those tests fail on permissions rather than on behaviour, which
// reads as a broken test suite instead of a missing capability.
func TestGoLinuxGrantsCapSysAdmin(t *testing.T) {
	out, code := runGoLinuxDry(t, t.TempDir(), "go", "test", "./...")
	if code != 0 {
		t.Fatalf("dry run exited %d: %s", code, out)
	}
	if !strings.Contains(out, "CAP_SYS_ADMIN") {
		t.Errorf("CAP_SYS_ADMIN is not granted:\n%s", out)
	}
}

// A sandbox with no host module cache, or one that wants an isolated cache,
// needs a way to say so without editing the script.
func TestGoLinuxHonoursAModuleCacheOverride(t *testing.T) {
	override := t.TempDir()

	cmd := exec.Command(filepath.Join(repoRoot(t), "scripts", "go-linux.sh"), "go", "build", "./...")
	cmd.Env = append(os.Environ(),
		"GO_LINUX_DRY_RUN=1",
		"XDG_CACHE_HOME="+t.TempDir(),
		"GO_LINUX_MODCACHE="+override,
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run go-linux.sh: %v: %s", err, out)
	}
	if !strings.Contains(string(out), "-v "+override+":/gomodcache") {
		t.Errorf("GO_LINUX_MODCACHE override is ignored:\n%s", out)
	}
}

func TestGoLinuxRejectsAnEmptyCommand(t *testing.T) {
	out, code := runGoLinuxDry(t, t.TempDir())
	if code == 0 {
		t.Errorf("expected a non-zero exit for an empty command, got:\n%s", out)
	}
}

// A future edit must not reintroduce a throwaway cache under /tmp.
func TestGoLinuxNeverMintsAThrowawayCache(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "go-linux.sh"))
	if err != nil {
		t.Fatalf("read go-linux.sh: %v", err)
	}
	source := string(body)

	if strings.Contains(source, "mktemp") {
		t.Error("go-linux.sh uses mktemp; the cache must be derived, not invented")
	}
	for _, bad := range []string{"GOCACHE=/tmp", "GOCACHE=/private/tmp", "GOMODCACHE=/tmp"} {
		if strings.Contains(source, bad) {
			t.Errorf("go-linux.sh points a Go cache at /tmp (%q)", bad)
		}
	}
}
