package scripts

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// scripts/go-linux.sh runs Go work against a Linux container, which CSM needs
// because most of the daemon is //go:build linux (fanotify, nftables,
// spoolwatch) and cannot be tested on a macOS host.

func cleanEnv(overrides ...string) []string {
	overridden := map[string]struct{}{
		"GO_LINUX_DRY_RUN":  {},
		"GO_LINUX_IMAGE":    {},
		"GO_LINUX_MEMORY":   {},
		"GO_LINUX_MODCACHE": {},
		"GO_LINUX_RUNTIME":  {},
		"XDG_CACHE_HOME":    {},
	}
	for _, entry := range overrides {
		if key, _, ok := strings.Cut(entry, "="); ok {
			overridden[key] = struct{}{}
		}
	}

	env := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if _, skip := overridden[key]; !skip {
			env = append(env, entry)
		}
	}
	return append(env, overrides...)
}

func fakeRuntime(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "runtime")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\"\n"), 0o700); err != nil {
		t.Fatalf("write fake runtime: %v", err)
	}
	return path
}

// runGoLinux invokes the wrapper with a fake runtime that prints each received
// argument on its own line. Exact argument assertions catch writable mounts and
// quoting errors without creating a real container.
func runGoLinux(t *testing.T, dir string, env []string, args ...string) (string, int) {
	t.Helper()

	if !hasEnvKey(env, "XDG_CACHE_HOME") {
		env = append(env, "XDG_CACHE_HOME="+t.TempDir())
	}
	cmd := exec.Command(filepath.Join(repoRoot(t), "scripts", "go-linux.sh"), args...)
	cmd.Dir = dir
	cmd.Env = cleanEnv(append(env, "GO_LINUX_RUNTIME="+fakeRuntime(t))...)

	out, err := cmd.CombinedOutput()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("run go-linux.sh: %v", err)
	}
	return string(out), code
}

func hasEnvKey(env []string, want string) bool {
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		if key == want {
			return true
		}
	}
	return false
}

func invocationArgs(t *testing.T, output string) []string {
	t.Helper()

	trimmed := strings.TrimSuffix(output, "\n")
	if trimmed == "" {
		t.Fatal("wrapper produced no runtime arguments")
	}
	return strings.Split(trimmed, "\n")
}

func requireArgPair(t *testing.T, args []string, first, second string) {
	t.Helper()

	for i := 0; i+1 < len(args); i++ {
		if args[i] == first && args[i+1] == second {
			return
		}
	}
	t.Errorf("runtime arguments do not contain %q %q:\n%q", first, second, args)
}

func hasArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

func repoRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Dir(wd)
}

func physicalPath(t *testing.T, path string) string {
	t.Helper()

	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("resolve %s: %v", path, err)
	}
	return resolved
}

func goVersion(t *testing.T) string {
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
			return fields[1]
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	t.Fatal("no go directive in go.mod")
	return ""
}

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

func TestGoLinuxUsesStableRuntimeCachesAndReadOnlyHostSeed(t *testing.T) {
	cacheHome := t.TempDir()
	env := []string{"XDG_CACHE_HOME=" + cacheHome}
	firstOutput, code := runGoLinux(t, repoRoot(t), env, "go", "test", "./...")
	if code != 0 {
		t.Fatalf("wrapper exited %d: %s", code, firstOutput)
	}
	first := invocationArgs(t, firstOutput)
	physicalCacheHome := physicalPath(t, cacheHome)

	for _, mount := range []string{
		filepath.Join(physicalCacheHome, "csm-linux", "go-build") + ":/gocache",
		filepath.Join(physicalCacheHome, "csm-linux", "go-mod") + ":/gomodcache",
		filepath.Join(physicalCacheHome, "csm-linux", "golangci-lint") + ":/golangci-cache",
	} {
		requireArgPair(t, first, "-v", mount)
	}

	hostModCache := goEnv(t, "GOMODCACHE")
	requireArgPair(t, first, "-v", hostModCache+":/gomodcache-host:ro")
	if hasArg(first, hostModCache+":/gomodcache") {
		t.Errorf("host module cache is writable inside the container:\n%q", first)
	}
	requireArgPair(t, first, "-e", "GOPROXY=file:///gomodcache-host/cache/download,https://proxy.golang.org,direct")

	secondOutput, secondCode := runGoLinux(t, repoRoot(t), env, "go", "test", "./...")
	if secondCode != 0 {
		t.Fatalf("second wrapper run exited %d: %s", secondCode, secondOutput)
	}
	if second := invocationArgs(t, secondOutput); !reflect.DeepEqual(first, second) {
		t.Errorf("cache arguments are not stable across runs:\n%q\n%q", first, second)
	}
}

func TestGoLinuxMountsTheWorkspaceAndPinsTheExactToolchain(t *testing.T) {
	out, code := runGoLinux(t, repoRoot(t), nil, "go", "test", "./...", "-count=1")
	if code != 0 {
		t.Fatalf("wrapper exited %d: %s", code, out)
	}
	args := invocationArgs(t, out)

	requireArgPair(t, args, "-v", repoRoot(t)+":/src")
	requireArgPair(t, args, "-w", "/src")

	image := "golang:" + goVersion(t)
	for i, arg := range args {
		if arg != image {
			continue
		}
		wantCommand := []string{"go", "test", "./...", "-count=1"}
		if got := args[i+1:]; !reflect.DeepEqual(got, wantCommand) {
			t.Fatalf("forwarded command = %q, want %q", got, wantCommand)
		}
		return
	}
	t.Errorf("image is not pinned to exact toolchain %s:\n%q", image, args)
}

func TestGoLinuxPreservesAWorkingDirectoryInsideTheRepository(t *testing.T) {
	dir := filepath.Join(repoRoot(t), "internal", "checks")
	out, code := runGoLinux(t, dir, nil, "go", "test", ".")
	if code != 0 {
		t.Fatalf("wrapper exited %d: %s", code, out)
	}

	requireArgPair(t, invocationArgs(t, out), "-w", "/src/internal/checks")
}

func TestGoLinuxMakesLinkedWorktreeMetadataReadable(t *testing.T) {
	fakeRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(fakeRoot, "scripts"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"go.mod", filepath.Join("scripts", "go-linux.sh")} {
		body, err := os.ReadFile(filepath.Join(repoRoot(t), name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		mode := os.FileMode(0o600)
		if strings.HasSuffix(name, ".sh") {
			mode = 0o700
		}
		if err := os.WriteFile(filepath.Join(fakeRoot, name), body, mode); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if err := os.WriteFile(filepath.Join(fakeRoot, ".git"), []byte("gitdir: elsewhere\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	commonDir := filepath.Join(t.TempDir(), ".git")
	if err := os.Mkdir(commonDir, 0o700); err != nil {
		t.Fatal(err)
	}
	binDir := t.TempDir()
	gitStub := filepath.Join(binDir, "git")
	if err := os.WriteFile(gitStub, []byte("#!/bin/sh\nprintf '%s\\n' \"$FAKE_GIT_COMMON_DIR\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	runtime := fakeRuntime(t)
	cmd := exec.Command(filepath.Join(fakeRoot, "scripts", "go-linux.sh"), "go", "build", "./...")
	cmd.Dir = fakeRoot
	cmd.Env = cleanEnv(
		"FAKE_GIT_COMMON_DIR="+commonDir,
		"GO_LINUX_MODCACHE=",
		"GO_LINUX_RUNTIME="+runtime,
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run copied wrapper: %v: %s", err, out)
	}
	args := invocationArgs(t, string(out))
	requireArgPair(t, args, "-v", commonDir+":"+commonDir+":ro")
	requireArgPair(t, args, "-e", "GIT_OPTIONAL_LOCKS=0")
}

func TestGoLinuxGrantsCapSysAdmin(t *testing.T) {
	out, code := runGoLinux(t, repoRoot(t), nil, "go", "test", "./...")
	if code != 0 {
		t.Fatalf("wrapper exited %d: %s", code, out)
	}
	if !hasArg(invocationArgs(t, out), "CAP_SYS_ADMIN") {
		t.Errorf("CAP_SYS_ADMIN is not granted:\n%s", out)
	}
}

func TestGoLinuxHonoursAReadOnlyModuleCacheOverride(t *testing.T) {
	override := t.TempDir()
	out, code := runGoLinux(t, repoRoot(t), []string{"GO_LINUX_MODCACHE=" + override}, "go", "build", "./...")
	if code != 0 {
		t.Fatalf("wrapper exited %d: %s", code, out)
	}
	args := invocationArgs(t, out)

	physicalOverride := physicalPath(t, override)
	requireArgPair(t, args, "-v", physicalOverride+":/gomodcache-host:ro")
	if hasArg(args, physicalOverride+":/gomodcache") {
		t.Errorf("module cache override is writable inside the container:\n%q", args)
	}
}

func TestGoLinuxRejectsAMissingModuleCacheOverride(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	out, code := runGoLinux(t, repoRoot(t), []string{"GO_LINUX_MODCACHE=" + missing}, "go", "build", "./...")
	if code == 0 {
		t.Fatalf("missing module cache override was accepted: %s", out)
	}
	if !strings.Contains(out, "GO_LINUX_MODCACHE is not a directory") {
		t.Errorf("missing module cache error is not actionable: %s", out)
	}
}

func TestGoLinuxRejectsTheWritableCacheAsTheHostSeed(t *testing.T) {
	cacheHome := t.TempDir()
	writable := filepath.Join(cacheHome, "csm-linux", "go-mod")
	if err := os.MkdirAll(writable, 0o700); err != nil {
		t.Fatal(err)
	}
	out, code := runGoLinux(t, repoRoot(t), []string{
		"GO_LINUX_MODCACHE=" + writable,
		"XDG_CACHE_HOME=" + cacheHome,
	}, "go", "build", "./...")
	if code == 0 {
		t.Fatalf("writable cache was accepted as the read-only seed: %s", out)
	}
	if !strings.Contains(out, "host module cache must differ") {
		t.Errorf("overlapping module cache error is not actionable: %s", out)
	}
}

func TestGoLinuxRejectsARelativeCacheHome(t *testing.T) {
	out, code := runGoLinux(t, repoRoot(t), []string{"XDG_CACHE_HOME=relative"}, "go", "build", "./...")
	if code == 0 {
		t.Fatalf("relative cache home was accepted: %s", out)
	}
	if !strings.Contains(out, "XDG_CACHE_HOME must be an absolute path") {
		t.Errorf("relative cache error is not actionable: %s", out)
	}
}

func TestGoLinuxAllowsDisablingTheHostModuleCache(t *testing.T) {
	out, code := runGoLinux(t, repoRoot(t), []string{"GO_LINUX_MODCACHE="}, "go", "build", "./...")
	if code != 0 {
		t.Fatalf("wrapper exited %d: %s", code, out)
	}
	args := invocationArgs(t, out)

	hostModCache := goEnv(t, "GOMODCACHE")
	for _, arg := range args {
		if strings.Contains(arg, hostModCache+":/gomodcache") {
			t.Errorf("disabled host module cache is still mounted: %q", args)
		}
	}
}

func TestGoLinuxPrefersAReadyDockerDaemon(t *testing.T) {
	binDir := t.TempDir()
	dockerStub := filepath.Join(binDir, "docker")
	if err := os.WriteFile(dockerStub, []byte("#!/bin/sh\n[ \"$1\" = info ]\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	containerStub := filepath.Join(binDir, "container")
	if err := os.WriteFile(containerStub, []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(filepath.Join(repoRoot(t), "scripts", "go-linux.sh"), "go", "test", "./...")
	cmd.Env = cleanEnv(
		"GO_LINUX_DRY_RUN=1",
		"GO_LINUX_MODCACHE=",
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dry run wrapper: %v: %s", err, out)
	}
	if !strings.HasPrefix(string(out), "docker run ") {
		t.Errorf("ready Docker daemon was not preferred: %s", out)
	}
}

func TestGoLinuxFallsBackToAppleContainerWhenDockerIsStopped(t *testing.T) {
	binDir := t.TempDir()
	for name, body := range map[string]string{
		"docker":    "#!/bin/sh\nexit 1\n",
		"container": "#!/bin/sh\nexit 0\n",
	} {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(body), 0o700); err != nil {
			t.Fatalf("write %s stub: %v", name, err)
		}
	}

	cmd := exec.Command(filepath.Join(repoRoot(t), "scripts", "go-linux.sh"), "go", "test", "./...")
	cmd.Env = cleanEnv(
		"GO_LINUX_DRY_RUN=1",
		"GO_LINUX_MODCACHE=",
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dry run wrapper: %v: %s", err, out)
	}
	if !strings.HasPrefix(string(out), "container run ") {
		t.Errorf("apple/container was not used as fallback: %s", out)
	}
}

func TestGoLinuxRejectsAnEmptyCommand(t *testing.T) {
	out, code := runGoLinux(t, repoRoot(t), nil)
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
		t.Error("go-linux.sh uses mktemp; caches must be named and stable")
	}
	for _, bad := range []string{"GOCACHE=/tmp", "GOCACHE=/private/tmp", "GOMODCACHE=/tmp"} {
		if strings.Contains(source, bad) {
			t.Errorf("go-linux.sh points a Go cache at /tmp (%q)", bad)
		}
	}
}
