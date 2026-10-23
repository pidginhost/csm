//go:build linux

package checks

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/yara"
)

func TestInspectDocrootExecFallbackRejectsSymlinks(t *testing.T) {
	for _, parent := range []bool{false, true} {
		t.Run(map[bool]string{false: "final", true: "ancestor"}[parent], func(t *testing.T) {
			f := newDocrootExecFixture(t)
			outside := t.TempDir()
			if err := os.WriteFile(filepath.Join(outside, "tool"), []byte(testELFHeader+"payload-fetcher"), 0700); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(f.docroot, "link")
			target, filename := filepath.Join(outside, "tool"), link
			if parent {
				target, filename = outside, filepath.Join(link, "tool")
			}
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			osFS = realOS{}
			if got := InspectDocrootExec(nil, 1<<30, 1001, filename, "lsphp", f.roots); got != nil {
				t.Fatalf("followed tenant symlink outside docroot: %+v", got)
			}
			if f.backend.scans.Load() != 0 {
				t.Fatal("scanned a file outside the document root")
			}
		})
	}
}

func TestInspectDocrootExecFallbackDoesNotBlockOnFIFO(t *testing.T) {
	f := newDocrootExecFixture(t)
	path := filepath.Join(f.docroot, "pipe")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	osFS = realOS{}
	done := make(chan *alert.Finding, 1)
	go func() { done <- InspectDocrootExec(nil, 1<<30, 1001, path, "lsphp", f.roots) }()
	select {
	case got := <-done:
		if got != nil {
			t.Fatalf("FIFO finding: %+v", got)
		}
	case <-time.After(time.Second):
		// Release an unsafe blocking open before reporting the failure, so
		// the test cannot leave a reader behind when the mocks are restored.
		fd, err := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		_ = unix.Close(fd)
		<-done
		t.Fatal("exited-program inspection blocked opening a FIFO")
	}
}

func TestInspectDocrootExecPathRetryPinsOriginalProgram(t *testing.T) {
	f := newDocrootExecFixture(t)
	path := f.write(t, "tool", testELFHeader+"payload-fetcher")
	b := &docrootPathRetryBackend{beforeRetry: func() {
		if err := os.Rename(path, path+".old"); err != nil {
			t.Fatal(err)
		}
		f.write(t, "tool", testELFHeader+"clean program")
	}}
	activeYARABackend = func() yara.Backend { return b }
	got := InspectDocrootExec(nil, 704, 1001, path, "bash", f.roots)
	if got == nil || got.Severity != alert.Critical {
		t.Fatalf("retry lost the opened malware program: %+v", got)
	}
	if !strings.HasPrefix(b.retryPath, "/proc/") || !strings.Contains(b.retryPath, "/fd/") || strings.HasPrefix(b.retryPath, "/proc/self/") {
		t.Fatalf("retry path = %q, want a descriptor in the scanner parent's process", b.retryPath)
	}
}

// buildDocrootSleeper compiles a small static program that sleeps. A copy of a
// distribution sleep binary does not work everywhere: on AlmaLinux 8 it is a
// shebang wrapper, so the running image is the interpreter outside the docroot.
func buildDocrootSleeper(t *testing.T) []byte {
	t.Helper()
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	if err = os.WriteFile(src, []byte("package main\n\nimport \"time\"\n\nfunc main() { time.Sleep(30 * time.Second) }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "sleeper")
	build := exec.Command(goBinary, "build", "-o", out, src)
	build.Dir = dir
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=")
	if output, buildErr := build.CombinedOutput(); buildErr != nil {
		t.Fatalf("build sleeper: %v\n%s", buildErr, output)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestInspectDocrootExecReadsPinnedLiveImage(t *testing.T) {
	f := newDocrootExecFixture(t)
	data := buildDocrootSleeper(t)
	path := f.write(t, "bin/sleeper", string(data))
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(alias)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	osFS = realOS{}
	for _, deleted := range []bool{false, true} {
		if deleted {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
		got := InspectDocrootExec(nil, cmd.Process.Pid, 1001, alias, "lsphp", f.roots)
		if got == nil || got.FilePath != path || got.ContentSHA256 == "" || got.Severity != alert.Warning {
			t.Fatalf("deleted=%t: pinned live image = %+v", deleted, got)
		}
	}
}
