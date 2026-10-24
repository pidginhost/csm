package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestInstallPreparesWorkerExecutable(t *testing.T) {
	if root := os.Getenv("CSM_TEST_INSTALL_BINARY_ROOT"); root != "" {
		oldMask := syscall.Umask(0077)
		defer syscall.Umask(oldMask)
		stop := errors.New("stop before deploying services")
		inst := &Installer{
			BinaryPath: filepath.Join(root, "bin", "csm"),
			ConfigPath: filepath.Join(root, "config", "csm.yaml"),
			StatePath:  filepath.Join(root, "state"),
			LogPath:    filepath.Join(root, "logs", "monitor.log"),
			operations: &installerOperations{
				getuid:        func() int { return 0 },
				deployAuditd:  func() error { return nil },
				deploySystemd: func() error { return stop },
			},
		}
		if err := inst.Install(); !errors.Is(err, stop) {
			t.Fatalf("install did not reach service deployment: %v", err)
		}
		for path, want := range map[string]os.FileMode{
			inst.BinaryPath:                          0711,
			filepath.Dir(inst.BinaryPath):            0711,
			inst.StatePath:                           0700,
			filepath.Join(root, "bin", "quarantine"): 0700,
			filepath.Join(root, "bin", "rules"):      0700,
		} {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Mode().Perm(); got != want {
				t.Errorf("%s mode = %#o, want %#o", path, got, want)
			}
		}
		return
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"fresh", "replace", "in-place"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			command := self
			if scenario != "fresh" {
				binary := filepath.Join(root, "bin", "csm")
				if err := os.Mkdir(filepath.Dir(binary), 0700); err != nil {
					t.Fatal(err)
				}
				contents := []byte("previous binary")
				if scenario == "in-place" {
					var readErr error
					contents, readErr = os.ReadFile(self)
					if readErr != nil {
						t.Fatal(readErr)
					}
					command = binary
				}
				if err := os.WriteFile(binary, contents, 0700); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command(command, "-test.run=^TestInstallPreparesWorkerExecutable$")
			cmd.Env = append(os.Environ(), "CSM_TEST_INSTALL_BINARY_ROOT="+root)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("installer permissions: %v\n%s", err, out)
			}
		})
	}
}

func TestPrepareWorkerExecutable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "opt")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "csm")
	if err := os.WriteFile(binary, []byte("x"), 0700); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := prepareWorkerExecutable(binary); err != nil {
			t.Fatal(err)
		}
	}
	for path, want := range map[string]os.FileMode{binary: 0711, dir: 0711} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s mode = %#o, want %#o", path, got, want)
		}
	}
}

// Upgrades run by an older deploy script chmod the new binary 0700, then run
// its rehash; rehash must give the parse worker its execute access back
// before the immutable flag is set again.
func TestRehashPreparesWorkerExecutable(t *testing.T) {
	body, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	start := strings.Index(src, "func runRehash()")
	if start < 0 {
		t.Fatal("runRehash not found")
	}
	end := strings.Index(src[start:], "\nfunc ")
	if end < 0 {
		end = len(src) - start
	}
	rehash := src[start : start+end]
	prepare := strings.Index(rehash, "prepareWorkerExecutable(binaryPath)")
	immutable := strings.Index(rehash, "setBinaryImmutable(binaryPath")
	if prepare < 0 || immutable < 0 || prepare > immutable {
		t.Error("runRehash must call prepareWorkerExecutable(binaryPath) before setBinaryImmutable")
	}
}
