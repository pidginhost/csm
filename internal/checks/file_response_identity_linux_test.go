//go:build linux

package checks

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/alert"
)

func TestFileResponseSpecialFileSwapDoesNotBlock(t *testing.T) {
	for _, operation := range []string{"quarantine", "clean open", "clean replace"} {
		t.Run(operation, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "source.php")
			if err := os.WriteFile(path, []byte("original content"), 0600); err != nil {
				t.Fatal(err)
			}
			target, err := openCleanTarget(path)
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := unix.Mkfifo(path, 0600); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				switch operation {
				case "quarantine":
					done <- quarantineFileTOCTOUSafe(path, filepath.Join(root, "recovery"), target.Info, nil)
				case "clean open":
					got, err := openCleanTarget(path)
					if got != nil {
						got.Close()
					}
					done <- err
				case "clean replace":
					done <- verifyCleanTargetUnchanged(target)
				}
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("special-file replacement was accepted")
				}
			case <-time.After(time.Second):
				// Release a blocking reader before failing, so the regression
				// never leaves a goroutine or test process stuck on a FIFO.
				fd, err := unix.Open(path, unix.O_RDWR|unix.O_NONBLOCK, 0)
				if err != nil {
					t.Fatal(err)
				}
				<-done
				if err := unix.Close(fd); err != nil {
					t.Fatal(err)
				}
				t.Fatal("file response blocked on a special-file replacement")
			}
		})
	}
}

func TestAutoFileResponseChangedSourceAfterCopyDoesNotTripBreaker(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "modified", true: "replaced"}[replace], func(t *testing.T) {
			cfg, homes := fileResponseFixture(t, "  max_file_action_failures_per_hour: 1\n")
			sink := withActionSink(t)
			f := responseFile(t, homes, "alice", "source.bin", []byte("original content"))
			oldCopy := quarantineCopyByFD
			quarantineCopyByFD = func(file *os.File, path string, metadata []byte) error {
				if err := oldCopy(file, path, metadata); err != nil {
					return err
				}
				if replace {
					replacement := f.FilePath + ".replacement"
					if err := os.WriteFile(replacement, []byte("updated content"), 0600); err != nil {
						return err
					}
					return os.Rename(replacement, f.FilePath)
				}
				return os.WriteFile(f.FilePath, []byte("updated content"), 0600)
			}
			t.Cleanup(func() { quarantineCopyByFD = oldCopy })
			AutoQuarantineFiles(cfg, []alert.Finding{f})
			if len(sink.records) != 1 || sink.records[0].Result != actionlog.Refused {
				t.Errorf("identity refusal recorded as failure: %+v", sink.records)
			}
			quarantineCopyByFD = oldCopy
			assertResponseFile(t, f.FilePath, []byte("updated content"))
			assertOtherAccountCanRespond(t, cfg, homes)
		})
	}
}

func TestAutomaticCleanSourceRefusals(t *testing.T) {
	for _, kind := range []string{"removed", "symlink", "special file", "socket"} {
		t.Run(kind, func(t *testing.T) {
			cfg, homes := fileResponseFixture(t, "")
			oldRoots := fixHtaccessAllowedRoots
			fixHtaccessAllowedRoots = []string{homes}
			t.Cleanup(func() { fixHtaccessAllowedRoots = oldRoots })
			f := responseFile(t, homes, "alice", ".htaccess", []byte("original content"))
			info, err := os.Stat(f.FilePath)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.Remove(f.FilePath); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink":
				err = os.Symlink(cfg.StatePath, f.FilePath)
			case "special file":
				err = unix.Mkfifo(f.FilePath, 0600)
			case "socket":
				err = unix.Mknod(f.FilePath, unix.S_IFSOCK|0600, 0)
			}
			if err != nil {
				t.Fatal(err)
			}
			if result := cleanInfectedFileIdentified(f.FilePath, info); !result.Refused || result.Cleaned {
				t.Errorf("PHP source refusal reported as failure: %+v", result)
			}
			if result := cleanHtaccessFileIdentified(f.FilePath, info); !result.Refused || result.Success {
				t.Errorf("access-file source refusal reported as failure: %+v", result)
			}
		})
	}
}

func TestAutoFileResponseSocketReplacementDoesNotTripBreaker(t *testing.T) {
	cfg, homes := fileResponseFixture(t, "  max_file_action_failures_per_hour: 1\n")
	sink := withActionSink(t)
	f := responseFile(t, homes, "alice", "source.bin", []byte("original content"))
	oldMove := quarantineTargetFn
	quarantineTargetFn = func(path, qpath string, info os.FileInfo, data []byte) error {
		if err := os.Remove(path); err != nil {
			return err
		}
		if err := unix.Mknod(path, unix.S_IFSOCK|0600, 0); err != nil {
			return err
		}
		return oldMove(path, qpath, info, data)
	}
	t.Cleanup(func() { quarantineTargetFn = oldMove })
	AutoQuarantineFiles(cfg, []alert.Finding{f})
	quarantineTargetFn = oldMove
	if len(sink.records) != 1 || sink.records[0].Result != actionlog.Refused {
		t.Errorf("socket replacement recorded as failure: %+v", sink.records)
	}
	if info, err := os.Lstat(f.FilePath); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket replacement was not preserved: %v", err)
	}
	assertOtherAccountCanRespond(t, cfg, homes)
}

func TestAutoFileResponseParentReplacementAfterCopyDoesNotTripBreaker(t *testing.T) {
	for _, kind := range []string{"file", "symlink loop"} {
		t.Run(kind, func(t *testing.T) {
			cfg, homes := fileResponseFixture(t, "  max_file_action_failures_per_hour: 1\n")
			sink := withActionSink(t)
			body := []byte("original content")
			f := responseFile(t, homes, "alice", "source.bin", body)
			parent := filepath.Dir(f.FilePath)
			moved := parent + ".moved"
			oldCopy := quarantineCopyByFD
			quarantineCopyByFD = func(file *os.File, path string, metadata []byte) error {
				if err := oldCopy(file, path, metadata); err != nil {
					return err
				}
				if err := os.Rename(parent, moved); err != nil {
					return err
				}
				if kind == "symlink loop" {
					return os.Symlink(parent, parent)
				}
				return os.WriteFile(parent, []byte("replacement"), 0600)
			}
			t.Cleanup(func() { quarantineCopyByFD = oldCopy })
			AutoQuarantineFiles(cfg, []alert.Finding{f})
			quarantineCopyByFD = oldCopy
			if len(sink.records) != 1 {
				t.Fatalf("expected one quarantine record, got %+v", sink.records)
			}
			if sink.records[0].Result != actionlog.Refused {
				t.Errorf("parent replacement recorded as failure: %+v", sink.records)
			}
			assertResponseFile(t, filepath.Join(moved, filepath.Base(f.FilePath)), body)
			assertResponseFile(t, sink.records[0].RecoveryPath, body)
			assertOtherAccountCanRespond(t, cfg, homes)
		})
	}
}
