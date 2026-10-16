//go:build linux

package checks

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestQuarantineUnleasedSourceRejectsCapturedRewrite(t *testing.T) {
	for _, removalOnly := range []bool{false, true} {
		name := "copy-and-remove"
		if removalOnly {
			name = "remove-copied-source"
		}
		t.Run(name, func(t *testing.T) {
			for _, restoreMtime := range []bool{false, true} {
				name := "changed-mtime"
				if restoreMtime {
					name = "restored-mtime"
				}
				t.Run(name, func(t *testing.T) {
					root := t.TempDir()
					src := filepath.Join(root, "source.php")
					qPath := filepath.Join(root, "quarantine", "copy.php")
					const original, replacement = "detected content", "replaced content"
					if err := os.WriteFile(src, []byte(original), 0600); err != nil {
						t.Fatal(err)
					}
					writer, openErr := os.OpenFile(src, os.O_WRONLY, 0)
					if openErr != nil {
						t.Fatal(openErr)
					}
					defer writer.Close()
					info, statErr := writer.Stat()
					if statErr != nil {
						t.Fatal(statErr)
					}
					if err := os.MkdirAll(filepath.Dir(qPath), 0700); err != nil {
						t.Fatal(err)
					}
					if removalOnly {
						if err := os.WriteFile(qPath, []byte(original), 0600); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(qPath+".meta", []byte("{}"), 0600); err != nil {
							t.Fatal(err)
						}
					}

					oldHook := quarantineBeforeCapturedUnlink
					t.Cleanup(func() { quarantineBeforeCapturedUnlink = oldHook })
					rewritten := false
					quarantineBeforeCapturedUnlink = func(path string) error {
						if _, err := os.Lstat(path); !os.IsNotExist(err) {
							t.Fatalf("source was not captured before rewrite: %v", err)
						}
						// Cross a filesystem timestamp tick before restoring mtime,
						// so this case tests ctime even on coarse-clock filesystems.
						time.Sleep(20 * time.Millisecond)
						if _, err := writer.WriteAt([]byte(replacement), 0); err != nil {
							return err
						}
						if restoreMtime {
							if err := os.Chtimes("/proc/self/fd/"+strconv.FormatUint(uint64(writer.Fd()), 10), info.ModTime(), info.ModTime()); err != nil {
								return err
							}
							rewrittenInfo, err := writer.Stat()
							if err != nil || !sameContentShape(rewrittenInfo, info) {
								t.Fatalf("rewrite did not preserve size and mtime: %v", err)
							}
						}
						rewritten = true
						return nil
					}

					var moveErr error
					if removalOnly {
						moveErr = removeQuarantinedSource(src, qPath, info)
					} else {
						moveErr = quarantineFileTOCTOUSafe(src, qPath, info, []byte("{}"))
					}
					if !rewritten || !errors.Is(moveErr, errFileResponseRefused) {
						t.Fatalf("captured rewrite was not refused: rewritten=%v, error=%v", rewritten, moveErr)
					}
					if got, err := os.ReadFile(src); err != nil || string(got) != replacement {
						t.Fatalf("rewritten source was not restored: content=%q, error=%v", got, err)
					}
					if restored, err := os.Stat(src); err != nil || !os.SameFile(info, restored) {
						t.Fatalf("restored source identity changed: %v", err)
					}
					for _, path := range []string{qPath, qPath + ".meta"} {
						if _, err := os.Stat(path); !os.IsNotExist(err) {
							t.Fatalf("untrustworthy recovery copy remains at %s: %v", path, err)
						}
					}
				})
			}
		})
	}
}

func TestQuarantineUnleasedSourcePreservesRewriteWhenNameRecreated(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "source.php")
	qPath := filepath.Join(root, "quarantine", "copy.php")
	const original, rewritten, replacement = "detected content", "updated original", "replacement at original name"
	if err := os.WriteFile(src, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	writer, openErr := os.OpenFile(src, os.O_WRONLY, 0)
	if openErr != nil {
		t.Fatal(openErr)
	}
	defer writer.Close()
	info, statErr := writer.Stat()
	if statErr != nil {
		t.Fatal(statErr)
	}
	if err := os.MkdirAll(filepath.Dir(qPath), 0700); err != nil {
		t.Fatal(err)
	}
	oldHook := quarantineBeforeCapturedUnlink
	t.Cleanup(func() { quarantineBeforeCapturedUnlink = oldHook })
	quarantineBeforeCapturedUnlink = func(path string) error {
		if _, err := writer.WriteAt([]byte(rewritten), 0); err != nil {
			return err
		}
		// A deliberately different mtime avoids relying on filesystem precision.
		stamp := info.ModTime().Add(time.Hour)
		if err := os.Chtimes("/proc/self/fd/"+strconv.FormatUint(uint64(writer.Fd()), 10), stamp, stamp); err != nil {
			return err
		}
		return os.WriteFile(path, []byte(replacement), 0600)
	}
	moveErr := quarantineFileTOCTOUSafe(src, qPath, info, []byte("{}"))
	if moveErr == nil || !strings.Contains(moveErr.Error(), "captured source retained in private directory") {
		t.Fatalf("failed rollback was not reported: %v", moveErr)
	}
	if got, err := os.ReadFile(src); err != nil || string(got) != replacement {
		t.Fatalf("replacement was overwritten: content=%q, error=%v", got, err)
	}
	staged, err := filepath.Glob(filepath.Join(root, ".csm-restore-*", "captured"))
	if err != nil || len(staged) != 1 {
		t.Fatalf("expected one retained source: paths=%v, error=%v", staged, err)
	}
	if got, err := os.ReadFile(staged[0]); err != nil || string(got) != rewritten {
		t.Fatalf("rewritten source lost after rollback failure: content=%q, error=%v", got, err)
	}
	if got, err := os.ReadFile(qPath); err != nil || string(got) != original {
		t.Fatalf("recovery copy lost after rollback failure: content=%q, error=%v", got, err)
	}
}

func TestQuarantineUnleasedSourceAllowsForeignOwnedOpenFile(t *testing.T) {
	for _, removalOnly := range []bool{false, true} {
		name := "copy-and-remove"
		if removalOnly {
			name = "remove-copied-source"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			src := filepath.Join(root, "source.php")
			qPath := filepath.Join(root, "quarantine", "copy.php")
			const original = "detected content"
			if err := os.WriteFile(src, []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			writer, openErr := os.OpenFile(src, os.O_WRONLY, 0)
			if openErr != nil {
				t.Fatal(openErr)
			}
			defer writer.Close()
			if os.Geteuid() == 0 {
				if err := writer.Chown(1001, 1002); err != nil {
					t.Fatal(err)
				}
			}
			info, statErr := writer.Stat()
			if statErr != nil {
				t.Fatal(statErr)
			}
			if err := os.MkdirAll(filepath.Dir(qPath), 0700); err != nil {
				t.Fatal(err)
			}
			if removalOnly {
				if err := os.WriteFile(qPath, []byte(original), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(qPath+".meta", []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			var moveErr error
			if removalOnly {
				moveErr = removeQuarantinedSource(src, qPath, info)
			} else {
				moveErr = quarantineFileTOCTOUSafe(src, qPath, info, []byte("{}"))
			}
			if moveErr != nil {
				t.Fatalf("generic quarantine failed with an open writer: %v", moveErr)
			}
			if _, err := os.Lstat(src); !os.IsNotExist(err) {
				t.Fatalf("source remains after quarantine: %v", err)
			}
			if got, err := os.ReadFile(qPath); err != nil || string(got) != original {
				t.Fatalf("recovery copy changed: content=%q, error=%v", got, err)
			}
		})
	}
}

func TestQuarantineUnleasedSourceBoundsGrowingCopy(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "source.php")
	qPath := filepath.Join(root, "quarantine", "copy.php")
	const original, appended = "detected content", "appended during capture"
	if err := os.WriteFile(src, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	info, statErr := os.Stat(src)
	if statErr != nil {
		t.Fatal(statErr)
	}
	writer, openErr := os.OpenFile(src, os.O_WRONLY|os.O_APPEND, 0)
	if openErr != nil {
		t.Fatal(openErr)
	}
	defer writer.Close()
	oldCopy := quarantineCopyByFD
	t.Cleanup(func() { quarantineCopyByFD = oldCopy })
	copyChecked := false
	quarantineCopyByFD = func(fd *os.File, destination string, metadata []byte, size int64) error {
		if _, err := writer.WriteString(appended); err != nil {
			return err
		}
		if err := oldCopy(fd, destination, metadata, size); err != nil {
			return err
		}
		copied, err := os.ReadFile(destination)
		if err != nil || string(copied) != original {
			t.Errorf("copy followed source growth: content=%q, error=%v", copied, err)
		}
		copyChecked = true
		return nil
	}
	moveErr := quarantineFileTOCTOUSafe(src, qPath, info, []byte("{}"))
	if !copyChecked || !errors.Is(moveErr, errFileResponseRefused) {
		t.Fatalf("growing source was not refused after bounded copy: checked=%v, error=%v", copyChecked, moveErr)
	}
	if got, err := os.ReadFile(src); err != nil || string(got) != original+appended {
		t.Fatalf("growing source was changed: content=%q, error=%v", got, err)
	}
	for _, path := range []string{qPath, qPath + ".meta"} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("untrustworthy copy remains at %s: %v", path, err)
		}
	}
}
