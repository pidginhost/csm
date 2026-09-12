//go:build linux

package checks

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestQuarantineMetadataFailureKeepsOriginal(t *testing.T) {
	oldDir, oldCopy := quarantineDir, quarantineCopyByFD
	t.Cleanup(func() {
		quarantineDir = oldDir
		quarantineCopyByFD = oldCopy
	})
	for _, automatic := range []bool{false, true} {
		name := "manual"
		if automatic {
			name = "automatic"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			quarantineDir = filepath.Join(root, "quarantine")
			source := filepath.Join(root, "malware.bin")
			const content = "captured evidence"
			if err := os.WriteFile(source, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			info, err := os.Lstat(source)
			if err != nil {
				t.Fatal(err)
			}
			quarantineCopyByFD = func(src *os.File, destination string, metadata []byte) error {
				// A real filesystem failure, including when tests run as root:
				// the sidecar name cannot be opened as a regular output file.
				if err := os.Mkdir(destination+".meta", 0700); err != nil {
					return err
				}
				return oldCopy(src, destination, metadata)
			}
			if automatic {
				cfg := &config.Config{StatePath: t.TempDir()}
				cfg.AutoResponse.Enabled = true
				cfg.AutoResponse.QuarantineFiles = true
				actions := AutoQuarantineFiles(cfg, []alert.Finding{{Check: "backdoor_binary", Severity: alert.Critical, FilePath: source, Message: "detected test content"}})
				if len(actions) != 0 {
					t.Errorf("metadata failure reported successful automatic quarantine: %+v", actions)
				}
			} else {
				result := quarantineResolvedTarget(source, info)
				if result.Success || result.Error == "" {
					t.Errorf("metadata failure reported successful manual quarantine: %+v", result)
				}
			}
			data, readErr := os.ReadFile(source)
			if readErr != nil || string(data) != content {
				t.Fatalf("original removed before recoverable metadata existed: %q, error=%v", data, readErr)
			}
		})
	}
}

func TestQuarantineRegularFileAcrossFilesystems(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(source, []byte("cross-device evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("tmpfs destination", func(t *testing.T) {
		t.Setenv("TMPDIR", "/dev/shm")
		qDir := t.TempDir()
		qInfo, statErr := os.Stat(qDir)
		if statErr != nil {
			t.Fatal(statErr)
		}
		if info.Sys().(*syscall.Stat_t).Dev == qInfo.Sys().(*syscall.Stat_t).Dev {
			t.Fatal("cross-device test requires /dev/shm on a separate filesystem")
		}
		qPath := filepath.Join(qDir, "captured")
		if err := quarantineTarget(source, qPath, info, QuarantineMeta{OriginalPath: source, Size: info.Size()}); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(source); !os.IsNotExist(err) {
			t.Fatalf("source still present after cross-device quarantine: %v", err)
		}
		data, err := os.ReadFile(qPath)
		if err != nil || string(data) != "cross-device evidence" {
			t.Fatalf("cross-device recovery copy=%q, error=%v", data, err)
		}
		if data, err := os.ReadFile(qPath + ".meta"); err != nil || len(data) == 0 {
			t.Fatalf("cross-device metadata missing: %q, error=%v", data, err)
		}
	})
}
