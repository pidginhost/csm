//go:build linux

package checks

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// A hard-linked malware file used to be "quarantined" by adding one more
// link to the same account-owned inode and unlinking the detected name: the
// content stayed live under its other name and the quarantine entry itself
// stayed writable by the account through that name. A multi-link inode must
// be copied into quarantine, and the surviving links must be reported.
func TestQuarantineFileTOCTOUSafe_CopiesMultiLinkFile(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "public_html", "shell.php")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("<?php /* linked */"), 0o644); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(tmp, "elsewhere", "same.php")
	if err := os.MkdirAll(filepath.Dir(other), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(src, other); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(src)
	if err != nil {
		t.Fatal(err)
	}
	qPath := filepath.Join(tmp, "quarantine", "ts_shell.php")
	if mkErr := os.MkdirAll(filepath.Dir(qPath), 0o700); mkErr != nil {
		t.Fatal(mkErr)
	}

	err = quarantineFileTOCTOUSafe(src, qPath, info)
	if err == nil || !strings.Contains(err.Error(), "hard link") {
		t.Fatalf("surviving hard link not reported: err=%v", err)
	}
	if _, statErr := os.Stat(src); !os.IsNotExist(statErr) {
		t.Fatalf("detected path still present: %v", statErr)
	}
	qInfo, err := os.Stat(qPath)
	if err != nil {
		t.Fatalf("quarantine copy missing: %v", err)
	}
	otherInfo, err := os.Stat(other)
	if err != nil {
		t.Fatalf("surviving link missing: %v", err)
	}
	if os.SameFile(qInfo, otherInfo) {
		t.Fatal("quarantine entry shares the account-owned inode with the surviving link")
	}
	if qInfo.Mode().Perm() != 0o600 {
		t.Fatalf("quarantine copy mode = %04o, want 0600", qInfo.Mode().Perm())
	}
	if st, ok := qInfo.Sys().(*syscall.Stat_t); !ok || st.Uid != uint32(os.Geteuid()) {
		t.Fatalf("quarantine copy owner = %#v, want effective uid %d", qInfo.Sys(), os.Geteuid())
	}
	if got, _ := os.ReadFile(qPath); string(got) != "<?php /* linked */" {
		t.Fatalf("quarantine copy content = %q", got)
	}
}

// The account can create another hard link after the helper's initial fstat.
// The captured evidence must still be an independent private inode, and the
// surviving account-owned name must be reported after the detected name is
// removed.
func TestQuarantineFileTOCTOUSafe_CopiesLinkAddedAfterFstat(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "shell.php")
	if err := os.WriteFile(src, []byte("<?php /* raced link */"), 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(src)
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(tmp, "surviving.php")
	qPath := filepath.Join(tmp, "quarantine", "shell.php")
	if err = os.MkdirAll(filepath.Dir(qPath), 0o700); err != nil {
		t.Fatal(err)
	}

	oldCopy := quarantineCopyByFD
	quarantineCopyByFD = func(fd *os.File, dst string) error {
		if linkErr := os.Link(src, other); linkErr != nil {
			return linkErr
		}
		return oldCopy(fd, dst)
	}
	t.Cleanup(func() { quarantineCopyByFD = oldCopy })

	err = quarantineFileTOCTOUSafe(src, qPath, info)
	if err == nil || !strings.Contains(err.Error(), "hard link") {
		t.Fatalf("link added after fstat was not reported: %v", err)
	}
	if _, statErr := os.Stat(src); !os.IsNotExist(statErr) {
		t.Fatalf("detected name remains after quarantine: %v", statErr)
	}
	qInfo, err := os.Stat(qPath)
	if err != nil {
		t.Fatal(err)
	}
	otherInfo, err := os.Stat(other)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(qInfo, otherInfo) {
		t.Fatal("quarantine entry shares the raced account-owned inode")
	}
}

func linkedQuarantineFixture(t *testing.T, payload []byte) (string, string) {
	t.Helper()
	tmp := t.TempDir()
	src := filepath.Join(tmp, "shell.php")
	if err := os.WriteFile(src, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(tmp, "surviving.php")
	if err := os.Link(src, other); err != nil {
		t.Fatal(err)
	}
	return src, other
}

// The hard-link result is a warning about another reachable name, not a
// failed move: the detected path is gone and an independent captured copy is
// already in quarantine. Callers must record that completed action and write
// its metadata instead of reporting that nothing happened.
func TestQuarantineCallersTreatRemainingLinksAsCompleted(t *testing.T) {
	t.Run("batch", func(t *testing.T) {
		src, other := linkedQuarantineFixture(t, []byte("<?php /* linked */"))
		qdir := filepath.Join(filepath.Dir(src), "quarantine")
		withAutoRespQuarantineDir(t, qdir)
		cfg := &config.Config{}
		cfg.AutoResponse.Enabled = true
		cfg.AutoResponse.QuarantineFiles = true

		actions := AutoQuarantineFiles(cfg, []alert.Finding{{
			Check: "php_dropper", Severity: alert.Critical, FilePath: src, Message: "linked dropper",
		}})
		if len(actions) != 1 || !strings.Contains(actions[0].Details, "hard link") {
			t.Fatalf("completed hard-link quarantine actions = %+v, want one warning action", actions)
		}
		if _, err := os.Stat(src); !os.IsNotExist(err) {
			t.Fatalf("detected path remains after batch quarantine: %v", err)
		}
		if _, err := os.Stat(other); err != nil {
			t.Fatalf("surviving link unexpectedly removed: %v", err)
		}
	})

	t.Run("inline", func(t *testing.T) {
		payload := makeHighEntropyContent(t, 2048)
		src, _ := linkedQuarantineFixture(t, payload)
		qdir := filepath.Join(filepath.Dir(src), "quarantine")
		withQuarantineDirIQ(t, qdir)
		qPath, ok := InlineQuarantine(alert.Finding{
			Check: "yara_match", Details: "Category: dropper\nRule: webshell_generic\n",
		}, src, payload)
		if !ok || qPath == "" {
			t.Fatalf("inline hard-link quarantine = (%q, %v), want completed", qPath, ok)
		}
		if _, err := os.Stat(qPath + ".meta"); err != nil {
			t.Fatalf("inline quarantine metadata missing: %v", err)
		}
	})

	t.Run("remediation", func(t *testing.T) {
		src, _ := linkedQuarantineFixture(t, []byte("linked remediation"))
		root := filepath.Dir(src)
		withAllowedRoots(t, root)
		withQuarantineDir(t, filepath.Join(root, "quarantine"))
		res := fixQuarantine(src)
		if !res.Success || !strings.Contains(res.Description, "hard link") {
			t.Fatalf("hard-link remediation result = %+v, want completed with warning", res)
		}
	})
}
