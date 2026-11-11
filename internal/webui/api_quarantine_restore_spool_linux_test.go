package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
)

const restoreSpoolMsgID = "1vABCD-000123-AB"

// quarantineSpoolMessage queues a message in a test Exim spool and moves it
// to quarantine through the finding's Fix action, as the Web UI does.
func quarantineSpoolMessage(t *testing.T) (qdir, spoolDir string) {
	t.Helper()
	tmp := t.TempDir()
	input := filepath.Join(tmp, "spool", "input")
	qdir = filepath.Join(tmp, "quarantine")
	if err := os.MkdirAll(qdir, 0700); err != nil {
		t.Fatal(err)
	}
	spoolDir = filepath.Join(input, restoreSpoolMsgID[5:6])
	if err := os.MkdirAll(spoolDir, 0750); err != nil {
		t.Fatal(err)
	}
	for suffix, body := range map[string]string{"-H": restoreSpoolMsgID + "-H\nheader\n", "-D": restoreSpoolMsgID + "-D\nbody\n"} {
		if err := os.WriteFile(filepath.Join(spoolDir, restoreSpoolMsgID+suffix), []byte(body), 0640); err != nil {
			t.Fatal(err)
		}
	}
	withQuarantineDir(t, qdir)
	t.Cleanup(checks.SetQuarantineDirForTest(qdir))
	t.Cleanup(checks.SetEximSpoolDirsForTest([]string{input}))

	res := checks.ApplyFix(context.Background(), "email_phishing_content", "Phishing queued (message: "+restoreSpoolMsgID+")", "")
	if !res.Success {
		t.Fatalf("quarantine spool message: %+v", res)
	}
	return qdir, spoolDir
}

func quarantinedSpoolEntry(t *testing.T, qdir, suffix string) string {
	t.Helper()
	entries, err := os.ReadDir(qdir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), restoreSpoolMsgID+suffix) {
			return e.Name()
		}
	}
	t.Fatalf("no quarantine entry for %s%s in %v", restoreSpoolMsgID, suffix, entries)
	return ""
}

func TestApiQuarantineRestoreReturnsSpoolMessageToQueue(t *testing.T) {
	for _, picked := range []string{"-H", "-D"} {
		t.Run(picked, func(t *testing.T) {
			qdir, spoolDir := quarantineSpoolMessage(t)
			id := quarantinedSpoolEntry(t, qdir, picked)
			// As in production, the Exim spool is outside the account roots.
			withQuarantineRestoreRoots(t, t.TempDir())

			s := newRestoreServer(t)
			w := httptest.NewRecorder()
			s.apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": id}))
			if w.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
			}
			for _, suffix := range []string{"-H", "-D"} {
				path := filepath.Join(spoolDir, restoreSpoolMsgID+suffix)
				got, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("%s not back in the spool: %v", suffix, err)
				}
				if !strings.HasPrefix(string(got), restoreSpoolMsgID+suffix+"\n") {
					t.Errorf("%s content = %q", suffix, got)
				}
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() != 0640 {
					t.Errorf("%s mode = %o, want 640", suffix, info.Mode().Perm())
				}
			}
			left, err := os.ReadDir(qdir)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range left {
				if strings.Contains(e.Name(), restoreSpoolMsgID) {
					t.Errorf("quarantine still holds %s", e.Name())
				}
			}
		})
	}
}

func TestApiQuarantineRestoreRefusesSpoolEntryOutsideEximSpool(t *testing.T) {
	qdir, spoolDir := quarantineSpoolMessage(t)
	id := quarantinedSpoolEntry(t, qdir, "-H")
	elsewhere := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.MkdirAll(elsewhere, 0755); err != nil {
		t.Fatal(err)
	}
	withQuarantineRestoreRoots(t, elsewhere)

	metaPath := filepath.Join(qdir, id+".meta")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatal(err)
	}
	var meta checks.QuarantineMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		t.Fatal(err)
	}
	meta.SpoolDir = elsewhere
	meta.OriginalPath = filepath.Join(elsewhere, restoreSpoolMsgID+"-H")
	data, _ = json.Marshal(meta)
	if err := os.WriteFile(metaPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	s := newRestoreServer(t)
	w := httptest.NewRecorder()
	s.apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": id}))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(meta.OriginalPath); !os.IsNotExist(err) {
		t.Errorf("restore wrote outside the Exim spool: %v", err)
	}
	if _, err := os.Stat(filepath.Join(spoolDir, restoreSpoolMsgID+"-H")); !os.IsNotExist(err) {
		t.Errorf("restore put the header back despite the refusal: %v", err)
	}
}

func TestApiQuarantineRestoreRefusesHashDirectoryLinkedOutsideQueue(t *testing.T) {
	qdir, spoolDir := quarantineSpoolMessage(t)
	id := quarantinedSpoolEntry(t, qdir, "-H")
	withQuarantineRestoreRoots(t, t.TempDir())
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.MkdirAll(outside, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(spoolDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, spoolDir); err != nil {
		t.Fatal(err)
	}

	s := newRestoreServer(t)
	w := httptest.NewRecorder()
	s.apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": id}))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", w.Code, w.Body.String())
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("restore wrote through the hash directory link: %v", entries)
	}
}
