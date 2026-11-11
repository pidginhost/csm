package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/safepath"
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
			assertRestoredSpoolMessage(t, spoolDir)
			for _, suffix := range []string{"-H", "-D"} {
				path := filepath.Join(spoolDir, restoreSpoolMsgID+suffix)
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

func TestSpoolRestorePublishesOnlyCompleteFiles(t *testing.T) {
	qdir, spoolDir := quarantineSpoolMessage(t)
	id := quarantinedSpoolEntry(t, qdir, "-H")
	old := syncQuarantineRestoredFile
	t.Cleanup(func() { syncQuarantineRestoredFile = old })
	syncs := 0
	syncQuarantineRestoredFile = func(f *os.File) error {
		syncs++
		if _, err := os.Lstat(filepath.Join(spoolDir, restoreSpoolMsgID+"-H")); !os.IsNotExist(err) {
			t.Errorf("header visible before staged files are durable: %v", err)
		}
		return old(f)
	}
	w := httptest.NewRecorder()
	newRestoreServer(t).apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": id}))
	if w.Code != http.StatusOK || syncs != 2 {
		t.Fatalf("restore status=%d syncs=%d body=%s", w.Code, syncs, w.Body.String())
	}
}

func TestSpoolRestoreRetryAfterHeaderFailure(t *testing.T) {
	qdir, spoolDir := quarantineSpoolMessage(t)
	id := quarantinedSpoolEntry(t, qdir, "-D")
	old := syncQuarantineRestoredFile
	t.Cleanup(func() { syncQuarantineRestoredFile = old })
	syncs := 0
	syncQuarantineRestoredFile = func(f *os.File) error {
		syncs++
		if syncs == 2 {
			return syscall.EIO
		}
		return old(f)
	}
	s := newRestoreServer(t)
	w := httptest.NewRecorder()
	s.apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": id}))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("fault returned %d: %s", w.Code, w.Body.String())
	}
	if _, err := os.Lstat(filepath.Join(spoolDir, restoreSpoolMsgID+"-H")); !os.IsNotExist(err) {
		t.Fatalf("failed header was published: %v", err)
	}
	syncQuarantineRestoredFile = old
	w = httptest.NewRecorder()
	s.apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": id}))
	if w.Code != http.StatusOK {
		t.Fatalf("retry using the same entry returned %d: %s", w.Code, w.Body.String())
	}
	assertRestoredSpoolMessage(t, spoolDir)
}

func TestSpoolRestoreRetryAfterEvidenceRemovalFailure(t *testing.T) {
	for _, suffix := range []string{"-D", "-H"} {
		for _, phase := range []string{"before-content", "after-content", "after-metadata", "delivered"} {
			t.Run(suffix+"/"+phase, func(t *testing.T) {
				qdir, spoolDir := quarantineSpoolMessage(t)
				id := quarantinedSpoolEntry(t, qdir, suffix)
				old := removeRestoredQuarantineEvidence
				t.Cleanup(func() { removeRestoredQuarantineEvidence = old })
				injected := false
				removeRestoredQuarantineEvidence = func(path, metaPath string) error {
					if !strings.HasSuffix(path, suffix) {
						return old(path, metaPath)
					}
					injected = true
					if phase == "after-content" {
						if err := os.Remove(path); err != nil {
							t.Fatal(err)
						}
					}
					if phase == "after-metadata" {
						if err := old(path, metaPath); err != nil {
							t.Fatal(err)
						}
					}
					if phase == "delivered" {
						assertRestoredSpoolMessage(t, spoolDir)
						for _, part := range []string{"-H", "-D"} {
							if err := os.Remove(filepath.Join(spoolDir, restoreSpoolMsgID+part)); err != nil {
								t.Fatal(err)
							}
						}
					}
					return syscall.EIO
				}
				s := newRestoreServer(t)
				w := httptest.NewRecorder()
				s.apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": id}))
				if !injected || w.Code == http.StatusOK {
					t.Fatalf("cleanup fault not reported: %d %s", w.Code, w.Body.String())
				}
				removeRestoredQuarantineEvidence = old
				w = httptest.NewRecorder()
				s.apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": id}))
				if w.Code != http.StatusOK {
					t.Fatalf("cleanup retry returned %d: %s", w.Code, w.Body.String())
				}
				if phase == "delivered" {
					for _, part := range []string{"-H", "-D"} {
						if _, err := os.Lstat(filepath.Join(spoolDir, restoreSpoolMsgID+part)); !os.IsNotExist(err) {
							t.Errorf("retry requeued delivered %s: %v", part, err)
						}
					}
				} else {
					assertRestoredSpoolMessage(t, spoolDir)
				}
				entries, err := os.ReadDir(qdir)
				if err != nil || len(entries) != 0 {
					t.Errorf("cleanup left quarantine entries: %v, %v", entries, err)
				}
			})
		}
	}
}

func TestSpoolRestoreRefusesIncompletePair(t *testing.T) {
	for _, missing := range []string{"body-metadata", "body", "header"} {
		t.Run(missing, func(t *testing.T) {
			qdir, spoolDir := quarantineSpoolMessage(t)
			body := quarantinedSpoolEntry(t, qdir, "-D")
			header := quarantinedSpoolEntry(t, qdir, "-H")
			id, remove := header, body
			if missing == "header" {
				id, remove = body, header
			}
			if err := os.Remove(filepath.Join(qdir, remove+".meta")); err != nil {
				t.Fatal(err)
			}
			if missing != "body-metadata" {
				if err := os.Remove(filepath.Join(qdir, remove)); err != nil {
					t.Fatal(err)
				}
			}
			w := httptest.NewRecorder()
			newRestoreServer(t).apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": id}))
			if w.Code == http.StatusOK {
				t.Fatalf("incomplete message accepted: %s", w.Body.String())
			}
			entries, err := os.ReadDir(spoolDir)
			if err != nil || len(entries) != 0 {
				t.Errorf("refusal changed spool: %v, %v", entries, err)
			}
		})
	}
}

func TestSpoolRestoreHeaderConflictDoesNotPublishBody(t *testing.T) {
	qdir, spoolDir := quarantineSpoolMessage(t)
	id := quarantinedSpoolEntry(t, qdir, "-D")
	header := filepath.Join(spoolDir, restoreSpoolMsgID+"-H")
	if err := os.WriteFile(header, []byte("existing header"), 0640); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	newRestoreServer(t).apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": id}))
	if w.Code != http.StatusConflict {
		t.Fatalf("conflict returned %d: %s", w.Code, w.Body.String())
	}
	if _, err := os.Lstat(filepath.Join(spoolDir, restoreSpoolMsgID+"-D")); !os.IsNotExist(err) {
		t.Errorf("body published alongside an existing header: %v", err)
	}
	if got, err := os.ReadFile(header); err != nil || string(got) != "existing header" {
		t.Errorf("existing header changed: %q %v", got, err)
	}
}

func assertRestoredSpoolMessage(t *testing.T, spoolDir string) {
	t.Helper()
	for suffix, content := range map[string]string{"-H": "header", "-D": "body"} {
		want := restoreSpoolMsgID + suffix + "\n" + content + "\n"
		got, err := os.ReadFile(filepath.Join(spoolDir, restoreSpoolMsgID+suffix))
		if err != nil || string(got) != want {
			t.Fatalf("restored %s = %q, %v; want %q", suffix, got, err, want)
		}
	}
}

func TestSpoolRestoreResumesPublicationAfterSyncFailure(t *testing.T) {
	for _, phase := range []string{"body", "header", "delivered"} {
		t.Run(phase, func(t *testing.T) {
			qdir, spoolDir := quarantineSpoolMessage(t)
			id := quarantinedSpoolEntry(t, qdir, "-H")
			parentInfo, err := os.Stat(spoolDir)
			if err != nil {
				t.Fatal(err)
			}
			old := syncQuarantineRestoredParent
			t.Cleanup(func() { syncQuarantineRestoredParent = old })
			injected := false
			syncQuarantineRestoredParent = func(dir *safepath.Dir) error {
				info, err := dir.Info()
				if err != nil {
					t.Fatal(err)
				}
				if !os.SameFile(info, parentInfo) {
					return old(dir)
				}
				_, headerErr := os.Lstat(filepath.Join(spoolDir, restoreSpoolMsgID+"-H"))
				if phase != "body" && os.IsNotExist(headerErr) {
					return old(dir)
				}
				if phase == "body" && !os.IsNotExist(headerErr) {
					t.Fatalf("header was published before its body was durable: %v", headerErr)
				}
				injected = true
				if phase == "delivered" {
					assertRestoredSpoolMessage(t, spoolDir)
					for _, suffix := range []string{"-D", "-H"} {
						if err := os.Remove(filepath.Join(spoolDir, restoreSpoolMsgID+suffix)); err != nil {
							t.Fatal(err)
						}
					}
				}
				return syscall.EIO
			}
			w := httptest.NewRecorder()
			newRestoreServer(t).apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": id}))
			if !injected || w.Code != http.StatusInternalServerError {
				t.Fatalf("sync failure returned %d, injected=%v: %s", w.Code, injected, w.Body.String())
			}
			syncQuarantineRestoredParent = old
			w = httptest.NewRecorder()
			// A fresh server also has to recover the on-disk publication state.
			newRestoreServer(t).apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": id}))
			if w.Code != http.StatusOK {
				t.Fatalf("publication retry returned %d: %s", w.Code, w.Body.String())
			}
			if phase == "delivered" {
				entries, err := os.ReadDir(spoolDir)
				if err != nil || len(entries) != 0 {
					t.Fatalf("delivered mail was requeued: %v %v", entries, err)
				}
			} else {
				assertRestoredSpoolMessage(t, spoolDir)
			}
		})
	}
}

func TestSpoolRestoreRetainsHeaderWhenPublishedBodyChanges(t *testing.T) {
	qdir, spoolDir := quarantineSpoolMessage(t)
	id := quarantinedSpoolEntry(t, qdir, "-H")
	old := syncQuarantineRestoredParent
	t.Cleanup(func() { syncQuarantineRestoredParent = old })
	parentInfo, err := os.Stat(spoolDir)
	if err != nil {
		t.Fatal(err)
	}
	syncQuarantineRestoredParent = func(dir *safepath.Dir) error {
		info, err := dir.Info()
		if err != nil {
			t.Fatal(err)
		}
		if os.SameFile(parentInfo, info) {
			return syscall.EIO
		}
		return old(dir)
	}
	s := newRestoreServer(t)
	w := httptest.NewRecorder()
	s.apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": id}))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected partial publication, got %d: %s", w.Code, w.Body.String())
	}
	syncQuarantineRestoredParent = old
	body := filepath.Join(spoolDir, restoreSpoolMsgID+"-D")
	if err := os.WriteFile(body, []byte("different body"), 0640); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	s.apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": id}))
	if w.Code != http.StatusConflict {
		t.Fatalf("changed body returned %d: %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(spoolDir, restoreSpoolMsgID+"-H")); !os.IsNotExist(err) {
		t.Errorf("header published over changed body: %v", err)
	}
	if got, err := os.ReadFile(body); err != nil || string(got) != "different body" {
		t.Errorf("changed body was overwritten: %q %v", got, err)
	}
}

func TestSpoolRestoreHeaderOnlyUsesExistingBody(t *testing.T) {
	qdir, spoolDir := quarantineSpoolMessage(t)
	id := quarantinedSpoolEntry(t, qdir, "-H")
	body := filepath.Join(qdir, quarantinedSpoolEntry(t, qdir, "-D"))
	if err := os.Rename(body, filepath.Join(spoolDir, restoreSpoolMsgID+"-D")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(body + ".meta"); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	newRestoreServer(t).apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": id}))
	if w.Code != http.StatusOK {
		t.Fatalf("partial quarantine restore returned %d: %s", w.Code, w.Body.String())
	}
	assertRestoredSpoolMessage(t, spoolDir)
}

func TestSpoolRestorePreservesAttributes(t *testing.T) {
	qdir, spoolDir := quarantineSpoolMessage(t)
	id := quarantinedSpoolEntry(t, qdir, "-H")
	mtime := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	uid, gid := os.Getuid(), os.Getgid()
	if os.Geteuid() == 0 {
		uid, gid = 1234, 1235
	}
	for _, suffix := range []string{"-D", "-H"} {
		metaPath := filepath.Join(qdir, quarantinedSpoolEntry(t, qdir, suffix)+".meta")
		meta, err := readQuarantineMeta(metaPath)
		if err != nil {
			t.Fatal(err)
		}
		meta.OriginalModTime, meta.Mode = mtime, "-rw-------"
		meta.Owner, meta.Group = uid, gid
		data, err := json.Marshal(meta)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(metaPath, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	w := httptest.NewRecorder()
	newRestoreServer(t).apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": id}))
	if w.Code != http.StatusOK {
		t.Fatalf("restore returned %d: %s", w.Code, w.Body.String())
	}
	for _, suffix := range []string{"-D", "-H"} {
		path := filepath.Join(spoolDir, restoreSpoolMsgID+suffix)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 || !info.ModTime().Equal(mtime) {
			t.Errorf("%s attributes: %v %v", suffix, info.Mode(), info.ModTime())
		}
		if owner := fileOwner(t, path); owner.uid != uid || owner.gid != gid {
			t.Errorf("%s owner = %v", suffix, owner)
		}
	}
}

func TestSpoolRestoreConcurrentRequests(t *testing.T) {
	qdir, spoolDir := quarantineSpoolMessage(t)
	ids := []string{quarantinedSpoolEntry(t, qdir, "-H"), quarantinedSpoolEntry(t, qdir, "-D")}
	s := newRestoreServer(t)
	start := make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, 8)
	var wg sync.WaitGroup
	for i := range 8 {
		r := newRestoreRequest(t, map[string]string{"id": ids[i%2]})
		wg.Go(func() {
			<-start
			w := httptest.NewRecorder()
			s.apiQuarantineRestore(w, r)
			results <- w
		})
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	for w := range results {
		if w.Code == http.StatusOK {
			successes++
		} else if w.Code != http.StatusNotFound {
			t.Errorf("concurrent restore returned %d: %s", w.Code, w.Body.String())
		}
	}
	if successes != 1 {
		t.Errorf("successful restores = %d, want 1", successes)
	}
	assertRestoredSpoolMessage(t, spoolDir)
}

func TestSpoolRestoreStaleRequestDoesNotRequeue(t *testing.T) {
	qdir, spoolDir := quarantineSpoolMessage(t)
	id := quarantinedSpoolEntry(t, qdir, "-H")
	entry, err := resolveQuarantineEntry(id)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := readQuarantineMeta(entry.MetaPath)
	if err != nil {
		t.Fatal(err)
	}
	s := newRestoreServer(t)
	w := httptest.NewRecorder()
	s.apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": id}))
	if w.Code != http.StatusOK {
		t.Fatalf("restore returned %d: %s", w.Code, w.Body.String())
	}
	for _, suffix := range []string{"-D", "-H"} {
		if removeErr := os.Remove(filepath.Join(spoolDir, restoreSpoolMsgID+suffix)); removeErr != nil {
			t.Fatal(removeErr)
		}
	}
	w = httptest.NewRecorder()
	// This caller read metadata before the first caller acquired the lock.
	s.restoreQuarantinedSpoolMessage(w, newRestoreRequest(t, map[string]string{"id": id}), entry, *meta)
	if w.Code != http.StatusNotFound {
		t.Fatalf("stale request returned %d: %s", w.Code, w.Body.String())
	}
	entries, err := os.ReadDir(spoolDir)
	if err != nil || len(entries) != 0 {
		t.Errorf("stale request requeued delivered mail: %v %v", entries, err)
	}
}
