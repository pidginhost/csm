package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
)

// TestApiVerifyFindingResolvedDismisses: a re-check that finds the condition
// gone (here, a quarantine-family file that no longer exists) clears the
// finding from the latest set.
func TestApiVerifyFindingResolvedDismisses(t *testing.T) {
	checks.SetOS(verifyFindingFakeOS{})
	t.Cleanup(func() { checks.SetOS(verifyFindingRealOS{}) })

	s := newTestServer(t, "tok")
	path := "/home/alice/public_html/gone.php"
	f := alert.Finding{
		Check:   "webshell",
		Message: "Known webshell found: " + path,
	}
	s.store.ClearLatestFindings()
	s.store.SetLatestFindings([]alert.Finding{f})

	w := httptest.NewRecorder()
	body := `{"check":"webshell","message":"Known webshell found: ` + path + `","file_path":"` + path + `"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiVerifyFinding(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var res struct {
		Checked  bool `json:"checked"`
		Resolved bool `json:"resolved"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if !res.Checked || !res.Resolved {
		t.Fatalf("expected checked+resolved, got %+v (body %s)", res, w.Body.String())
	}
	if got := len(s.store.LatestFindings()); got != 0 {
		t.Errorf("resolved finding should be dismissed, still have %d", got)
	}
}

// TestApiVerifyFindingNotResolvedKeeps: a check type with no automated
// re-check returns checked=false and must NOT dismiss the finding.
func TestApiVerifyFindingNotResolvedKeeps(t *testing.T) {
	s := newTestServer(t, "tok")
	f := alert.Finding{Check: "brute_force", Message: "SSH brute force from 198.51.100.7"}
	s.store.ClearLatestFindings()
	s.store.SetLatestFindings([]alert.Finding{f})

	w := httptest.NewRecorder()
	body := `{"check":"brute_force","message":"SSH brute force from 198.51.100.7"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiVerifyFinding(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var res struct {
		Checked  bool `json:"checked"`
		Resolved bool `json:"resolved"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if res.Checked || res.Resolved {
		t.Errorf("unknown type should be unchecked+unresolved, got %+v", res)
	}
	if got := len(s.store.LatestFindings()); got != 1 {
		t.Errorf("unresolved finding must remain, have %d want 1", got)
	}
}

func TestApiVerifyFindingCheckedUnresolvedKeeps(t *testing.T) {
	path := "/home/alice/public_html/shell.php"
	checks.SetOS(verifyFindingFakeOS{path: path})
	t.Cleanup(func() { checks.SetOS(verifyFindingRealOS{}) })

	s := newTestServer(t, "tok")
	f := alert.Finding{Check: "webshell", Message: "Known webshell found: " + path, FilePath: path}
	s.store.ClearLatestFindings()
	s.store.SetLatestFindings([]alert.Finding{f})

	w := httptest.NewRecorder()
	body := `{"check":"webshell","message":"Known webshell found: ` + path + `","file_path":"` + path + `"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiVerifyFinding(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var res struct {
		Checked  bool `json:"checked"`
		Resolved bool `json:"resolved"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if !res.Checked || res.Resolved {
		t.Fatalf("expected checked+unresolved, got %+v (body %s)", res, w.Body.String())
	}
	if got := len(s.store.LatestFindings()); got != 1 {
		t.Errorf("checked unresolved finding must remain, have %d want 1", got)
	}
}

func TestVerifyFindingInputUsesStoredFingerprint(t *testing.T) {
	s := newTestServer(t, "tok")
	f := alert.Finding{
		Check:         "suspicious_php_content",
		Message:       "Suspicious PHP content detected: /home/alice/public_html/shell.php",
		Details:       "server details",
		FilePath:      "/home/alice/public_html/shell.php",
		ContentSHA256: "recordedhash",
		DetectLogic:   "php=1;sig=2;yara=3",
	}
	s.store.ClearLatestFindings()
	s.store.SetLatestFindings([]alert.Finding{f})

	in, key := s.verifyFindingInput(verifyFindingRequest{
		Key:           f.Key(),
		Check:         f.Check,
		Message:       f.Message,
		Details:       "client details",
		FilePath:      "/home/alice/public_html/other.php",
		ContentSHA256: "forged-current-hash",
	})
	if key != f.Key() {
		t.Fatalf("key = %q, want %q", key, f.Key())
	}
	if in.ContentSHA256 != f.ContentSHA256 || in.DetectLogic != f.DetectLogic {
		t.Fatalf("fingerprint = (%q, %q), want stored (%q, %q)", in.ContentSHA256, in.DetectLogic, f.ContentSHA256, f.DetectLogic)
	}
	if in.Path != f.FilePath || in.Details != f.Details {
		t.Fatalf("input used client-controlled fields: %+v", in)
	}
}

func TestVerifyFindingInputIgnoresClientFingerprintWithoutStoredFinding(t *testing.T) {
	s := newTestServer(t, "tok")
	in, _ := s.verifyFindingInput(verifyFindingRequest{
		Check:         "suspicious_php_content",
		Message:       "Suspicious PHP content detected: /home/alice/public_html/shell.php",
		FilePath:      "/home/alice/public_html/shell.php",
		ContentSHA256: "forged-current-hash",
	})
	if in.ContentSHA256 != "" || in.DetectLogic != "" {
		t.Fatalf("client fingerprint was trusted: %+v", in)
	}
}

type verifyFindingFakeOS struct {
	path string
}

func (v verifyFindingFakeOS) ReadFile(string) ([]byte, error) { return nil, os.ErrNotExist }
func (v verifyFindingFakeOS) ReadDir(string) ([]os.DirEntry, error) {
	return nil, os.ErrNotExist
}
func (v verifyFindingFakeOS) Stat(name string) (os.FileInfo, error)  { return v.Lstat(name) }
func (v verifyFindingFakeOS) Lstat(name string) (os.FileInfo, error) { return v.info(name) }
func (v verifyFindingFakeOS) Readlink(string) (string, error)        { return "", os.ErrNotExist }
func (v verifyFindingFakeOS) Open(string) (*os.File, error)          { return nil, os.ErrNotExist }
func (v verifyFindingFakeOS) WriteFile(string, []byte, os.FileMode) error {
	return os.ErrPermission
}
func (v verifyFindingFakeOS) MkdirAll(string, os.FileMode) error { return os.ErrPermission }
func (v verifyFindingFakeOS) Remove(string) error                { return os.ErrPermission }
func (v verifyFindingFakeOS) Glob(string) ([]string, error)      { return nil, nil }

func (v verifyFindingFakeOS) info(name string) (os.FileInfo, error) {
	switch name {
	case "/home", "/home/alice", "/home/alice/public_html":
		return verifyFindingFileInfo{name: name, mode: os.ModeDir | 0755}, nil
	case v.path:
		return verifyFindingFileInfo{name: "shell.php", mode: 0644, size: 5}, nil
	default:
		return nil, os.ErrNotExist
	}
}

type verifyFindingRealOS struct{}

func (verifyFindingRealOS) ReadFile(name string) ([]byte, error)       { return os.ReadFile(name) }
func (verifyFindingRealOS) ReadDir(name string) ([]os.DirEntry, error) { return os.ReadDir(name) }
func (verifyFindingRealOS) Stat(name string) (os.FileInfo, error)      { return os.Stat(name) }
func (verifyFindingRealOS) Lstat(name string) (os.FileInfo, error)     { return os.Lstat(name) }
func (verifyFindingRealOS) Readlink(name string) (string, error)       { return os.Readlink(name) }
func (verifyFindingRealOS) Open(name string) (*os.File, error)         { return os.Open(name) }
func (verifyFindingRealOS) WriteFile(name string, data []byte, perm os.FileMode) error {
	return os.WriteFile(name, data, perm)
}
func (verifyFindingRealOS) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}
func (verifyFindingRealOS) Remove(name string) error              { return os.Remove(name) }
func (verifyFindingRealOS) Glob(pattern string) ([]string, error) { return filepath.Glob(pattern) }

type verifyFindingFileInfo struct {
	name string
	mode os.FileMode
	size int64
}

func (v verifyFindingFileInfo) Name() string       { return v.name }
func (v verifyFindingFileInfo) Size() int64        { return v.size }
func (v verifyFindingFileInfo) Mode() os.FileMode  { return v.mode }
func (v verifyFindingFileInfo) ModTime() time.Time { return time.Time{} }
func (v verifyFindingFileInfo) IsDir() bool        { return v.mode.IsDir() }
func (v verifyFindingFileInfo) Sys() any           { return nil }

func TestApiVerifyFindingMissingFields(t *testing.T) {
	s := newTestServer(t, "tok")
	for _, body := range []string{`{}`, `{"check":"webshell"}`, `{"message":"x"}`} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		s.apiVerifyFinding(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("body %s: status = %d, want 400", body, w.Code)
		}
	}
}

func TestApiVerifyFindingRejectsGET(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiVerifyFinding(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}
