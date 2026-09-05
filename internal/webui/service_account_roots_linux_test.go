//go:build linux && systemdintegration

package webui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/signatures"
	"golang.org/x/sys/unix"
)

// This test runs as a real systemd service using the packaged sandbox and the
// generated account-root drop-in. An ordinary test process cannot prove that
// the configured grant is active in the service's mount namespace.
func TestCustomAccountRootsInSystemdService(t *testing.T) {
	if os.Getenv("INVOCATION_ID") == "" {
		t.Fatal("run this test inside the isolated systemd service harness")
	}
	root, outside := os.Getenv("CSM_TEST_ACCOUNT_ROOT"), os.Getenv("CSM_TEST_OUTSIDE_ROOT")
	if !strings.HasPrefix(root, "/srv/") || !strings.HasPrefix(outside, "/srv/") || root == outside {
		t.Fatal("isolated custom account and sibling roots are required")
	}
	var insideFS, outsideFS unix.Statfs_t
	if err := unix.Statfs(root, &insideFS); err != nil {
		t.Fatal(err)
	}
	if err := unix.Statfs(outside, &outsideFS); err != nil {
		t.Fatal(err)
	}
	if insideFS.Flags&unix.ST_RDONLY != 0 || outsideFS.Flags&unix.ST_RDONLY == 0 {
		t.Fatal("test requires a writable custom volume and a read-only sibling")
	}
	doctor, doctorErr := exec.Command(os.Getenv("CSM_TEST_BINARY"), "doctor", "--json", "--config", os.Getenv("CSM_TEST_CONFIG")).Output()
	var report struct {
		Checks []struct{ Name, Status, Message string }
	}
	if err := json.Unmarshal(doctor, &report); err != nil {
		t.Fatalf("doctor output=%s error=%v command error=%v", doctor, err, doctorErr)
	}
	rootChecks := 0
	for _, check := range report.Checks {
		if check.Name == "account root access" {
			rootChecks++
			if check.Status != "ok" {
				t.Fatalf("live systemd access check: %+v", check)
			}
		}
	}
	if rootChecks != 1 {
		t.Fatalf("doctor must inspect the running service exactly once: %s", doctor)
	}
	t.Setenv("TMPDIR", root)
	dir := t.TempDir()
	path := filepath.Join(dir, "detected.php")
	payload := "<?php eval($_POST['cmd']); /*" + strings.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 64) + "*/"
	if err := os.WriteFile(path, []byte(payload), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 1001, 1002); err != nil {
		t.Fatal(err)
	}
	stamp := time.Date(2024, 2, 3, 4, 5, 6, 123456789, time.UTC)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	original, statErr := os.Stat(path)
	if statErr != nil {
		t.Fatal(statErr)
	}
	scanner := signatures.NewScanner(os.Getenv("CSM_TEST_RULES_DIR"))
	if err := scanner.LoadError(); err != nil {
		t.Fatal(err)
	}
	matches := scanner.ScanFile(path, len(payload)+1)
	if len(matches) == 0 || matches[0].Severity != "critical" {
		t.Fatalf("production rules did not detect the fixture: %+v", matches)
	}
	server := newRestoreServer(t)
	server.cfg.AccountRoots = []string{root}
	server.cfg.AutoResponse.Enabled, server.cfg.AutoResponse.QuarantineFiles = true, true
	finding := alert.Finding{Severity: alert.Critical, Check: "signature_match_realtime", FilePath: path, Details: fmt.Sprintf("Category: %s\n", matches[0].Category)}
	qpath, ok := checks.InlineQuarantineGatedIdentified(server.cfg, finding, path, []byte(payload), original)
	if !ok {
		t.Fatal("detected content was not quarantined under the service sandbox")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("original still exists: %v", err)
	}
	listed := httptest.NewRecorder()
	server.apiQuarantine(listed, httptest.NewRequest(http.MethodGet, "/api/v1/quarantine", nil))
	var entries []struct {
		ID   string `json:"id"`
		Path string `json:"original_path"`
	}
	if err := json.Unmarshal(listed.Body.Bytes(), &entries); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, entry := range entries {
		if entry.Path == path {
			ids = append(ids, entry.ID)
		}
	}
	if len(ids) != 1 {
		t.Fatalf("quarantine listing lost or duplicated the capture: %+v", entries)
	}
	restored := httptest.NewRecorder()
	server.apiQuarantineRestore(restored, newRestoreRequest(t, map[string]string{"id": ids[0]}))
	if restored.Code != http.StatusOK {
		t.Fatalf("restore=%d %s", restored.Code, restored.Body.String())
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if stat.Uid != 1001 || stat.Gid != 1002 || info.Mode().Perm() != 0640 || !info.ModTime().Equal(stamp) {
		t.Fatalf("restored attributes=%+v", info)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != payload {
		t.Fatalf("restored bytes differ: %v", err)
	}
	for _, evidence := range []string{qpath, qpath + ".meta"} {
		if _, err := os.Stat(evidence); !os.IsNotExist(err) {
			t.Fatalf("restored evidence remains: %s %v", evidence, err)
		}
	}

	for _, attack := range []bool{false, true} {
		destination := filepath.Join(outside, "guard")
		if attack {
			parent := filepath.Join(dir, "attack")
			if err := os.Mkdir(parent, 0755); err != nil {
				t.Fatal(err)
			}
			destination = filepath.Join(parent, "guard")
			quarantineRestoreAfterValidateForTest = func(string) {
				if err := os.Rename(parent, parent+"-moved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, parent); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() { quarantineRestoreAfterValidateForTest = nil })
		}
		id := fmt.Sprintf("root-boundary-%v", attack)
		qfile := filepath.Join(quarantineDir, id)
		metadata, marshalErr := json.Marshal(checks.QuarantineMeta{OriginalPath: destination, Mode: "-rw-r-----", Owner: 1001, Group: 1002})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if err := os.WriteFile(qfile, []byte("replacement"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(qfile+".meta", metadata, 0600); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		server.apiQuarantineRestore(response, newRestoreRequest(t, map[string]string{"id": id}))
		quarantineRestoreAfterValidateForTest = nil
		want := http.StatusBadRequest
		if attack {
			want = http.StatusConflict
		}
		if response.Code != want {
			t.Fatalf("root attack=%v status=%d body=%s", attack, response.Code, response.Body.String())
		}
		got, err := os.ReadFile(filepath.Join(outside, "guard"))
		if err != nil || string(got) != "untouched" {
			t.Fatalf("sibling was changed: %q %v", got, err)
		}
		for _, evidence := range []string{qfile, qfile + ".meta"} {
			if _, err := os.Stat(evidence); err != nil {
				t.Fatalf("failed restore lost evidence: %s %v", evidence, err)
			}
		}
	}
}
