//go:build linux && systemdintegration

package webui

import (
	"context"
	"encoding/json"
	"errors"
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
	"github.com/pidginhost/csm/internal/modsec"
	"github.com/pidginhost/csm/internal/processhandle"
	"github.com/pidginhost/csm/internal/signatures"
	"github.com/pidginhost/csm/internal/systemdrun"
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
	t.Run("configuration confinement", testServiceConfigurationWrites)
	t.Run("process signaling", func(t *testing.T) {
		child := exec.Command("sleep", "60")
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
		if err := processhandle.Signal(context.Background(), child.Process.Pid, syscall.SIGTERM, func() error { return nil }); err != nil {
			t.Fatal(err)
		}
		if err := child.Wait(); err == nil || child.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGTERM {
			t.Fatalf("service could not signal its captured child: %v", err)
		}
	})
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
	qpath, ok, _ := checks.InlineQuarantineGatedIdentified(server.cfg, &finding, path, []byte(payload), original)
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

func testServiceConfigurationWrites(t *testing.T) {
	for _, path := range []string{"/etc/csm-audit-unrelated", "/etc/exim.conf.local"} {
		if err := os.WriteFile(path, []byte("unexpected write"), 0600); !errors.Is(err, syscall.EROFS) {
			t.Fatalf("unrelated configuration write %s: %v", path, err)
		}
	}
	for _, dir := range []string{"/etc/audit/rules.d", "/etc/modprobe.d", "/etc/apache2/conf.d/modsec", "/etc/apache2/conf-enabled", "/etc/httpd/conf.d", "/etc/nginx/conf.d", "/usr/local/lsws/conf/templates"} {
		file, err := os.CreateTemp(dir, "csm-test-*")
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(file.Name(), file.Name()+".conf"); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(file.Name() + ".conf"); err != nil {
			t.Fatal(err)
		}
	}
	rules := "/etc/apache2/conf.d/modsec/modsec2.user.conf"
	overrides := "/etc/apache2/conf.d/modsec/csm-overrides.conf"
	if err := os.WriteFile(rules, []byte("# operator rule\n"), 0644); err != nil {
		t.Fatal(err)
	}
	modsec.EnsureOverridesInclude(rules, overrides)
	merged, err := os.ReadFile(rules)
	if err != nil || !strings.Contains(string(merged), "# operator rule\n") || !strings.Contains(string(merged), overrides) {
		t.Fatalf("override include not preserved: %s %v", merged, err)
	}
	if err = modsec.RestoreOverrides(overrides, []byte("# restored overrides\n")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(overrides)
	if err != nil || string(data) != "# restored overrides\n" {
		t.Fatalf("override transaction: %s %v", data, err)
	}
	unprivileged := exec.Command("runuser", "-u", "nobody", "--", os.Getenv("CSM_TEST_BINARY"), "forward-guard-worker")
	unprivileged.Stdin = strings.NewReader(`{"operation":"remove"}`)
	rejected, rejection := unprivileged.CombinedOutput()
	if rejection == nil || !strings.Contains(string(rejected), "requires root") {
		t.Fatalf("worker accepted unprivileged caller: %s %v", rejected, rejection)
	}
	original, err := os.ReadFile("/etc/exim.conf.local")
	if err != nil {
		t.Fatal(err)
	}
	mutate := func(body string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
			cmd := exec.CommandContext(ctx, name, args...)
			cmd.Stdin = strings.NewReader(body)
			return cmd.CombinedOutput()
		}
		out, runErr := systemdrun.Run(ctx, exec.LookPath, run, systemdrun.Options{Pipe: true, RuntimeMax: 30 * time.Second}, os.Getenv("CSM_TEST_BINARY"), "forward-guard-worker")
		if runErr != nil {
			return fmt.Errorf("%w: %s", runErr, out)
		}
		return nil
	}
	apply := `{"operation":"apply","config":{"Enabled":true,"HoldSignals":{"BounceBackscatter":true}},"bad_ips":["192.0.2.10"]}`
	if err = mutate(apply); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile("/etc/exim.conf.local")
	if err != nil || !strings.Contains(string(data), "csm_forward_guard:") {
		t.Fatalf("helper did not install router: %s %v", data, err)
	}
	if err = mutate(`{"operation":"remove"}`); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile("/etc/exim.conf.local")
	if err != nil || string(data) != string(original) {
		t.Fatalf("helper did not preserve operator config: %s %v", data, err)
	}
	if err = os.WriteFile("/var/lib/csm/fail-next-rebuild", nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err = mutate(apply); err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("helper did not report failed rebuild: %v", err)
	}
	data, err = os.ReadFile("/etc/exim.conf.local")
	if err != nil || string(data) != string(original) {
		t.Fatalf("helper rollback lost operator config: %s %v", data, err)
	}
	calls, err := os.ReadFile("/etc/csm-audit-rebuilds")
	if err != nil || string(calls) != strings.Repeat("rebuild\n", 4) {
		t.Fatalf("rebuilds=%s error=%v", calls, err)
	}
}
