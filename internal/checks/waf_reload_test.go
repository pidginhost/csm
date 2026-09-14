package checks

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/store"
)

// ModSecurity reads its configuration only when the web server starts or
// reloads. CSM rewrote its rule section on upgrade and never reloaded, so new
// virtual patches stayed inactive until an unrelated restart.

type reloadRecorder struct {
	commands []string
	err      error
}

func withReloadRecorder(t *testing.T, err error) *reloadRecorder {
	t.Helper()
	rec := &reloadRecorder{err: err}
	old := modsecReloadRunner
	modsecReloadRunner = func(command string) (string, error) {
		rec.commands = append(rec.commands, command)
		return "", rec.err
	}
	t.Cleanup(func() { modsecReloadRunner = old })
	return rec
}

func withReconcileStore(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.SetGlobal(db)
	t.Cleanup(func() {
		store.SetGlobal(nil)
		if closeErr := db.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	return db
}

func TestReconcileModSecReloadActivatesNewSectionOnce(t *testing.T) {
	withReconcileStore(t)
	dest := vpTestOperator + vpTestSection(vpTestSrcV2)
	setupVPTestFS(t, vpTestSrcV2, &dest)
	rec := withReloadRecorder(t, nil)

	if err := ReconcileModSecReload("systemctl reload lsws"); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	if err := ReconcileModSecReload("systemctl reload lsws"); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if len(rec.commands) != 1 || rec.commands[0] != "systemctl reload lsws" {
		t.Fatalf("reload commands = %q, want the configured command exactly once", rec.commands)
	}
}

func TestReconcileModSecReloadReloadsWhenSectionChanges(t *testing.T) {
	withReconcileStore(t)
	dest := vpTestSection(vpTestSrcV1)
	fs := setupVPTestFS(t, vpTestSrcV1, &dest)
	rec := withReloadRecorder(t, nil)

	if err := ReconcileModSecReload("apachectl graceful"); err != nil {
		t.Fatal(err)
	}
	fs.files[vpTestDest] = vpTestSection(vpTestSrcV2)
	if err := ReconcileModSecReload("apachectl graceful"); err != nil {
		t.Fatal(err)
	}
	if len(rec.commands) != 2 {
		t.Fatalf("reloads = %d, want one per distinct section", len(rec.commands))
	}
}

// Operator rules outside the section are the operator's to activate.
func TestReconcileModSecReloadIgnoresOperatorBytes(t *testing.T) {
	withReconcileStore(t)
	dest := vpTestSection(vpTestSrcV2)
	fs := setupVPTestFS(t, vpTestSrcV2, &dest)
	rec := withReloadRecorder(t, nil)

	if err := ReconcileModSecReload("apachectl graceful"); err != nil {
		t.Fatal(err)
	}
	fs.files[vpTestDest] = vpTestOperator + vpTestSection(vpTestSrcV2) + vpTestOperator
	if err := ReconcileModSecReload("apachectl graceful"); err != nil {
		t.Fatal(err)
	}
	if len(rec.commands) != 1 {
		t.Fatalf("reloads = %d, operator edits outside the section must not reload", len(rec.commands))
	}
}

func TestReconcileModSecReloadWithoutCommandStaysPending(t *testing.T) {
	withReconcileStore(t)
	dest := vpTestSection(vpTestSrcV2)
	setupVPTestFS(t, vpTestSrcV2, &dest)
	rec := withReloadRecorder(t, nil)

	if err := ReconcileModSecReload(""); !errors.Is(err, ErrModSecReloadNotConfigured) {
		t.Fatalf("err = %v, want ErrModSecReloadNotConfigured", err)
	}
	if len(rec.commands) != 0 {
		t.Fatalf("ran %q without a configured command", rec.commands)
	}
	// Configuring the command later must still activate the pending section.
	if err := ReconcileModSecReload("apachectl graceful"); err != nil {
		t.Fatal(err)
	}
	if len(rec.commands) != 1 {
		t.Fatalf("reloads = %d after configuring the command, want 1", len(rec.commands))
	}
}

func TestReconcileModSecReloadRetriesAfterFailure(t *testing.T) {
	withReconcileStore(t)
	dest := vpTestSection(vpTestSrcV2)
	setupVPTestFS(t, vpTestSrcV2, &dest)
	rec := withReloadRecorder(t, errors.New("exit status 1"))

	err := ReconcileModSecReload("systemctl reload lsws")
	if err == nil || errors.Is(err, ErrModSecReloadNotConfigured) {
		t.Fatalf("err = %v, want the reload failure", err)
	}
	rec.err = nil
	if err := ReconcileModSecReload("systemctl reload lsws"); err != nil {
		t.Fatal(err)
	}
	if len(rec.commands) != 2 {
		t.Fatalf("reloads = %d, a failed reload must be retried", len(rec.commands))
	}
}

func TestReconcileModSecReloadWithoutSectionDoesNothing(t *testing.T) {
	withReconcileStore(t)
	dest := vpTestOperator
	setupVPTestFS(t, vpTestSrcV2, &dest)
	rec := withReloadRecorder(t, nil)

	if err := ReconcileModSecReload("apachectl graceful"); err != nil {
		t.Fatal(err)
	}
	if len(rec.commands) != 0 {
		t.Fatalf("reloaded %q with no CSM section on disk", rec.commands)
	}
}

// Without the state store there is no record of what was activated, so every
// run would reload the web server.
func TestReconcileModSecReloadWithoutStoreDoesNothing(t *testing.T) {
	store.SetGlobal(nil)
	dest := vpTestSection(vpTestSrcV2)
	setupVPTestFS(t, vpTestSrcV2, &dest)
	rec := withReloadRecorder(t, nil)

	if err := ReconcileModSecReload("apachectl graceful"); err != nil {
		t.Fatal(err)
	}
	if len(rec.commands) != 0 {
		t.Fatalf("reloaded %q without a state store", rec.commands)
	}
}

func wafReloadCheckFixture(t *testing.T) {
	t.Helper()
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	platform.SetOverrides(platform.Overrides{
		Panel:           ptrPanel(platform.PanelCPanel),
		WebServer:       ptrWebServer(platform.WSApache),
		ApacheConfigDir: "/usr/local/apache",
	})
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "whmapi1" && len(args) > 0 && args[0] == "modsec_is_installed" {
				return []byte("installed: 1\n"), nil
			}
			return nil, nil
		},
	})
	withReconcileStore(t)
	setupVPTestFS(t, vpTestSrcV2, nil)
}

func TestCheckWAFStatusReportsFailedModSecReload(t *testing.T) {
	wafReloadCheckFixture(t)
	rec := withReloadRecorder(t, errors.New("exit status 1"))
	cfg := &config.Config{}
	cfg.ModSec.ReloadCommand = "systemctl reload lsws"

	findings := CheckWAFStatus(context.Background(), cfg, nil)

	if len(rec.commands) != 1 {
		t.Fatalf("reloads = %d, want the deployed section activated once", len(rec.commands))
	}
	for _, f := range findings {
		if f.Check == "waf_status" && f.Severity == alert.Warning && strings.Contains(f.Message, "reload") {
			return
		}
	}
	t.Fatalf("no waf_status warning for the failed reload, got %+v", findings)
}

func TestCheckWAFStatusObserveModeDoesNotReload(t *testing.T) {
	wafReloadCheckFixture(t)
	rec := withReloadRecorder(t, nil)
	cfg := &config.Config{Mode: config.ModeObserve}
	cfg.ModSec.ReloadCommand = "systemctl reload lsws"

	CheckWAFStatus(context.Background(), cfg, nil)

	if len(rec.commands) != 0 {
		t.Fatalf("observe mode reloaded the web server: %q", rec.commands)
	}
}
