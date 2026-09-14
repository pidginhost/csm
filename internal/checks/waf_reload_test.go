package checks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	reconciler := &ModSecReloadReconciler{}
	withReconcileStore(t)
	dest := vpTestOperator + vpTestSection(vpTestSrcV2)
	setupVPTestFS(t, vpTestSrcV2, &dest)
	rec := withReloadRecorder(t, nil)

	if err := reconciler.Reconcile("systemctl reload lsws"); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	if err := reconciler.Reconcile("systemctl reload lsws"); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if len(rec.commands) != 1 || rec.commands[0] != "systemctl reload lsws" {
		t.Fatalf("reload commands = %q, want the configured command exactly once", rec.commands)
	}
}

func TestReconcileModSecReloadReloadsWhenSectionChanges(t *testing.T) {
	reconciler := &ModSecReloadReconciler{}
	withReconcileStore(t)
	dest := vpTestSection(vpTestSrcV1)
	fs := setupVPTestFS(t, vpTestSrcV1, &dest)
	rec := withReloadRecorder(t, nil)

	if err := reconciler.Reconcile("apachectl graceful"); err != nil {
		t.Fatal(err)
	}
	fs.files[vpTestDest] = vpTestSection(vpTestSrcV2)
	if err := reconciler.Reconcile("apachectl graceful"); err != nil {
		t.Fatal(err)
	}
	if len(rec.commands) != 2 {
		t.Fatalf("reloads = %d, want one per distinct section", len(rec.commands))
	}
}

// Operator rules outside the section are the operator's to activate.
func TestReconcileModSecReloadIgnoresOperatorBytes(t *testing.T) {
	reconciler := &ModSecReloadReconciler{}
	withReconcileStore(t)
	dest := vpTestSection(vpTestSrcV2)
	fs := setupVPTestFS(t, vpTestSrcV2, &dest)
	rec := withReloadRecorder(t, nil)

	if err := reconciler.Reconcile("apachectl graceful"); err != nil {
		t.Fatal(err)
	}
	fs.files[vpTestDest] = vpTestOperator + vpTestSection(vpTestSrcV2) + vpTestOperator
	if err := reconciler.Reconcile("apachectl graceful"); err != nil {
		t.Fatal(err)
	}
	if len(rec.commands) != 1 {
		t.Fatalf("reloads = %d, operator edits outside the section must not reload", len(rec.commands))
	}
}

func TestReconcileModSecReloadWithoutCommandStaysPending(t *testing.T) {
	reconciler := &ModSecReloadReconciler{}
	withReconcileStore(t)
	dest := vpTestSection(vpTestSrcV2)
	setupVPTestFS(t, vpTestSrcV2, &dest)
	rec := withReloadRecorder(t, nil)

	if err := reconciler.Reconcile(""); !errors.Is(err, ErrModSecReloadNotConfigured) {
		t.Fatalf("err = %v, want ErrModSecReloadNotConfigured", err)
	}
	if len(rec.commands) != 0 {
		t.Fatalf("ran %q without a configured command", rec.commands)
	}
	// Configuring the command later must still activate the pending section.
	if err := reconciler.Reconcile("apachectl graceful"); err != nil {
		t.Fatal(err)
	}
	if len(rec.commands) != 1 {
		t.Fatalf("reloads = %d after configuring the command, want 1", len(rec.commands))
	}
}

func TestReconcileModSecReloadRetriesAfterFailure(t *testing.T) {
	reconciler := &ModSecReloadReconciler{}
	withReconcileStore(t)
	dest := vpTestSection(vpTestSrcV2)
	setupVPTestFS(t, vpTestSrcV2, &dest)
	rec := withReloadRecorder(t, errors.New("exit status 1"))

	err := reconciler.Reconcile("systemctl reload lsws")
	if err == nil || errors.Is(err, ErrModSecReloadNotConfigured) {
		t.Fatalf("err = %v, want the reload failure", err)
	}
	rec.err = nil
	if err := reconciler.Reconcile("systemctl reload lsws"); err != nil {
		t.Fatal(err)
	}
	if len(rec.commands) != 2 {
		t.Fatalf("reloads = %d, a failed reload must be retried", len(rec.commands))
	}
}

func TestReconcileModSecReloadWithoutSectionDoesNothing(t *testing.T) {
	reconciler := &ModSecReloadReconciler{}
	withReconcileStore(t)
	dest := vpTestOperator
	setupVPTestFS(t, vpTestSrcV2, &dest)
	rec := withReloadRecorder(t, nil)

	if err := reconciler.Reconcile("apachectl graceful"); err != nil {
		t.Fatal(err)
	}
	if len(rec.commands) != 0 {
		t.Fatalf("reloaded %q with no CSM section on disk", rec.commands)
	}
}

// Without the state store there is no record of what was activated, so every
// run would reload the web server.
func TestReconcileModSecReloadWithoutStoreDoesNothing(t *testing.T) {
	reconciler := &ModSecReloadReconciler{}
	store.SetGlobal(nil)
	dest := vpTestSection(vpTestSrcV2)
	setupVPTestFS(t, vpTestSrcV2, &dest)
	rec := withReloadRecorder(t, nil)

	if err := reconciler.Reconcile("apachectl graceful"); err != nil {
		t.Fatal(err)
	}
	if len(rec.commands) != 0 {
		t.Fatalf("reloaded %q without a state store", rec.commands)
	}
}

func wafReloadCheckFixture(t *testing.T) context.Context {
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
	return WithModSecReload(context.Background(), &ModSecReloadReconciler{})
}

func TestCheckWAFStatusReportsFailedModSecReload(t *testing.T) {
	ctx := wafReloadCheckFixture(t)
	rec := withReloadRecorder(t, errors.New("exit status 1"))
	cfg := &config.Config{}
	cfg.ModSec.ReloadCommand = "systemctl reload lsws"

	findings := CheckWAFStatus(ctx, cfg, nil)

	if len(rec.commands) != 1 {
		t.Fatalf("reloads = %d, want the deployed section activated once", len(rec.commands))
	}
	for _, f := range findings {
		if f.Check == "waf_status" && f.Severity == alert.Warning && strings.Contains(f.Message, "activation") {
			return
		}
	}
	t.Fatalf("no waf_status warning for the failed reload, got %+v", findings)
}

func TestCheckWAFStatusObserveModeDoesNotReload(t *testing.T) {
	ctx := wafReloadCheckFixture(t)
	rec := withReloadRecorder(t, nil)
	cfg := &config.Config{Mode: config.ModeObserve}
	cfg.ModSec.ReloadCommand = "systemctl reload lsws"

	CheckWAFStatus(ctx, cfg, nil)

	if len(rec.commands) != 0 {
		t.Fatalf("observe mode reloaded the web server: %q", rec.commands)
	}
}

func TestCheckWAFStatusCLIWithStoreDoesNotReload(t *testing.T) {
	wafReloadCheckFixture(t)
	rec := withReloadRecorder(t, nil)
	cfg := &config.Config{}
	cfg.ModSec.ReloadCommand = "systemctl reload lsws"
	CheckWAFStatus(context.Background(), cfg, nil)
	if len(rec.commands) != 0 {
		t.Fatalf("CLI check reloaded the web server: %q", rec.commands)
	}
}

func TestReconcileModSecReloadConcurrentCallsReloadOnce(t *testing.T) {
	reconciler := &ModSecReloadReconciler{}
	withReconcileStore(t)
	dest := vpTestSection(vpTestSrcV2)
	setupVPTestFS(t, vpTestSrcV2, &dest)
	var calls atomic.Int32
	old := modsecReloadRunner
	modsecReloadRunner = func(string) (string, error) {
		calls.Add(1)
		time.Sleep(50 * time.Millisecond)
		return "", nil
	}
	t.Cleanup(func() { modsecReloadRunner = old })
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if err := reconciler.Reconcile("systemctl reload lsws"); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if got := calls.Load(); got != 1 {
		t.Fatalf("concurrent reloads = %d, want 1", got)
	}
}

func TestReconcileModSecReloadMetadataFailureDoesNotRepeatReload(t *testing.T) {
	reconciler := &ModSecReloadReconciler{}
	db := withReconcileStore(t)
	dest := vpTestSection(vpTestSrcV2)
	setupVPTestFS(t, vpTestSrcV2, &dest)
	old := modsecReloadRunner
	calls := 0
	modsecReloadRunner = func(string) (string, error) {
		calls++
		// Lose the store after the web server accepted the reload.
		_ = db.Close()
		return "", nil
	}
	t.Cleanup(func() { modsecReloadRunner = old })
	for range 2 {
		if err := reconciler.Reconcile("systemctl reload lsws"); err == nil {
			t.Fatal("lost metadata write was not reported")
		}
	}
	if calls != 1 {
		t.Fatalf("reloads after metadata failure = %d, want 1", calls)
	}
}

func TestReconcileModSecReloadFindsFallbackSection(t *testing.T) {
	reconciler := &ModSecReloadReconciler{}
	for _, readErr := range []error{os.ErrNotExist, os.ErrPermission} {
		t.Run(readErr.Error(), func(t *testing.T) {
			withReconcileStore(t)
			rec := withReloadRecorder(t, nil)
			withMockOS(t, &mockOS{
				stat: func(string) (os.FileInfo, error) { return nil, nil },
				readFile: func(name string) ([]byte, error) {
					if name == vpDestPaths[0] {
						return nil, readErr
					}
					if name == vpDestPaths[1] {
						return []byte(vpTestSection(vpTestSrcV2)), nil
					}
					return nil, os.ErrNotExist
				},
			})
			if err := reconciler.Reconcile("apachectl graceful"); err != nil {
				t.Fatal(err)
			}
			if len(rec.commands) != 1 {
				t.Fatalf("fallback %s was not activated", filepath.Dir(vpDestPaths[1]))
			}
		})
	}
}

func TestReconcileModSecReloadTracksFallbackChanges(t *testing.T) {
	reconciler := &ModSecReloadReconciler{}
	withReconcileStore(t)
	rec := withReloadRecorder(t, nil)
	fallback := vpTestSection(vpTestSrcV1)
	withMockOS(t, &mockOS{
		stat: func(string) (os.FileInfo, error) { return nil, nil },
		readFile: func(name string) ([]byte, error) {
			if name == vpDestPaths[0] {
				return []byte(vpTestSection(vpTestSrcV1)), nil
			}
			return []byte(fallback), nil
		},
	})
	if err := reconciler.Reconcile("apachectl graceful"); err != nil {
		t.Fatal(err)
	}
	fallback = vpTestSection(vpTestSrcV2)
	if err := reconciler.Reconcile("apachectl graceful"); err != nil {
		t.Fatal(err)
	}
	if len(rec.commands) != 2 {
		t.Fatalf("reloads = %d, want fallback update activated", len(rec.commands))
	}
}

func TestReconcileModSecReloadWhitespaceCommandStaysPending(t *testing.T) {
	reconciler := &ModSecReloadReconciler{}
	db := withReconcileStore(t)
	dest := vpTestSection(vpTestSrcV2)
	setupVPTestFS(t, vpTestSrcV2, &dest)
	rec := withReloadRecorder(t, nil)
	if err := reconciler.Reconcile(" \t\n "); !errors.Is(err, ErrModSecReloadNotConfigured) {
		t.Fatalf("whitespace command error = %v", err)
	}
	if len(rec.commands) != 0 || db.GetMetaString(modsecActiveSectionKey) != "" {
		t.Fatal("empty shell command marked rules active")
	}
}

func TestReconcileModSecReloadDoesNotTrustStaleMetadata(t *testing.T) {
	reconciler := &ModSecReloadReconciler{}
	db := withReconcileStore(t)
	dest := vpTestSection(vpTestSrcV1)
	fs := setupVPTestFS(t, vpTestSrcV1, &dest)
	rec := withReloadRecorder(t, nil)
	if err := reconciler.Reconcile("apachectl graceful"); err != nil {
		t.Fatal(err)
	}
	oldDigest := db.GetMetaString(modsecActiveSectionKey)
	fs.files[vpTestDest] = vpTestSection(vpTestSrcV2)
	if err := reconciler.Reconcile("apachectl graceful"); err != nil {
		t.Fatal(err)
	}
	// Reproduce stale durable state after a successful activation. The next
	// reconciliation must use what this daemon actually activated.
	if err := db.SetMetaString(modsecActiveSectionKey, oldDigest); err != nil {
		t.Fatal(err)
	}
	fs.files[vpTestDest] = vpTestSection(vpTestSrcV1)
	if err := reconciler.Reconcile("apachectl graceful"); err != nil {
		t.Fatal(err)
	}
	if len(rec.commands) != 3 {
		t.Fatalf("reloads = %d, reverted rules were not reactivated", len(rec.commands))
	}
}

func TestReconcileModSecReloadStoreReadFailureDoesNotReload(t *testing.T) {
	reconciler := &ModSecReloadReconciler{}
	db := withReconcileStore(t)
	dest := vpTestSection(vpTestSrcV2)
	setupVPTestFS(t, vpTestSrcV2, &dest)
	rec := withReloadRecorder(t, nil)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Reconcile("apachectl graceful"); err == nil {
		t.Fatal("unavailable activation metadata was not reported")
	}
	if len(rec.commands) != 0 {
		t.Fatalf("unreadable activation metadata triggered %q", rec.commands)
	}
}

func TestCheckWAFStatusRepeatedScansDoNotRepeatReload(t *testing.T) {
	for _, command := range []string{"systemctl reload lsws", "", " \t\n"} {
		t.Run(command, func(t *testing.T) {
			ctx := wafReloadCheckFixture(t)
			rec := withReloadRecorder(t, nil)
			cfg := &config.Config{}
			cfg.ModSec.ReloadCommand = command
			for range 3 {
				for _, f := range CheckWAFStatus(ctx, cfg, nil) {
					if strings.Contains(f.Message, "activation") {
						t.Fatalf("unexpected activation finding: %+v", f)
					}
				}
			}
			want := 0
			if strings.TrimSpace(command) != "" {
				want = 1
			}
			if len(rec.commands) != want {
				t.Fatalf("reloads = %d, want %d", len(rec.commands), want)
			}
		})
	}
}

func TestReconcileModSecReloadSurvivesDaemonRestart(t *testing.T) {
	withReconcileStore(t)
	dest := vpTestSection(vpTestSrcV2)
	setupVPTestFS(t, vpTestSrcV2, &dest)
	rec := withReloadRecorder(t, nil)
	for range 2 {
		reconciler := &ModSecReloadReconciler{}
		if err := reconciler.Reconcile("apachectl graceful"); err != nil {
			t.Fatal(err)
		}
	}
	if len(rec.commands) != 1 {
		t.Fatalf("daemon restart reloaded unchanged rules: %q", rec.commands)
	}
}
