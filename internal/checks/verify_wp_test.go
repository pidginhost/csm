package checks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/store"
)

func withWPVerifyAllowedRoots(t *testing.T, dir string) {
	t.Helper()
	old := wpVerifyAllowedRoots
	wpVerifyAllowedRoots = []string{dir}
	t.Cleanup(func() { wpVerifyAllowedRoots = old })
}

// wpPluginListMock returns a mockCmd that answers `wp plugin list` with the
// given JSON and errors every other command.
func wpPluginListMock(t *testing.T, pluginJSON string) {
	t.Helper()
	old := cmdExec
	SetCmdRunner(&mockCmd{
		runContextStdout: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			for _, a := range args {
				if strings.Contains(a, "plugin list") {
					return []byte(pluginJSON), nil
				}
			}
			return nil, os.ErrNotExist // siteurl lookup -> domain falls back
		},
	})
	t.Cleanup(func() { SetCmdRunner(old) })
}

func makeWPInstall(t *testing.T, root, site string) string {
	t.Helper()
	if filepath.Base(root) != "home" {
		root = filepath.Join(root, "home")
	}
	dir := filepath.Join(root, site, "public_html")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "wp-config.php"), []byte("<?php"), 0644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestVerifyOutdatedPluginsResolvedWhenCurrent(t *testing.T) {
	tmp := t.TempDir()
	withWPVerifyAllowedRoots(t, tmp)
	dir := makeWPInstall(t, tmp, "alice")
	// All active, none with an available update.
	wpPluginListMock(t, `[{"name":"akismet","status":"active","version":"5.3","update_version":""}]`)

	details := "Path: " + dir + "\nOutdated plugins (1):\n- akismet"
	res := VerifyFinding("outdated_plugins", "1 outdated plugin on alice.tld (alice): worst severity high", details)
	if !res.Checked || !res.Resolved {
		t.Fatalf("current plugins should verify resolved, got %+v", res)
	}
}

func TestVerifyOutdatedPluginsUnresolvedWhenStillOutdated(t *testing.T) {
	tmp := t.TempDir()
	withWPVerifyAllowedRoots(t, tmp)
	dir := makeWPInstall(t, tmp, "bob")
	wpPluginListMock(t, `[{"name":"woocommerce","status":"active","version":"8.0.0","update_version":"8.5.0"}]`)

	details := "Path: " + dir + "\nOutdated plugins (1):\n- woocommerce"
	res := VerifyFinding("outdated_plugins", "1 outdated plugin on bob.tld (bob): worst severity high", details)
	if !res.Checked || res.Resolved {
		t.Fatalf("still-outdated plugin should verify unresolved, got %+v", res)
	}
	if !strings.Contains(res.Detail, "still outdated") {
		t.Errorf("detail should mention still outdated, got %q", res.Detail)
	}
}

func TestVerifyOutdatedPluginsScanErrorNotResolved(t *testing.T) {
	tmp := t.TempDir()
	withWPVerifyAllowedRoots(t, tmp)
	dir := makeWPInstall(t, tmp, "carol")
	old := cmdExec
	SetCmdRunner(&mockCmd{
		runContextStdout: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
			return nil, os.ErrPermission
		},
	})
	t.Cleanup(func() { SetCmdRunner(old) })

	details := "Path: " + dir
	res := VerifyFinding("outdated_plugins", "1 outdated plugin on carol.tld (carol)", details)
	if res.Checked || res.Resolved {
		t.Fatalf("wp-cli failure must not verify resolved, got %+v", res)
	}
}

func TestVerifyOutdatedPluginsTimeoutNotResolved(t *testing.T) {
	tmp := t.TempDir()
	withWPVerifyAllowedRoots(t, tmp)
	dir := makeWPInstall(t, tmp, "carol")
	old := cmdExec
	SetCmdRunner(&mockCmd{
		runContextStdout: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
			return nil, context.DeadlineExceeded
		},
	})
	t.Cleanup(func() { SetCmdRunner(old) })

	res := VerifyFinding("outdated_plugins", "1 outdated plugin on carol.tld (carol)", "Path: "+dir)
	if res.Checked || res.Resolved {
		t.Fatalf("wp-cli timeout must not verify resolved, got %+v", res)
	}
}

func TestVerifyOutdatedPluginsMalformedJSONNotResolved(t *testing.T) {
	tmp := t.TempDir()
	withWPVerifyAllowedRoots(t, tmp)
	dir := makeWPInstall(t, tmp, "carol")
	wpPluginListMock(t, `not json`)

	res := VerifyFinding("outdated_plugins", "1 outdated plugin on carol.tld (carol)", "Path: "+dir)
	if res.Checked || res.Resolved {
		t.Fatalf("malformed wp-cli output must not verify resolved, got %+v", res)
	}
}

func TestVerifyOutdatedPluginsNilStoreUsesWPCLIUpdateVersion(t *testing.T) {
	tmp := t.TempDir()
	withWPVerifyAllowedRoots(t, tmp)
	dir := makeWPInstall(t, tmp, "dave")
	old := store.Global()
	store.SetGlobal(nil)
	t.Cleanup(func() { store.SetGlobal(old) })
	wpPluginListMock(t, `[{"name":"woocommerce","status":"active","version":"8.0.0","update_version":"8.5.0"}]`)

	res := VerifyFinding("outdated_plugins", "1 outdated plugin on dave.tld (dave)", "Path: "+dir)
	if !res.Checked || res.Resolved {
		t.Fatalf("wp-cli update_version should keep finding unresolved without a store, got %+v", res)
	}
}

func TestVerifyOutdatedPluginsCancelsBoundedWPCLIContext(t *testing.T) {
	tmp := t.TempDir()
	withWPVerifyAllowedRoots(t, tmp)
	dir := makeWPInstall(t, tmp, "erin")
	old := cmdExec
	var pluginCtx context.Context
	SetCmdRunner(&mockCmd{
		runContextStdout: func(ctx context.Context, _ string, args ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			if strings.Contains(joined, "option get siteurl") {
				t.Fatal("outdated-plugin verification should not run wp-cli siteurl lookup")
				return nil, errors.New("unexpected siteurl lookup")
			}
			if !strings.Contains(joined, "plugin list") {
				return nil, errors.New("unexpected command")
			}
			if _, ok := ctx.Deadline(); !ok {
				t.Error("wp-cli re-check context should have a deadline")
			}
			pluginCtx = ctx
			return []byte(`[{"name":"akismet","status":"active","version":"5.3","update_version":""}]`), nil
		},
	})
	t.Cleanup(func() { SetCmdRunner(old) })

	res := VerifyFinding("outdated_plugins", "1 outdated plugin on erin.tld (erin)", "Path: "+dir)
	if !res.Checked || !res.Resolved {
		t.Fatalf("current plugins should verify resolved, got %+v", res)
	}
	if pluginCtx == nil {
		t.Fatal("wp-cli plugin list command was not called")
	}
	select {
	case <-pluginCtx.Done():
	default:
		t.Fatal("wp-cli re-check context was not cancelled after verification returned")
	}
}

func TestVerifyOutdatedPluginsRejectsSymlinkAncestorBeforeCommand(t *testing.T) {
	tmp := t.TempDir()
	withWPVerifyAllowedRoots(t, tmp)
	realDir := makeWPInstall(t, tmp, "frank")
	linkDir := filepath.Join(tmp, "link")
	if err := os.Symlink(filepath.Dir(realDir), linkDir); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	old := cmdExec
	calls := 0
	SetCmdRunner(&mockCmd{
		runContextStdout: func(context.Context, string, ...string) ([]byte, error) {
			calls++
			return []byte(`[]`), nil
		},
	})
	t.Cleanup(func() { SetCmdRunner(old) })

	res := VerifyFinding("outdated_plugins", "msg", "Path: "+filepath.Join(linkDir, "public_html"))
	if res.Checked || res.Resolved {
		t.Fatalf("symlink ancestor should not be auto-verifiable, got %+v", res)
	}
	if calls != 0 {
		t.Fatalf("wp-cli should not run before path validation succeeds, got %d calls", calls)
	}
}

func TestVerifyOutdatedPluginsRejectsInjectedAccountBeforeCommand(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	withWPVerifyAllowedRoots(t, home)
	dir := makeWPInstall(t, home, "-c")
	old := cmdExec
	calls := 0
	SetCmdRunner(&mockCmd{
		runContextStdout: func(context.Context, string, ...string) ([]byte, error) {
			calls++
			return []byte(`[]`), nil
		},
	})
	t.Cleanup(func() { SetCmdRunner(old) })

	res := VerifyFinding("outdated_plugins", "msg", "Path: "+dir)
	if res.Checked || res.Resolved {
		t.Fatalf("account name that can be parsed as a su option should be rejected, got %+v", res)
	}
	if calls != 0 {
		t.Fatalf("wp-cli should not run with an injected account name, got %d calls", calls)
	}
}

func TestVerifyOutdatedPluginsMissingInstallResolved(t *testing.T) {
	tmp := t.TempDir()
	withWPVerifyAllowedRoots(t, tmp)
	res := VerifyFinding("outdated_plugins", "msg", "Path: "+filepath.Join(tmp, "gone", "public_html"))
	if !res.Checked || !res.Resolved {
		t.Fatalf("missing install should verify resolved, got %+v", res)
	}
}

func TestVerifyOutdatedPluginsNoPathNotVerifiable(t *testing.T) {
	res := VerifyFinding("outdated_plugins", "1 outdated plugin", "no path recorded")
	if res.Checked {
		t.Errorf("finding without a Path should not be auto-verifiable, got %+v", res)
	}
}

// wpCoreVerifyMock installs a mockCmd whose RunContext (combined output)
// answers `wp core verify-checksums` with the given output/err.
func wpCoreVerifyMock(t *testing.T, out []byte, err error) {
	t.Helper()
	old := cmdExec
	SetCmdRunner(&mockCmd{
		runContext: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name != "wp" {
				t.Fatalf("unexpected command name: %s", name)
			}
			joined := strings.Join(args, " ")
			if !strings.Contains(joined, "verify-checksums") {
				t.Fatalf("unexpected command args: %s", joined)
			}
			return out, err
		},
	})
	t.Cleanup(func() { SetCmdRunner(old) })
}

func TestVerifyWPCoreCleanResolved(t *testing.T) {
	tmp := t.TempDir()
	withWPVerifyAllowedRoots(t, tmp)
	dir := makeWPInstall(t, tmp, "alice")
	wpCoreVerifyMock(t, []byte("Success: WordPress verifies against checksums."), nil)

	res := VerifyFinding("wp_core_integrity", "WordPress core integrity failure for alice", "Path: "+dir)
	if !res.Checked || !res.Resolved {
		t.Fatalf("clean core should verify resolved, got %+v", res)
	}
}

func TestVerifyWPCoreStillHasExtraFileUnresolved(t *testing.T) {
	tmp := t.TempDir()
	withWPVerifyAllowedRoots(t, tmp)
	dir := makeWPInstall(t, tmp, "bob")
	wpCoreVerifyMock(t, []byte("Warning: File should not exist: wp-admin/evil.php\n"), errors.New("exit status 1"))

	res := VerifyFinding("wp_core_integrity", "WordPress core integrity failure for bob", "Path: "+dir)
	if !res.Checked || res.Resolved {
		t.Fatalf("remaining extraneous core file should verify unresolved, got %+v", res)
	}
}

func TestVerifyWPCoreOtherChecksumIssueNotConfirmed(t *testing.T) {
	tmp := t.TempDir()
	withWPVerifyAllowedRoots(t, tmp)
	dir := makeWPInstall(t, tmp, "carol")
	// Non-zero exit, but no "should not exist" line (e.g. a modified file). The
	// finding's specific condition (extra files) can't be confirmed gone, and
	// the output might be a wp-cli error, so we must NOT resolve.
	wpCoreVerifyMock(t, []byte("Warning: wp-includes/x.php doesn't verify against checksum.\n"), errors.New("exit status 1"))

	res := VerifyFinding("wp_core_integrity", "WordPress core integrity failure for carol", "Path: "+dir)
	if res.Resolved {
		t.Fatalf("ambiguous verify output must not resolve, got %+v", res)
	}
	if res.Checked {
		t.Errorf("ambiguous verify output should be reported as not auto-confirmable, got %+v", res)
	}
}

func TestVerifyWPCoreFatalErrorOutputNotResolved(t *testing.T) {
	tmp := t.TempDir()
	withWPVerifyAllowedRoots(t, tmp)
	dir := makeWPInstall(t, tmp, "dave")
	wpCoreVerifyMock(t, []byte("Error: This does not seem to be a WordPress installation.\n"), errors.New("exit status 1"))

	res := VerifyFinding("wp_core_integrity", "WordPress core integrity failure for dave", "Path: "+dir)
	if res.Checked || res.Resolved {
		t.Fatalf("wp-cli fatal error must not verify resolved, got %+v", res)
	}
}

func TestVerifyWPCoreErrorLogExtraLineNotConfirmed(t *testing.T) {
	tmp := t.TempDir()
	withWPVerifyAllowedRoots(t, tmp)
	dir := makeWPInstall(t, tmp, "dave")
	wpCoreVerifyMock(t, []byte("Warning: File should not exist: wp-content/error_log\n"), errors.New("exit status 1"))

	res := VerifyFinding("wp_core_integrity", "WordPress core integrity failure for dave", "Path: "+dir)
	if res.Checked || res.Resolved {
		t.Fatalf("error_log-only checksum output must not resolve, got %+v", res)
	}
}

func TestVerifyWPCoreExecErrorNoOutputNotResolved(t *testing.T) {
	tmp := t.TempDir()
	withWPVerifyAllowedRoots(t, tmp)
	dir := makeWPInstall(t, tmp, "erin")
	wpCoreVerifyMock(t, nil, errors.New("wp: command not found"))

	res := VerifyFinding("wp_core_integrity", "WordPress core integrity failure for erin", "Path: "+dir)
	if res.Checked || res.Resolved {
		t.Fatalf("wp-cli exec failure must not verify resolved, got %+v", res)
	}
}

func TestVerifyWPCoreCommandUsesSanitizedPathAndBoundedContext(t *testing.T) {
	tmp := t.TempDir()
	withWPVerifyAllowedRoots(t, tmp)
	dir := makeWPInstall(t, tmp, "frank")
	rawPath := filepath.Dir(dir) + string(os.PathSeparator) + ".." + string(os.PathSeparator) + "frank" + string(os.PathSeparator) + "public_html"
	if rawPath == dir {
		t.Fatal("test raw path should differ from cleaned path")
	}

	old := cmdExec
	var cmdCtx context.Context
	SetCmdRunner(&mockCmd{
		runContext: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			cmdCtx = ctx
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("wp-cli core re-check context should have a deadline")
			}
			if name != "wp" {
				t.Fatalf("command name = %q, want wp", name)
			}
			wantArgs := []string{"core", "verify-checksums", "--path=" + dir, "--allow-root"}
			if len(args) != len(wantArgs) {
				t.Fatalf("args = %#v, want %#v", args, wantArgs)
			}
			for i, want := range wantArgs {
				if args[i] != want {
					t.Fatalf("arg %d = %q, want %q in %#v", i, args[i], want, args)
				}
			}
			for _, arg := range args {
				if arg == rawPath || strings.Contains(arg, rawPath) {
					t.Fatalf("command used raw finding path %q in args %#v", rawPath, args)
				}
			}
			return []byte("Success: WordPress verifies against checksums."), nil
		},
	})
	t.Cleanup(func() { SetCmdRunner(old) })

	res := VerifyFinding("wp_core_integrity", "WordPress core integrity failure for frank", "Path: "+rawPath)
	if !res.Checked || !res.Resolved {
		t.Fatalf("clean core should verify resolved, got %+v", res)
	}
	if cmdCtx == nil {
		t.Fatal("wp-cli core verify command was not called")
	}
	select {
	case <-cmdCtx.Done():
	default:
		t.Fatal("wp-cli core re-check context was not cancelled after verification returned")
	}
}

func TestVerifyWPCoreRejectsSymlinkAncestorBeforeCommand(t *testing.T) {
	tmp := t.TempDir()
	withWPVerifyAllowedRoots(t, tmp)
	realDir := makeWPInstall(t, tmp, "grace")
	linkDir := filepath.Join(tmp, "link")
	if err := os.Symlink(filepath.Dir(realDir), linkDir); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	old := cmdExec
	calls := 0
	SetCmdRunner(&mockCmd{
		runContext: func(context.Context, string, ...string) ([]byte, error) {
			calls++
			return []byte("Success: WordPress verifies against checksums."), nil
		},
	})
	t.Cleanup(func() { SetCmdRunner(old) })

	res := VerifyFinding("wp_core_integrity", "msg", "Path: "+filepath.Join(linkDir, "public_html"))
	if res.Checked || res.Resolved {
		t.Fatalf("symlink ancestor should not be auto-verifiable, got %+v", res)
	}
	if calls != 0 {
		t.Fatalf("wp-cli should not run before path validation succeeds, got %d calls", calls)
	}
}

func TestVerifyWPCoreMissingInstallResolved(t *testing.T) {
	tmp := t.TempDir()
	withWPVerifyAllowedRoots(t, tmp)
	res := VerifyFinding("wp_core_integrity", "msg", "Path: "+filepath.Join(tmp, "home", "gone", "public_html"))
	if !res.Checked || !res.Resolved {
		t.Fatalf("missing install should verify resolved, got %+v", res)
	}
}

func TestVerifyWPCoreNoPathNotVerifiable(t *testing.T) {
	res := VerifyFinding("wp_core_integrity", "WordPress core integrity failure", "no path")
	if res.Checked {
		t.Errorf("finding without a Path should not be auto-verifiable, got %+v", res)
	}
}

func TestInventoryWPSitePassesUserAfterSuOptionBoundary(t *testing.T) {
	tmp := t.TempDir()
	wpConfig := filepath.Join(tmp, "home", "alice", "public_html", "wp-config.php")
	if err := os.MkdirAll(filepath.Dir(wpConfig), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wpConfig, []byte("<?php"), 0644); err != nil {
		t.Fatal(err)
	}

	old := cmdExec
	var pluginArgs []string
	SetCmdRunner(&mockCmd{
		runContextStdout: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			if strings.Contains(joined, "option get siteurl") {
				return nil, os.ErrNotExist
			}
			if strings.Contains(joined, "plugin list") {
				pluginArgs = append([]string(nil), args...)
				return []byte(`[]`), nil
			}
			return nil, errors.New("unexpected command")
		},
	})
	t.Cleanup(func() { SetCmdRunner(old) })

	if _, err := inventoryWPSite(context.Background(), wpConfig); err != nil {
		t.Fatalf("inventoryWPSite: %v", err)
	}
	if len(pluginArgs) == 0 {
		t.Fatal("wp-cli plugin list command was not called")
	}
	wantPrefix := []string{"-l", "-s", "/bin/bash", "-c"}
	if len(pluginArgs) != 7 {
		t.Fatalf("su args length = %d, want 7: %#v", len(pluginArgs), pluginArgs)
	}
	for i, want := range wantPrefix {
		if pluginArgs[i] != want {
			t.Fatalf("su arg %d = %q, want %q in args %#v", i, pluginArgs[i], want, pluginArgs)
		}
	}
	if !strings.Contains(pluginArgs[4], "plugin list") {
		t.Fatalf("su command arg should run plugin list, got args %#v", pluginArgs)
	}
	if pluginArgs[5] != "--" || pluginArgs[6] != "alice" {
		t.Fatalf("su option boundary should be followed by user alice, got args %#v", pluginArgs)
	}
}

func TestInventoryWPSiteShellQuotesWPPath(t *testing.T) {
	tmp := t.TempDir()
	wpPath := filepath.Join(tmp, "home", "alice", "public'html")
	wpConfig := filepath.Join(wpPath, "wp-config.php")
	if err := os.MkdirAll(wpPath, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wpConfig, []byte("<?php"), 0644); err != nil {
		t.Fatal(err)
	}

	old := cmdExec
	var pluginCommand string
	SetCmdRunner(&mockCmd{
		runContextStdout: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			if strings.Contains(joined, "option get siteurl") {
				return nil, os.ErrNotExist
			}
			if strings.Contains(joined, "plugin list") {
				if len(args) < 5 {
					t.Fatalf("su args too short: %#v", args)
				}
				pluginCommand = args[4]
				return []byte(`[]`), nil
			}
			return nil, errors.New("unexpected command")
		},
	})
	t.Cleanup(func() { SetCmdRunner(old) })

	if _, err := inventoryWPSite(context.Background(), wpConfig); err != nil {
		t.Fatalf("inventoryWPSite: %v", err)
	}
	wantPathArg := "--path=" + shellQuote(wpPath)
	if !strings.Contains(pluginCommand, wantPathArg) {
		t.Fatalf("wp path should be shell-quoted in command %q; want %q", pluginCommand, wantPathArg)
	}
	if strings.Contains(pluginCommand, "--path="+wpPath) {
		t.Fatalf("wp path was passed unquoted in command %q", pluginCommand)
	}
}

func TestValidWPCLIUserRejectsShellSyntax(t *testing.T) {
	for _, user := range []string{"", "unknown", "-c", "alice root", "alice;id", "alice/root"} {
		if validWPCLIUser(user) {
			t.Errorf("validWPCLIUser(%q) = true, want false", user)
		}
	}
	for _, user := range []string{"alice", "alice_1", "site-owner", "customer.example"} {
		if !validWPCLIUser(user) {
			t.Errorf("validWPCLIUser(%q) = false, want true", user)
		}
	}
}
