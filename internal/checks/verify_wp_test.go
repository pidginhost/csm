package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withWPVerifyAllowedRoots(t *testing.T, dir string) {
	t.Helper()
	old := wpVerifyAllowedRoots
	wpVerifyAllowedRoots = []string{dir}
	t.Cleanup(func() { wpVerifyAllowedRoots = old })
}

// wpPluginListMock returns a mockCmd that answers `wp plugin list` with the
// given JSON and errors everything else (so extractWPDomain falls back).
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
