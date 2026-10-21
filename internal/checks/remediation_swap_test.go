package checks

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests play the account owner. Remediation runs as root inside a
// directory the owner controls, so anything it reaches by path after its
// checks can be swapped for a symlink to a file the owner must never get.

const swapVictimBody = "operator only\n"

func writeSwapVictim(t *testing.T) string {
	t.Helper()
	victim := filepath.Join(realTempDir(t), "victim.conf")
	if err := os.WriteFile(victim, []byte(swapVictimBody), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(victim, 0o600); err != nil {
		t.Fatal(err)
	}
	return victim
}

func assertSwapVictimUntouched(t *testing.T, victim string) {
	t.Helper()
	info, err := os.Lstat(victim)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("victim mode changed through the swapped path: %o", info.Mode().Perm())
	}
	data, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != swapVictimBody {
		t.Errorf("victim content changed through the swapped path: %q", data)
	}
}

// replaceWithSymlink runs inside the code under test, so it reports with
// Errorf instead of stopping the goroutine mid-remediation.
func replaceWithSymlink(t *testing.T, path, target string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Errorf("remove %s: %v", path, err)
		return
	}
	if err := os.Symlink(target, path); err != nil {
		t.Errorf("symlink %s: %v", path, err)
	}
}

func withFixAfterPathResolved(t *testing.T, fn func(string)) {
	t.Helper()
	prev := fixAfterPathResolved
	fixAfterPathResolved = fn
	t.Cleanup(func() { fixAfterPathResolved = prev })
}

func withCleanAfterTempCreated(t *testing.T, fn func(string)) {
	t.Helper()
	prev := cleanAfterTempCreated
	cleanAfterTempCreated = fn
	t.Cleanup(func() { cleanAfterTempCreated = prev })
}

func TestFixDisplayErrorsOnDoesNotFollowSwappedStagingFile(t *testing.T) {
	root := realTempDir(t)
	path := filepath.Join(root, ".user.ini")
	const original = "display_errors = On\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	// The owner picks the mode the fix copies onto its replacement.
	if err := os.Chmod(path, 0o606); err != nil {
		t.Fatal(err)
	}
	victim := writeSwapVictim(t)
	withCleanAfterTempCreated(t, func(staged string) { replaceWithSymlink(t, staged, victim) })

	res := FixDisplayErrorsOnInRoots(path, []string{root})

	assertSwapVictimUntouched(t, victim)
	if res.Success {
		t.Fatalf("fix reported success after its staged file was replaced: %+v", res)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != original {
		t.Errorf("original changed after a refused fix: %q", data)
	}
}

func TestFixDisableWPCronDoesNotFollowSwappedStagingFile(t *testing.T) {
	cfgPath, _ := wpCronTestEnv(t, sampleWPConfig)
	if err := os.Chmod(cfgPath, 0o606); err != nil {
		t.Fatal(err)
	}
	withMockCmd(t, (&crontabRecorder{}).mock())
	victim := writeSwapVictim(t)
	withCleanAfterTempCreated(t, func(staged string) { replaceWithSymlink(t, staged, victim) })

	res := FixDisableWPCron(cfgPath, WPCronFixOptions{IntervalMinutes: 5, PHPBin: "/usr/local/bin/php"})

	assertSwapVictimUntouched(t, victim)
	if res.Success {
		t.Fatalf("fix reported success after its staged file was replaced: %+v", res)
	}
}

func TestFixPermissionsDoesNotFollowSwappedFile(t *testing.T) {
	withSimulatedProcessSignal(t)
	root := realTempDir(t)
	withFixPermissionsAllowedRoots(t, root)
	path := filepath.Join(root, "loose.php")
	if err := os.WriteFile(path, []byte("<?php"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	victim := writeSwapVictim(t)
	withFixAfterPathResolved(t, func(resolved string) {
		if resolved == path {
			replaceWithSymlink(t, resolved, victim)
		}
	})

	res := ApplyFix(context.Background(), "world_writable_php", "", "", path)

	assertSwapVictimUntouched(t, victim)
	if res.Success || !res.Refused {
		t.Fatalf("swapped file was not refused: %+v", res)
	}
}

func TestOpenCleanTargetRefusesSymlinkedAncestor(t *testing.T) {
	root := realTempDir(t)
	site := filepath.Join(root, "real", "site")
	if err := os.MkdirAll(site, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(site, "index.php"), []byte("<?php"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "real"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}

	target, err := openCleanTarget(filepath.Join(root, "link", "site", "index.php"))
	if err == nil {
		target.Close()
		t.Fatal("opened a file through a symlinked ancestor directory")
	}
}

// The manual clean has no detection-time identity to compare, so only the
// directory walk keeps a swapped ancestor from steering it into another tree.
func TestCleanHtaccessFileDoesNotFollowSwappedAncestor(t *testing.T) {
	dir := setupHtaccessCleanRoots(t)
	const body = "# legit comment\nErrorDocument 404 https://phish.example.tk/oops.html\n"
	path := writeHtaccess(t, dir, filepath.Join("a", "site"), body)
	other := realTempDir(t)
	victim := writeHtaccess(t, other, filepath.Join("a", "site"), body)
	withFixAfterPathResolved(t, func(resolved string) {
		if resolved != path {
			return
		}
		if err := os.Rename(filepath.Join(dir, "a"), filepath.Join(dir, "a.orig")); err != nil {
			t.Errorf("rename: %v", err)
			return
		}
		if err := os.Symlink(filepath.Join(other, "a"), filepath.Join(dir, "a")); err != nil {
			t.Errorf("symlink: %v", err)
		}
	})

	res := CleanHtaccessFile(path)

	data, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != body {
		t.Fatalf("another tree's .htaccess was cleaned through a swapped ancestor:\n%s", data)
	}
	if res.Success {
		t.Fatalf("clean reported success through a swapped ancestor: %+v", res)
	}
}

// Path-based metadata calls follow symlinks in every component, and this
// package runs them as root on paths account owners control. Descriptor
// methods (f.Chmod, f.Chown) act on the file that was checked.
func TestChecksNeverChangeFileMetadataByPath(t *testing.T) {
	banned := map[string]map[string]bool{
		"os":      {"Chmod": true, "Chown": true, "Lchown": true, "Chtimes": true, "Truncate": true},
		"syscall": {"Chmod": true, "Chown": true, "Lchown": true, "Truncate": true, "Utimes": true, "UtimesNano": true},
		"unix":    {"Chmod": true, "Chown": true, "Lchown": true, "Fchmodat": true, "Fchownat": true, "Truncate": true, "Utimes": true, "UtimesNano": true, "Utimensat": true},
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var offenders []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); ok && banned[pkg.Name][sel.Sel.Name] {
				offenders = append(offenders, fset.Position(sel.Pos()).String()+": "+pkg.Name+"."+sel.Sel.Name)
			}
			return true
		})
	}
	if len(offenders) > 0 {
		t.Fatalf("path-based metadata calls in internal/checks:\n%s", strings.Join(offenders, "\n"))
	}
}

// A finding names a file the scanner saw in one account. If the owner then
// turns a directory on that path into a symlink to another account's tree,
// cleaning must refuse instead of editing the other account's file.
func TestCleanInfectedFileRefusesPlantedAncestorSymlink(t *testing.T) {
	withQuarantineDirCF(t, t.TempDir())
	root := realTempDir(t)
	other := realTempDir(t)
	const infected = "<?php\n@include('/tmp/evil.php');\necho 'safe';\n"
	victim := filepath.Join(other, "a", "site", "index.php")
	if err := os.MkdirAll(filepath.Dir(victim), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(victim, []byte(infected), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(other, "a"), filepath.Join(root, "a")); err != nil {
		t.Fatal(err)
	}

	res := CleanInfectedFile(filepath.Join(root, "a", "site", "index.php"))

	if got, err := os.ReadFile(victim); err != nil || string(got) != infected {
		t.Fatalf("another tree's file was cleaned through a planted ancestor: %q, %v", got, err)
	}
	if res.Cleaned {
		t.Fatalf("clean reported success through a planted ancestor: %+v", res)
	}
}
