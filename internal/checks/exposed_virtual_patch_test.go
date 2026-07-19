package checks

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// vpTestEnv redirects the remediation roots, backup dir, and chown to a
// t.TempDir so the virtual-patch writer can run under an unprivileged test.
func vpTestEnv(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	// resolveExistingFixPath EvalSymlinks the target; on macOS /var -> /private/var,
	// so pin the allowed root to the resolved path to match.
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	prevRoots := fixHtaccessAllowedRoots
	prevBackup := htaccessBackupDirRoot
	prevChown := chownFunc
	prevBeforeCommit := virtualPatchBeforeCommitForTest
	fixHtaccessAllowedRoots = []string{root}
	htaccessBackupDirRoot = filepath.Join(root, ".backups")
	chownFunc = func(*os.File, int, int) error { return nil } // unprivileged test
	virtualPatchBeforeCommitForTest = nil
	t.Cleanup(func() {
		fixHtaccessAllowedRoots = prevRoots
		htaccessBackupDirRoot = prevBackup
		chownFunc = prevChown
		virtualPatchBeforeCommitForTest = prevBeforeCommit
	})
	return root
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return string(b)
}

func TestVirtualPatchExposedFile_NewHtaccessFileMode(t *testing.T) {
	root := vpTestEnv(t)
	env := filepath.Join(root, "dom", "pacient", ".env")
	mustWrite(t, env, "SECRET=1\n")

	res := VirtualPatchExposedFile(env)
	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}
	hta := filepath.Join(root, "dom", "pacient", ".htaccess")
	got := readFile(t, hta)
	if !strings.Contains(got, `<Files ".env">`) || !strings.Contains(got, "Require all denied") {
		t.Fatalf("deny block missing:\n%s", got)
	}
	// The exposed file itself must be untouched (deny is HTTP-layer only).
	if readFile(t, env) != "SECRET=1\n" {
		t.Fatal("virtual-patch must not modify the exposed file")
	}

	entries, err := os.ReadDir(htaccessBackupDirRoot)
	if err != nil {
		t.Fatalf("read backup dir: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("new .htaccess must produce a rollback item and metadata, got %d entries", len(entries))
	}
	var metaPath string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".meta") {
			metaPath = filepath.Join(htaccessBackupDirRoot, entry.Name())
		}
	}
	if metaPath == "" {
		t.Fatal("new .htaccess rollback metadata missing")
	}
	var meta QuarantineMeta
	if err := json.Unmarshal([]byte(readFile(t, metaPath)), &meta); err != nil {
		t.Fatalf("decode rollback metadata: %v", err)
	}
	if meta.RestoreAction != QuarantineRestoreRemoveIfUnchanged || meta.ExpectedCurrentSHA256 == "" {
		t.Fatalf("new .htaccess rollback metadata = %+v", meta)
	}
}

func TestVirtualPatchExposedFile_AppendsAndBacksUp(t *testing.T) {
	root := vpTestEnv(t)
	dir := filepath.Join(root, "dom")
	mustWrite(t, filepath.Join(dir, "config.php.old"), "<?php $db='x';\n")
	existing := "# user rules\nOptions -Indexes\n"
	mustWrite(t, filepath.Join(dir, ".htaccess"), existing)

	res := VirtualPatchExposedFile(filepath.Join(dir, "config.php.old"))
	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}
	got := readFile(t, filepath.Join(dir, ".htaccess"))
	if !strings.Contains(got, "Options -Indexes") {
		t.Fatal("existing directives must be preserved")
	}
	if !strings.Contains(got, `<Files "config.php.old">`) {
		t.Fatalf("deny block missing:\n%s", got)
	}
	// A backup of the original must exist.
	entries, _ := os.ReadDir(htaccessBackupDirRoot)
	if len(entries) == 0 {
		t.Fatal("expected a pre-patch backup of the original .htaccess")
	}
}

func TestVirtualPatchExposedFile_PreservesExistingMode(t *testing.T) {
	root := vpTestEnv(t)
	dir := filepath.Join(root, "dom")
	mustWrite(t, filepath.Join(dir, "dump.sql"), "-- dump\n")
	htaccess := filepath.Join(dir, ".htaccess")
	mustWrite(t, htaccess, "Options -Indexes\n")
	if err := os.Chmod(htaccess, 0600); err != nil {
		t.Fatal(err)
	}

	if res := VirtualPatchExposedFile(filepath.Join(dir, "dump.sql")); !res.Success {
		t.Fatalf("apply failed: %+v", res)
	}
	info, err := os.Stat(htaccess)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("existing .htaccess mode = %o, want 600", got)
	}
}

func TestVirtualPatchExposedFile_RefusesOversizedPatchedContent(t *testing.T) {
	root := vpTestEnv(t)
	dir := filepath.Join(root, "dom")
	target := filepath.Join(dir, "dump.sql")
	htaccess := filepath.Join(dir, ".htaccess")
	mustWrite(t, target, "-- dump\n")
	if err := os.WriteFile(htaccess, make([]byte, maxVirtualPatchHtaccessSize), 0644); err != nil {
		t.Fatal(err)
	}

	res := VirtualPatchExposedFile(target)
	if res.Success || !strings.Contains(res.Error, "patched .htaccess larger") {
		t.Fatalf("oversized patched content must be rejected, got %+v", res)
	}
	if info, err := os.Stat(htaccess); err != nil || info.Size() != maxVirtualPatchHtaccessSize {
		t.Fatalf("oversized rejection changed .htaccess: info=%v err=%v", info, err)
	}
}

func TestVirtualPatchExposedFile_AppliesOriginalOwner(t *testing.T) {
	root := vpTestEnv(t)
	dir := filepath.Join(root, "dom")
	target := filepath.Join(dir, "dump.sql")
	htaccess := filepath.Join(dir, ".htaccess")
	mustWrite(t, target, "-- dump\n")
	mustWrite(t, htaccess, "Options -Indexes\n")
	info, err := os.Stat(htaccess)
	if err != nil {
		t.Fatal(err)
	}
	wantUID, wantGID, err := ownerFromInfo(info)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	chownFunc = func(_ *os.File, uid, gid int) error {
		called = true
		if uid != wantUID || gid != wantGID {
			t.Fatalf("temporary owner = %d:%d, want original %d:%d", uid, gid, wantUID, wantGID)
		}
		return nil
	}

	if res := VirtualPatchExposedFile(target); !res.Success {
		t.Fatalf("apply failed: %+v", res)
	}
	if !called {
		t.Fatal("temporary .htaccess ownership was not set")
	}
}

func TestVirtualPatchExposedFile_ChownFailureLeavesSiteUntouched(t *testing.T) {
	root := vpTestEnv(t)
	dir := filepath.Join(root, "dom")
	target := filepath.Join(dir, "dump.sql")
	htaccess := filepath.Join(dir, ".htaccess")
	mustWrite(t, target, "-- dump\n")
	mustWrite(t, htaccess, "Options -Indexes\n")
	chownFunc = func(*os.File, int, int) error { return errors.New("operation not permitted") }

	res := VirtualPatchExposedFile(target)
	if res.Success || !strings.Contains(res.Error, "setting owner") {
		t.Fatalf("chown failure must abort the patch, got %+v", res)
	}
	if got := readFile(t, htaccess); got != "Options -Indexes\n" {
		t.Fatalf("chown failure changed customer .htaccess:\n%s", got)
	}
	entries, err := os.ReadDir(htaccessBackupDirRoot)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed patch left stale rollback entries: %v", entries)
	}
}

func TestVirtualPatchExposedFile_RejectsSymlinkedHtaccess(t *testing.T) {
	root := vpTestEnv(t)
	dir := filepath.Join(root, "dom")
	target := filepath.Join(dir, "dump.sql")
	outside := filepath.Join(root, "outside.htaccess")
	mustWrite(t, target, "-- dump\n")
	mustWrite(t, outside, "outside\n")
	if err := os.Symlink(outside, filepath.Join(dir, ".htaccess")); err != nil {
		t.Fatal(err)
	}

	res := VirtualPatchExposedFile(target)
	if res.Success || !strings.Contains(res.Error, "symlink") {
		t.Fatalf("symlinked .htaccess must be rejected, got %+v", res)
	}
	if got := readFile(t, outside); got != "outside\n" {
		t.Fatalf("symlink target changed: %q", got)
	}
}

func TestVirtualPatchExposedFile_DoesNotFollowLegacyTempSymlink(t *testing.T) {
	root := vpTestEnv(t)
	dir := filepath.Join(root, "dom")
	target := filepath.Join(dir, "dump.sql")
	outside := filepath.Join(root, "outside")
	mustWrite(t, target, "-- dump\n")
	mustWrite(t, outside, "do not overwrite\n")
	if err := os.Symlink(outside, filepath.Join(dir, ".htaccess.csm-vpatch.tmp")); err != nil {
		t.Fatal(err)
	}

	if res := VirtualPatchExposedFile(target); !res.Success {
		t.Fatalf("apply failed: %+v", res)
	}
	if got := readFile(t, outside); got != "do not overwrite\n" {
		t.Fatalf("legacy fixed temp symlink was followed: %q", got)
	}
}

func TestVirtualPatchExposedFile_RefusesSwappedTemporaryFile(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprintf("existing_%t", existing), func(t *testing.T) {
			root := vpTestEnv(t)
			dir := filepath.Join(root, "dom")
			target := filepath.Join(dir, "dump.sql")
			htaccess := filepath.Join(dir, ".htaccess")
			outside := filepath.Join(root, "attacker-file")
			mustWrite(t, target, "-- dump\n")
			mustWrite(t, outside, "attacker content\n")
			if existing {
				mustWrite(t, htaccess, "customer rules\n")
			}
			virtualPatchBeforeCommitForTest = func(_, tmp string) {
				if err := os.Remove(tmp); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, tmp); err != nil {
					t.Fatal(err)
				}
			}

			res := VirtualPatchExposedFile(target)
			if res.Success || !strings.Contains(res.Error, "temporary .htaccess changed") {
				t.Fatalf("swapped temporary file must abort the patch, got %+v", res)
			}
			if got := readFile(t, outside); got != "attacker content\n" {
				t.Fatalf("temporary symlink target changed: %q", got)
			}
			if existing {
				if got := readFile(t, htaccess); got != "customer rules\n" {
					t.Fatalf("temporary swap changed customer .htaccess: %q", got)
				}
			} else if _, err := os.Lstat(htaccess); !os.IsNotExist(err) {
				t.Fatalf("temporary swap installed a new .htaccess: %v", err)
			}
			entries, err := os.ReadDir(htaccessBackupDirRoot)
			if err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("rolled-back patch left stale backup entries: %v", entries)
			}
		})
	}
}

func TestVirtualPatchExposedFile_RefusesConcurrentHtaccessChange(t *testing.T) {
	root := vpTestEnv(t)
	dir := filepath.Join(root, "dom")
	target := filepath.Join(dir, "dump.sql")
	htaccess := filepath.Join(dir, ".htaccess")
	mustWrite(t, target, "-- dump\n")
	mustWrite(t, htaccess, "original\n")
	virtualPatchBeforeCommitForTest = func(path, _ string) {
		mustWrite(t, path, "customer update\n")
	}

	res := VirtualPatchExposedFile(target)
	if res.Success || !strings.Contains(res.Error, "changed while") {
		t.Fatalf("concurrent edit must abort the patch, got %+v", res)
	}
	if got := readFile(t, htaccess); got != "customer update\n" {
		t.Fatalf("concurrent customer edit was lost: %q", got)
	}
}

func TestVirtualPatchExposedFile_RefusesConcurrentModeChange(t *testing.T) {
	root := vpTestEnv(t)
	dir := filepath.Join(root, "dom")
	target := filepath.Join(dir, "dump.sql")
	htaccess := filepath.Join(dir, ".htaccess")
	mustWrite(t, target, "-- dump\n")
	mustWrite(t, htaccess, "original\n")
	virtualPatchBeforeCommitForTest = func(string, string) {
		if err := os.Chmod(htaccess, 0600); err != nil {
			t.Fatal(err)
		}
	}

	res := VirtualPatchExposedFile(target)
	if res.Success || !strings.Contains(res.Error, "changed while") {
		t.Fatalf("concurrent mode edit must abort the patch, got %+v", res)
	}
	info, err := os.Stat(htaccess)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 || readFile(t, htaccess) != "original\n" {
		t.Fatalf("concurrent mode edit was lost: mode=%o content=%q", info.Mode().Perm(), readFile(t, htaccess))
	}
}

func TestRestoreVirtualPatchBackup_RefusesLaterModeChange(t *testing.T) {
	root := vpTestEnv(t)
	dir := filepath.Join(root, "dom")
	target := filepath.Join(dir, "dump.sql")
	htaccess := filepath.Join(dir, ".htaccess")
	mustWrite(t, target, "-- dump\n")
	mustWrite(t, htaccess, "original\n")
	if res := VirtualPatchExposedFile(target); !res.Success {
		t.Fatalf("apply failed: %+v", res)
	}

	entries, err := os.ReadDir(htaccessBackupDirRoot)
	if err != nil {
		t.Fatal(err)
	}
	var itemPath, metaPath string
	for _, entry := range entries {
		path := filepath.Join(htaccessBackupDirRoot, entry.Name())
		if strings.HasSuffix(entry.Name(), ".meta") {
			metaPath = path
		} else {
			itemPath = path
		}
	}
	var meta QuarantineMeta
	if unmarshalErr := json.Unmarshal([]byte(readFile(t, metaPath)), &meta); unmarshalErr != nil {
		t.Fatal(unmarshalErr)
	}
	if chmodErr := os.Chmod(htaccess, 0600); chmodErr != nil {
		t.Fatal(chmodErr)
	}
	err = RestoreVirtualPatchBackup(itemPath, htaccess, meta)
	if !errors.Is(err, ErrVirtualPatchRestoreConflict) {
		t.Fatalf("later mode change should conflict, got %v", err)
	}
	if got := readFile(t, htaccess); !strings.Contains(got, "Require all denied") {
		t.Fatalf("conflicting restore changed the live .htaccess:\n%s", got)
	}
}

func TestParseVirtualPatchModePreservesZeroPermissions(t *testing.T) {
	mode, err := parseVirtualPatchMode("----------")
	if err != nil {
		t.Fatal(err)
	}
	if mode != 0 {
		t.Fatalf("zero-permission mode = %o, want 0", mode)
	}
	if _, err := parseVirtualPatchMode("-rw-r-?r--"); err == nil {
		t.Fatal("invalid permission string was accepted")
	}
}

func TestVirtualPatchExposedFile_Idempotent(t *testing.T) {
	root := vpTestEnv(t)
	f := filepath.Join(root, "dom", "dump.sql")
	mustWrite(t, f, "-- dump\n")

	if res := VirtualPatchExposedFile(f); !res.Success {
		t.Fatalf("first apply failed: %+v", res)
	}
	first := readFile(t, filepath.Join(root, "dom", ".htaccess"))
	res := VirtualPatchExposedFile(f)
	if res.Success {
		t.Fatal("second apply should be a no-op, not a success write")
	}
	if !strings.Contains(res.Error, "already") {
		t.Fatalf("expected 'already' no-op error, got %q", res.Error)
	}
	if readFile(t, filepath.Join(root, "dom", ".htaccess")) != first {
		t.Fatal("idempotent re-apply must not duplicate the deny block")
	}
}

func TestVirtualPatchExposedFile_TwoFilesSameDir(t *testing.T) {
	root := vpTestEnv(t)
	dir := filepath.Join(root, "dom")
	mustWrite(t, filepath.Join(dir, "a.sql"), "1")
	mustWrite(t, filepath.Join(dir, "b.sql"), "2")
	if res := VirtualPatchExposedFile(filepath.Join(dir, "a.sql")); !res.Success {
		t.Fatalf("a failed: %+v", res)
	}
	if res := VirtualPatchExposedFile(filepath.Join(dir, "b.sql")); !res.Success {
		t.Fatalf("b failed: %+v", res)
	}
	got := readFile(t, filepath.Join(dir, ".htaccess"))
	if !strings.Contains(got, `<Files "a.sql">`) || !strings.Contains(got, `<Files "b.sql">`) {
		t.Fatalf("both files should be denied:\n%s", got)
	}
}

func TestVirtualPatchExposedFile_BackupDirDenyWhole(t *testing.T) {
	root := vpTestEnv(t)
	bak := filepath.Join(root, "dom", "wp-content", "ai1wm-backups")
	f := filepath.Join(bak, "site-backup.wpress")
	mustWrite(t, f, "archive")

	res := VirtualPatchExposedFile(f)
	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}
	// A backup plugin re-creates archives under new names, so the whole
	// directory is denied rather than the single file.
	got := readFile(t, filepath.Join(bak, ".htaccess"))
	if !strings.Contains(got, "Require all denied") {
		t.Fatalf("expected blanket directory deny:\n%s", got)
	}
	if !strings.Contains(got, `<FilesMatch "^">`) {
		t.Fatalf("backup dir should use a whole-directory file section:\n%s", got)
	}
	_, ranges := AuditHtaccessFile(filepath.Join(bak, ".htaccess"))
	if len(ranges) != 0 {
		t.Fatalf("directory virtual-patch self-triggered the htaccess auditor: %d ranges", len(ranges))
	}
	if got := classifyExposedFile(".htaccess"); got != classNone {
		t.Fatalf("directory virtual-patch .htaccess was reclassified as exposed: %v", got)
	}
}

func TestKnownBackupPluginDirRequiresHighConfidencePath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/home/a/public_html/wp-content/ai1wm-backups", true},
		{"/home/a/public_html/wp-content/updraft", true},
		{"/home/a/public_html/wp-content/wpvividbackups", true},
		{"/home/a/public_html/wp-content/plugins/updraftplus", false},
		{"/home/a/public_html/wp-content/plugins/wpvivid", false},
		{"/home/a/public_html/custom/ai1wm-backups", false},
		{"/home/a/public_html/wpvividbackups", false},
		{"/home/a/public_html/backwpup", false},
		{"/home/a/public_html/custom/updraft", false},
	}
	for _, tc := range cases {
		if got := isKnownBackupPluginDir(tc.path); got != tc.want {
			t.Errorf("isKnownBackupPluginDir(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestVirtualPatchExposedFile_RejectsOutsideRoots(t *testing.T) {
	vpTestEnv(t)
	res := VirtualPatchExposedFile("/etc/passwd")
	if res.Success || res.Error == "" {
		t.Fatalf("must refuse a path outside the allowed roots, got %+v", res)
	}
}

func TestVirtualPatchExposedFile_RejectsDirectiveInjection(t *testing.T) {
	root := vpTestEnv(t)
	for _, name := range []string{`evil".sql`, "#comment.sql", "*.sql", "dump?.sql", "dump[1].sql", "${MATCH}.sql"} {
		bad := filepath.Join(root, "dom", name)
		mustWrite(t, bad, "x")
		res := VirtualPatchExposedFile(bad)
		if res.Success {
			t.Errorf("must refuse unsafe .htaccess file name %q", name)
		}
	}
}

// The deny block we write must not be flagged by the .htaccess hardened
// auditor (Require all denied is the opposite of the FilesMatch shield).
func TestVirtualPatchExposedFile_NoSelfTrigger(t *testing.T) {
	root := vpTestEnv(t)
	f := filepath.Join(root, "dom", "index.php.old")
	mustWrite(t, f, "<?php")
	if res := VirtualPatchExposedFile(f); !res.Success {
		t.Fatalf("apply failed: %+v", res)
	}
	_, ranges := AuditHtaccessFile(filepath.Join(root, "dom", ".htaccess"))
	if len(ranges) != 0 {
		t.Fatalf("virtual-patch deny block self-triggered the htaccess auditor: %d ranges", len(ranges))
	}
	if got := classifyExposedFile(".htaccess"); got != classNone {
		t.Fatalf("virtual-patch .htaccess was reclassified as exposed: %v", got)
	}
}

func vpFinding(check, path string) alert.Finding {
	return alert.Finding{Check: check, FilePath: path, Severity: alert.Critical}
}

func TestVirtualPatchExposedFindings_ApplyVsPreview(t *testing.T) {
	root := vpTestEnv(t)
	f := filepath.Join(root, "dom", ".env")
	mustWrite(t, f, "S=1")
	findings := []alert.Finding{
		vpFinding("web_exposed_config_leak", f),
		vpFinding("outdated_plugins", filepath.Join(root, "dom", "x")), // must be ignored
	}
	cfg := &config.Config{}

	// Preview: nothing written, one advisory emitted.
	prev := VirtualPatchExposedFindings(cfg, findings, false)
	if len(prev) != 1 {
		t.Fatalf("preview: want 1 advisory, got %d", len(prev))
	}
	if _, err := os.Stat(filepath.Join(root, "dom", ".htaccess")); err == nil {
		t.Fatal("preview must not write any .htaccess")
	}

	// Apply: deny written.
	act := VirtualPatchExposedFindings(cfg, findings, true)
	if len(act) != 1 {
		t.Fatalf("apply: want 1 action, got %d", len(act))
	}
	if _, err := os.Stat(filepath.Join(root, "dom", ".htaccess")); err != nil {
		t.Fatalf("apply must write the deny .htaccess: %v", err)
	}
}

func TestAutoVirtualPatchExposedFiles_ModeGating(t *testing.T) {
	root := vpTestEnv(t)
	f := filepath.Join(root, "dom", ".env")
	mustWrite(t, f, "S=1")
	findings := []alert.Finding{vpFinding("web_exposed_config_leak", f)}

	newCfg := func(mode string, enabled bool, dryRun bool) *config.Config {
		c := &config.Config{}
		c.AutoResponse.Enabled = enabled
		c.AutoResponse.VirtualPatchExposedFiles = mode
		dr := dryRun
		c.AutoResponse.DryRun = &dr
		return c
	}

	// off -> nothing.
	if got := AutoVirtualPatchExposedFiles(newCfg("off", true, false), findings); got != nil {
		t.Fatalf("off mode should do nothing, got %v", got)
	}
	// manual -> auto path does nothing (operator triggers it separately).
	if got := AutoVirtualPatchExposedFiles(newCfg("manual", true, false), findings); got != nil {
		t.Fatalf("manual mode must not act during a scan, got %v", got)
	}
	// auto but auto_response disabled -> nothing.
	if got := AutoVirtualPatchExposedFiles(newCfg("auto", false, false), findings); got != nil {
		t.Fatalf("auto with auto_response disabled should do nothing, got %v", got)
	}
	// auto + enabled + dry_run -> preview only, no write.
	_ = AutoVirtualPatchExposedFiles(newCfg("auto", true, true), findings)
	if _, err := os.Stat(filepath.Join(root, "dom", ".htaccess")); err == nil {
		t.Fatal("auto+dry_run must not write")
	}
	// auto + enabled + not dry_run -> applies.
	act := AutoVirtualPatchExposedFiles(newCfg("auto", true, false), findings)
	if len(act) == 0 {
		t.Fatal("auto live mode should apply and report an action")
	}
	if _, err := os.Stat(filepath.Join(root, "dom", ".htaccess")); err != nil {
		t.Fatalf("auto live mode must write deny: %v", err)
	}
}

func TestAutoVirtualPatchExposedFiles_SkipsWarningOnlySamples(t *testing.T) {
	root := vpTestEnv(t)
	f := filepath.Join(root, "dom", "schema.sql")
	mustWrite(t, f, "CREATE TABLE example")
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.VirtualPatchExposedFiles = "auto"
	dryRun := false
	cfg.AutoResponse.DryRun = &dryRun
	findings := []alert.Finding{{
		Check:    "web_exposed_sample_sql",
		FilePath: f,
		Severity: alert.Warning,
	}}

	if got := AutoVirtualPatchExposedFiles(cfg, findings); got != nil {
		t.Fatalf("auto mode must not enforce warning-only sample files, got %v", got)
	}
	if _, err := os.Stat(filepath.Join(root, "dom", ".htaccess")); !os.IsNotExist(err) {
		t.Fatalf("auto mode wrote a deny for a warning-only sample: %v", err)
	}
}

func TestAutoVirtualPatchExposedFiles_AppliesConfirmedNonSampleWarning(t *testing.T) {
	root := vpTestEnv(t)
	f := filepath.Join(root, "dom", "phpinfo.php")
	mustWrite(t, f, "<?php phpinfo();")
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.VirtualPatchExposedFiles = "auto"
	dryRun := false
	cfg.AutoResponse.DryRun = &dryRun
	findings := []alert.Finding{{
		Check:    "web_exposed_phpinfo",
		FilePath: f,
		Severity: alert.Warning,
	}}

	if got := AutoVirtualPatchExposedFiles(cfg, findings); len(got) != 1 {
		t.Fatalf("auto mode should apply a confirmed phpinfo finding, got %v", got)
	}
	if _, err := os.Stat(filepath.Join(root, "dom", ".htaccess")); err != nil {
		t.Fatalf("auto mode did not write the phpinfo deny: %v", err)
	}
}

func TestVirtualPatchModeNormalization(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "off"}, {"off", "off"}, {"OFF", "off"}, {"garbage", "off"},
		{"manual", "manual"}, {"Manual", "manual"},
		{"auto", "auto"}, {"AUTO ", "auto"},
	}
	for _, c := range cases {
		cfg := &config.Config{}
		cfg.AutoResponse.VirtualPatchExposedFiles = c.in
		if got := cfg.VirtualPatchMode(); got != c.want {
			t.Errorf("VirtualPatchMode(%q)=%q want %q", c.in, got, c.want)
		}
	}
}
