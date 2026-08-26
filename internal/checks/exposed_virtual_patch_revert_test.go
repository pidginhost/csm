package checks

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// ai1wmPluginHtaccess is what All-in-One WP Migration writes into its own
// backup directory on every run, wiping anything else that was there.
const ai1wmPluginHtaccess = `<IfModule mod_mime.c>
    AddType application/octet-stream .wpress
</IfModule>
<IfModule mod_dir.c>
    DirectoryIndex index.php
</IfModule>
<IfModule mod_autoindex.c>
    Options -Indexes
</IfModule>
`

func countPrePatchBackups(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir(htaccessBackupDirRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatalf("read backup dir: %v", err)
	}
	n := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".meta") {
			n++
		}
	}
	return n
}

type prePatchBackupRecord struct {
	itemPath string
	meta     QuarantineMeta
}

func prePatchBackupsForPath(t *testing.T, originalPath string) []prePatchBackupRecord {
	t.Helper()
	entries, err := os.ReadDir(htaccessBackupDirRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("read backup dir: %v", err)
	}
	var records []prePatchBackupRecord
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".meta") {
			continue
		}
		metaPath := filepath.Join(htaccessBackupDirRoot, entry.Name())
		var meta QuarantineMeta
		data, readErr := os.ReadFile(metaPath)
		if readErr != nil {
			t.Fatalf("read %s: %v", metaPath, readErr)
		}
		if err := json.Unmarshal(data, &meta); err != nil {
			t.Fatalf("decode %s: %v", metaPath, err)
		}
		if meta.OriginalPath == originalPath {
			records = append(records, prePatchBackupRecord{
				itemPath: strings.TrimSuffix(metaPath, ".meta"),
				meta:     meta,
			})
		}
	}
	return records
}

// ai1wmSite lays out a plugin backup directory holding one archive and
// returns the archive path plus the plugin-owned .htaccess path.
func ai1wmSite(t *testing.T, root string) (archive, htaccess string) {
	t.Helper()
	dir := filepath.Join(root, "site", "wp-content", "ai1wm-backups")
	archive = filepath.Join(dir, "site-20260101-120000-abcdef.wpress")
	mustWrite(t, archive, "archive bytes\n")
	htaccess = filepath.Join(dir, ".htaccess")
	mustWrite(t, htaccess, ai1wmPluginHtaccess)
	return archive, htaccess
}

// --- backup deduplication --------------------------------------------

func TestVirtualPatchExposedFile_DoesNotArchiveIdenticalPrePatchTwice(t *testing.T) {
	root := vpTestEnv(t)
	archive, htaccess := ai1wmSite(t, root)

	if res := VirtualPatchExposedFile(archive); !res.Success {
		t.Fatalf("first patch: %+v", res)
	}
	after := countPrePatchBackups(t)
	if after == 0 {
		t.Fatal("first patch must archive the pre-patch .htaccess")
	}

	// The plugin rewrites its own .htaccess, wiping CSM's deny block.
	mustWrite(t, htaccess, ai1wmPluginHtaccess)

	if res := VirtualPatchExposedFile(archive); !res.Success {
		t.Fatalf("re-patch after revert: %+v", res)
	}
	if got := countPrePatchBackups(t); got != after {
		t.Errorf("backups = %d after re-patching identical content, want %d", got, after)
	}
}

func TestVirtualPatchExposedFile_ArchivesChangedPrePatchContent(t *testing.T) {
	root := vpTestEnv(t)
	archive, htaccess := ai1wmSite(t, root)

	if res := VirtualPatchExposedFile(archive); !res.Success {
		t.Fatalf("first patch: %+v", res)
	}
	after := countPrePatchBackups(t)

	// A revert that also carries a genuine customer edit must still be kept.
	mustWrite(t, htaccess, ai1wmPluginHtaccess+"\n# customer rule\nSetEnv X 1\n")

	if res := VirtualPatchExposedFile(archive); !res.Success {
		t.Fatalf("re-patch after edited revert: %+v", res)
	}
	if got := countPrePatchBackups(t); got <= after {
		t.Errorf("backups = %d, want more than %d: changed content must be archived", got, after)
	}
}

func TestVirtualPatchExposedFile_ArchivesIdenticalContentAfterModeChange(t *testing.T) {
	root := vpTestEnv(t)
	archive, htaccess := ai1wmSite(t, root)

	if res := VirtualPatchExposedFile(archive); !res.Success {
		t.Fatalf("first patch: %+v", res)
	}
	before := prePatchBackupsForPath(t, htaccess)
	if len(before) != 1 {
		t.Fatalf("plugin backups after first patch = %d, want 1", len(before))
	}

	// The bytes match the old rollback point, but restoring this patch must
	// preserve the customer's newer permissions as well.
	mustWrite(t, htaccess, ai1wmPluginHtaccess)
	if err := os.Chmod(htaccess, 0o600); err != nil {
		t.Fatal(err)
	}
	if res := VirtualPatchExposedFile(archive); !res.Success {
		t.Fatalf("re-patch after mode change: %+v", res)
	}

	records := prePatchBackupsForPath(t, htaccess)
	if len(records) != 2 {
		t.Fatalf("plugin backups after mode change = %d, want 2 distinct rollback states", len(records))
	}
	for _, record := range records {
		if record.meta.Mode != "-rw-------" {
			continue
		}
		if err := RestoreVirtualPatchBackup(record.itemPath, htaccess, record.meta); err != nil {
			t.Fatalf("restore mode-specific backup: %v", err)
		}
		info, err := os.Stat(htaccess)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("restored mode = %o, want 600", got)
		}
		if got := readFile(t, htaccess); got != ai1wmPluginHtaccess {
			t.Fatalf("restored content differs from plugin file:\n%s", got)
		}
		return
	}
	t.Fatal("mode-specific rollback metadata was not stored")
}

func TestFindExistingPrePatchBackup_RejectsOversizedMetadata(t *testing.T) {
	root := vpTestEnv(t)
	if err := os.MkdirAll(htaccessBackupDirRoot, 0o750); err != nil {
		t.Fatal(err)
	}

	htaccess := filepath.Join(root, "site", ".htaccess")
	state := htaccessState{
		content: []byte("customer rules\n"),
		existed: true,
		uid:     os.Getuid(),
		gid:     os.Getgid(),
		mode:    0o644,
	}
	block := buildDenyBlock("dump.sql", false)
	patched := append(append([]byte(nil), state.content...), block...)
	metaData, err := json.Marshal(QuarantineMeta{
		OriginalPath:          htaccess,
		Owner:                 state.uid,
		Group:                 state.gid,
		Mode:                  state.mode.String(),
		Size:                  int64(len(state.content)),
		RestoreAction:         QuarantineRestoreReplaceIfUnchanged,
		ExpectedCurrentSHA256: virtualPatchSHA256(patched),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(metaData) >= maxVirtualPatchHtaccessSize {
		t.Fatal("test metadata unexpectedly exceeds the read limit")
	}
	metaData = append(metaData, strings.Repeat(" ", maxVirtualPatchHtaccessSize-len(metaData))...)
	metaData = append(metaData, 'x')
	itemPath := filepath.Join(htaccessBackupDirRoot, "candidate")
	if err := os.WriteFile(itemPath, state.content, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(itemPath+".meta", metaData, 0o600); err != nil {
		t.Fatal(err)
	}

	if backup, found := findExistingPrePatchBackup(htaccess, state, patched); found {
		t.Fatalf("oversized metadata was accepted as rollback point: %+v", backup)
	}
}

func TestFindExistingPrePatchBackup_RejectsSymlinkedArchive(t *testing.T) {
	root := vpTestEnv(t)
	if err := os.MkdirAll(htaccessBackupDirRoot, 0o750); err != nil {
		t.Fatal(err)
	}

	htaccess := filepath.Join(root, "site", ".htaccess")
	state := htaccessState{
		content: []byte("customer rules\n"),
		existed: true,
		uid:     os.Getuid(),
		gid:     os.Getgid(),
		mode:    0o644,
	}
	block := buildDenyBlock("dump.sql", false)
	patched := patchedHtaccessContent(state.content, state.existed, block)
	metaData, err := json.Marshal(QuarantineMeta{
		OriginalPath:          htaccess,
		Owner:                 state.uid,
		Group:                 state.gid,
		Mode:                  state.mode.String(),
		Size:                  int64(len(state.content)),
		RestoreAction:         QuarantineRestoreReplaceIfUnchanged,
		ExpectedCurrentSHA256: virtualPatchSHA256(patched),
	})
	if err != nil {
		t.Fatal(err)
	}
	realItem := filepath.Join(htaccessBackupDirRoot, "real-item")
	if err := os.WriteFile(realItem, state.content, 0o640); err != nil {
		t.Fatal(err)
	}
	itemPath := filepath.Join(htaccessBackupDirRoot, "candidate")
	if err := os.Symlink(filepath.Base(realItem), itemPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(itemPath+".meta", metaData, 0o600); err != nil {
		t.Fatal(err)
	}

	if backup, found := findExistingPrePatchBackup(htaccess, state, patched); found {
		t.Fatalf("symlinked archive cannot be a restorable rollback point: %+v", backup)
	}
}

func TestEachPrePatchBackup_DoesNotFollowMetadataOutsideRoot(t *testing.T) {
	root := vpTestEnv(t)
	if err := os.MkdirAll(htaccessBackupDirRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	outsideMeta := filepath.Join(root, "outside.meta")
	if err := os.WriteFile(outsideMeta, []byte(`{"original_path":"/outside"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideMeta, filepath.Join(htaccessBackupDirRoot, "escape.meta")); err != nil {
		t.Fatal(err)
	}

	called := false
	eachPrePatchBackup(func(QuarantineMeta, string, func(string) ([]byte, error)) bool {
		called = true
		return true
	})
	if called {
		t.Fatal("backup enumeration followed metadata outside its os.Root")
	}
}

// --- revert detection ------------------------------------------------

func TestVirtualPatchExposedFile_ReportsRepatchAfterRevert(t *testing.T) {
	root := vpTestEnv(t)
	archive, htaccess := ai1wmSite(t, root)

	res := VirtualPatchExposedFile(archive)
	if !res.Success {
		t.Fatalf("first patch: %+v", res)
	}
	if res.Reverted {
		t.Error("first patch must not be reported as a re-patch")
	}

	mustWrite(t, htaccess, ai1wmPluginHtaccess)

	res = VirtualPatchExposedFile(archive)
	if !res.Success {
		t.Fatalf("re-patch: %+v", res)
	}
	if !res.Reverted {
		t.Error("re-patching a previously patched .htaccess must report a revert")
	}
}

func TestVirtualPatchExposedFile_DoesNotReportFirstPatchForSecondFileAsRevert(t *testing.T) {
	root := vpTestEnv(t)
	dir := filepath.Join(root, "site")
	first := filepath.Join(dir, "first.sql")
	second := filepath.Join(dir, "second.sql")
	mustWrite(t, first, "first\n")
	mustWrite(t, second, "second\n")

	if res := VirtualPatchExposedFile(first); !res.Success {
		t.Fatalf("first file: %+v", res)
	}
	res := VirtualPatchExposedFile(second)
	if !res.Success {
		t.Fatalf("second file: %+v", res)
	}
	if res.Reverted {
		t.Fatal("a different file's earlier deny must not make a new patch look reverted")
	}
}

func TestVirtualPatchExposedFindings_WarnsWhenPatchWasReverted(t *testing.T) {
	root := vpTestEnv(t)
	archive, htaccess := ai1wmSite(t, root)

	finding := alert.Finding{Check: "web_exposed_backup_archive", FilePath: archive}
	if actions := VirtualPatchExposedFindings(nil, []alert.Finding{finding}, true); len(actions) == 0 {
		t.Fatal("first patch produced no action finding")
	}

	mustWrite(t, htaccess, ai1wmPluginHtaccess)

	actions := VirtualPatchExposedFindings(nil, []alert.Finding{finding}, true)
	var reverted *alert.Finding
	for i := range actions {
		if strings.HasPrefix(actions[i].Message, virtualPatchRevertedPrefix) {
			reverted = &actions[i]
			break
		}
	}
	if reverted == nil {
		t.Fatalf("no finding reported the revert; got %+v", actions)
	}
	if reverted.Severity != alert.Warning {
		t.Errorf("revert finding severity = %v, want Warning", reverted.Severity)
	}
	if !strings.Contains(reverted.Details, "ai1wm-backups") {
		t.Errorf("revert finding should name the directory that is being rewritten: %q", reverted.Details)
	}
}

// --- durable parent-directory deny -----------------------------------

func TestVirtualPatchExposedFile_DeniesArchiveExtensionFromParent(t *testing.T) {
	root := vpTestEnv(t)
	archive, _ := ai1wmSite(t, root)

	if res := VirtualPatchExposedFile(archive); !res.Success {
		t.Fatalf("patch: %+v", res)
	}

	parent := filepath.Join(root, "site", "wp-content", ".htaccess")
	got := readFile(t, parent)
	want := string(buildParentExtensionDenyBlock(".wpress"))
	if got != want {
		t.Errorf("parent .htaccess must contain only the verified .wpress deny:\ngot:\n%s\nwant:\n%s", got, want)
	}
	if strings.Contains(got, ".zip") || strings.Contains(got, ".gz") {
		t.Errorf("parent .htaccess must not deny legitimate wp-content archives:\n%s", got)
	}
}

func TestVirtualPatchExposedFile_AddsParentDenyWhenDirectoryDenyAlreadyExists(t *testing.T) {
	root := vpTestEnv(t)
	archive, htaccess := ai1wmSite(t, root)
	existing := append([]byte(ai1wmPluginHtaccess), buildDenyBlock(filepath.Base(archive), true)...)
	if err := os.WriteFile(htaccess, existing, 0o644); err != nil {
		t.Fatal(err)
	}

	res := VirtualPatchExposedFile(archive)
	if !res.Success {
		t.Fatalf("missing durable parent deny must still be applied: %+v", res)
	}
	parent := filepath.Join(root, "site", "wp-content", ".htaccess")
	if got, want := readFile(t, parent), string(buildParentExtensionDenyBlock(".wpress")); got != want {
		t.Fatalf("parent deny after existing directory patch:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestVirtualPatchExposedFile_ReportsParentDenyReapplication(t *testing.T) {
	root := vpTestEnv(t)
	archive, _ := ai1wmSite(t, root)
	parent := filepath.Join(root, "site", "wp-content", ".htaccess")

	if res := VirtualPatchExposedFile(archive); !res.Success {
		t.Fatalf("first patch: %+v", res)
	}
	mustWrite(t, parent, "# customer replacement\n")

	res := VirtualPatchExposedFile(archive)
	if !res.Success {
		t.Fatalf("parent re-patch: %+v", res)
	}
	if res.Reverted {
		t.Fatal("the surviving plugin-directory deny means HTTP protection was not reverted")
	}
	if !strings.Contains(res.Description, "re-applied the durable .wpress deny") {
		t.Fatalf("parent re-apply missing from description: %q", res.Description)
	}
	if got := readFile(t, parent); !strings.Contains(got, string(buildParentExtensionDenyBlock(".wpress"))) {
		t.Fatalf("parent deny was not restored:\n%s", got)
	}
}

func TestVirtualPatchExposedFile_RepairsModifiedParentDeny(t *testing.T) {
	root := vpTestEnv(t)
	archive, _ := ai1wmSite(t, root)
	parent := filepath.Join(root, "site", "wp-content", ".htaccess")

	if res := VirtualPatchExposedFile(archive); !res.Success {
		t.Fatalf("first patch: %+v", res)
	}
	damaged := strings.Replace(readFile(t, parent), "Require all denied", "Require all granted", 1)
	mustWrite(t, parent, damaged)

	res := VirtualPatchExposedFile(archive)
	if !res.Success {
		t.Fatalf("repair modified parent deny: %+v", res)
	}
	if res.Reverted {
		t.Fatal("the surviving plugin-directory deny means HTTP protection was not reverted")
	}
	if !strings.Contains(res.Description, "re-applied the durable .wpress deny") {
		t.Fatalf("parent repair missing from description: %q", res.Description)
	}
	if got := readFile(t, parent); !strings.Contains(got, string(buildParentExtensionDenyBlock(".wpress"))) {
		t.Fatalf("valid parent deny was not restored:\n%s", got)
	}
}

func TestVirtualPatchExposedFile_DoesNotDenyParentOutsideKnownPluginPath(t *testing.T) {
	root := vpTestEnv(t)
	dir := filepath.Join(root, "site", "custom", "ai1wm-backups")
	archive := filepath.Join(dir, "customer-download.wpress")
	mustWrite(t, archive, "customer archive\n")

	if res := VirtualPatchExposedFile(archive); !res.Success {
		t.Fatalf("single-file patch: %+v", res)
	}
	if got := readFile(t, filepath.Join(dir, ".htaccess")); !strings.Contains(got, `<Files "customer-download.wpress">`) {
		t.Fatalf("single-file deny missing:\n%s", got)
	}
	parent := filepath.Join(root, "site", "custom", ".htaccess")
	if _, err := os.Stat(parent); !os.IsNotExist(err) {
		t.Fatalf("unverified plugin path created a parent-wide .wpress deny: %v", err)
	}
}

func TestVirtualPatchExposedFile_ParentDenySurvivesPluginRevert(t *testing.T) {
	root := vpTestEnv(t)
	archive, htaccess := ai1wmSite(t, root)
	parent := filepath.Join(root, "site", "wp-content", ".htaccess")

	if res := VirtualPatchExposedFile(archive); !res.Success {
		t.Fatalf("first patch: %+v", res)
	}
	// The plugin rewrites only the .htaccess it owns.
	mustWrite(t, htaccess, ai1wmPluginHtaccess)
	if got := readFile(t, parent); !strings.Contains(got, `\.wpress$`) {
		t.Fatal("parent deny must be untouched by the plugin rewrite")
	}

	if res := VirtualPatchExposedFile(archive); !res.Success {
		t.Fatalf("re-patch: %+v", res)
	}
	if got := strings.Count(readFile(t, parent), "Require all denied"); got != 1 {
		t.Errorf("parent deny written %d times, want 1", got)
	}
}

func TestVirtualPatchExposedFile_PreservesExistingParentDirectives(t *testing.T) {
	root := vpTestEnv(t)
	archive, _ := ai1wmSite(t, root)
	parent := filepath.Join(root, "site", "wp-content", ".htaccess")
	mustWrite(t, parent, "# customer rules\nSetEnv SITE live\n")

	if res := VirtualPatchExposedFile(archive); !res.Success {
		t.Fatalf("patch: %+v", res)
	}
	got := readFile(t, parent)
	if !strings.Contains(got, "SetEnv SITE live") {
		t.Errorf("existing parent directives must be preserved:\n%s", got)
	}
	if !strings.Contains(got, `\.wpress$`) {
		t.Errorf("parent deny missing:\n%s", got)
	}
}

func TestVirtualPatchExposedFile_DoesNotDenyAmbiguousExtensionFromParent(t *testing.T) {
	// updraft writes .zip and .gz, which wp-content serves legitimately.
	// Denying them for the whole tree would break working downloads.
	root := vpTestEnv(t)
	dir := filepath.Join(root, "site", "wp-content", "updraft")
	archive := filepath.Join(dir, "backup_2026-01-01-db.zip")
	mustWrite(t, archive, "PK\x03\x04")
	mustWrite(t, filepath.Join(dir, ".htaccess"), "Options -Indexes\n")

	if res := VirtualPatchExposedFile(archive); !res.Success {
		t.Fatalf("patch: %+v", res)
	}
	parent := filepath.Join(root, "site", "wp-content", ".htaccess")
	if data, err := os.ReadFile(parent); err == nil && strings.Contains(string(data), ".zip") {
		t.Errorf("must not deny .zip across wp-content:\n%s", data)
	}
	// The plugin-directory deny still has to be written.
	if got := readFile(t, filepath.Join(dir, ".htaccess")); !strings.Contains(got, "Require all denied") {
		t.Errorf("directory deny missing:\n%s", got)
	}
}

func TestVirtualPatchExposedFile_ParentDenyFailureDoesNotBlockDirectoryDeny(t *testing.T) {
	// The plugin-directory deny is the immediate protection; a parent that
	// cannot be written must not cost us that.
	root := vpTestEnv(t)
	archive, _ := ai1wmSite(t, root)
	parent := filepath.Join(root, "site", "wp-content", ".htaccess")
	if err := os.MkdirAll(parent, 0o755); err != nil { // a directory where the file should be
		t.Fatal(err)
	}

	res := VirtualPatchExposedFile(archive)
	if !res.Success {
		t.Fatalf("directory deny must still succeed: %+v", res)
	}
	dirHtaccess := filepath.Join(filepath.Dir(archive), ".htaccess")
	if got := readFile(t, dirHtaccess); !strings.Contains(got, "Require all denied") {
		t.Errorf("directory deny missing:\n%s", got)
	}
}

func TestVirtualPatchExposedFile_ReportsParentFailureWithExistingDirectoryDeny(t *testing.T) {
	root := vpTestEnv(t)
	archive, pluginHtaccess := ai1wmSite(t, root)
	existing := append([]byte(ai1wmPluginHtaccess), buildDenyBlock(filepath.Base(archive), true)...)
	if err := os.WriteFile(pluginHtaccess, existing, 0o644); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(root, "site", "wp-content", ".htaccess")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatal(err)
	}

	res := VirtualPatchExposedFile(archive)
	if !res.Success {
		t.Fatalf("existing directory deny must remain a successful partial remediation: %+v", res)
	}
	if !strings.Contains(res.Description, "could not be written") {
		t.Fatalf("parent failure missing from description: %q", res.Description)
	}
	if got := readFile(t, pluginHtaccess); got != string(existing) {
		t.Fatalf("existing plugin-directory deny changed:\n%s", got)
	}
}

func TestVirtualPatchExposedFile_FailedParentRepatchKeepsSharedBackups(t *testing.T) {
	root := vpTestEnv(t)
	archive, pluginHtaccess := ai1wmSite(t, root)
	parentHtaccess := filepath.Join(root, "site", "wp-content", ".htaccess")
	const parentRules = "# customer parent rules\nOptions -Indexes\n"
	mustWrite(t, parentHtaccess, parentRules)

	if res := VirtualPatchExposedFile(archive); !res.Success {
		t.Fatalf("first patch: %+v", res)
	}
	pluginBackups := prePatchBackupsForPath(t, pluginHtaccess)
	parentBackups := prePatchBackupsForPath(t, parentHtaccess)
	if len(pluginBackups) != 1 || len(parentBackups) != 1 {
		t.Fatalf("initial backups: plugin=%d parent=%d, want one each", len(pluginBackups), len(parentBackups))
	}

	mustWrite(t, pluginHtaccess, ai1wmPluginHtaccess)
	mustWrite(t, parentHtaccess, parentRules)
	chownCalls := 0
	chownFunc = func(*os.File, int, int) error {
		chownCalls++
		if chownCalls == 2 {
			return errors.New("parent write denied")
		}
		return nil
	}

	res := VirtualPatchExposedFile(archive)
	if !res.Success {
		t.Fatalf("directory re-patch must survive parent failure: %+v", res)
	}
	if !strings.Contains(res.Description, "could not be written") {
		t.Fatalf("parent failure missing from description: %q", res.Description)
	}
	if got := readFile(t, pluginHtaccess); !strings.Contains(got, "Require all denied") {
		t.Fatalf("failed parent write removed plugin-directory deny:\n%s", got)
	}
	if got := len(prePatchBackupsForPath(t, pluginHtaccess)); got != len(pluginBackups) {
		t.Fatalf("plugin backups after parent failure = %d, want %d", got, len(pluginBackups))
	}
	if got := len(prePatchBackupsForPath(t, parentHtaccess)); got != len(parentBackups) {
		t.Fatalf("parent backups after failed reuse = %d, want %d", got, len(parentBackups))
	}
}

// Sharing one archived copy across repeated patches must not cost the
// rollback point: restore still has to recognise the patched file and put the
// plugin's own .htaccess back.
func TestRestoreVirtualPatchBackup_WorksAfterDedupedRepatch(t *testing.T) {
	root := vpTestEnv(t)
	archive, htaccess := ai1wmSite(t, root)

	if res := VirtualPatchExposedFile(archive); !res.Success {
		t.Fatalf("first patch: %+v", res)
	}
	mustWrite(t, htaccess, ai1wmPluginHtaccess)
	if res := VirtualPatchExposedFile(archive); !res.Success {
		t.Fatalf("re-patch: %+v", res)
	}

	entries, err := os.ReadDir(htaccessBackupDirRoot)
	if err != nil {
		t.Fatalf("read backup dir: %v", err)
	}
	restored := false
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".meta") {
			continue
		}
		metaPath := filepath.Join(htaccessBackupDirRoot, entry.Name())
		var meta QuarantineMeta
		data, readErr := os.ReadFile(metaPath)
		if readErr != nil {
			t.Fatalf("read meta: %v", readErr)
		}
		if err := json.Unmarshal(data, &meta); err != nil {
			t.Fatalf("decode meta: %v", err)
		}
		if meta.OriginalPath != htaccess {
			continue
		}
		if err := RestoreVirtualPatchBackup(strings.TrimSuffix(metaPath, ".meta"), htaccess, meta); err != nil {
			t.Fatalf("restore: %v", err)
		}
		restored = true
		break
	}
	if !restored {
		t.Fatal("no backup recorded for the plugin .htaccess")
	}
	if got := readFile(t, htaccess); got != ai1wmPluginHtaccess {
		t.Errorf("restore did not put the original .htaccess back:\n%s", got)
	}
}

// An .htaccess CSM created and one it appended to roll back differently:
// remove versus replace. Reusing an archived copy across those two would make
// restore delete a file the customer owns, so the restore action has to match
// as well as the content.
func TestVirtualPatchExposedFile_DoesNotReuseBackupWithDifferentRestoreAction(t *testing.T) {
	root := vpTestEnv(t)
	dir := filepath.Join(root, "site", "wp-content", "ai1wm-backups")
	archive := filepath.Join(dir, "site.wpress")
	mustWrite(t, archive, "archive\n")
	htaccess := filepath.Join(dir, ".htaccess")

	// No .htaccess: CSM creates one, so rollback means removing it.
	if res := VirtualPatchExposedFile(archive); !res.Success {
		t.Fatalf("patch without .htaccess: %+v", res)
	}
	// Something replaces it with an empty file CSM must not delete.
	mustWrite(t, htaccess, "")
	if res := VirtualPatchExposedFile(archive); !res.Success {
		t.Fatalf("patch over empty .htaccess: %+v", res)
	}

	var actions []string
	entries, err := os.ReadDir(htaccessBackupDirRoot)
	if err != nil {
		t.Fatalf("read backup dir: %v", err)
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".meta") {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(htaccessBackupDirRoot, entry.Name()))
		if readErr != nil {
			t.Fatalf("read meta: %v", readErr)
		}
		var meta QuarantineMeta
		if err := json.Unmarshal(data, &meta); err != nil {
			t.Fatalf("decode meta: %v", err)
		}
		if meta.OriginalPath == htaccess {
			actions = append(actions, meta.RestoreAction)
		}
	}
	if len(actions) != 2 {
		t.Fatalf("restore actions recorded for the .htaccess = %v, want one per distinct rollback", actions)
	}
	seen := map[string]bool{actions[0]: true, actions[1]: true}
	if !seen[QuarantineRestoreRemoveIfUnchanged] || !seen[QuarantineRestoreReplaceIfUnchanged] {
		t.Errorf("restore actions = %v, want one remove and one replace", actions)
	}
}

func TestVirtualPatchExposedFile_ReusesBackupWhenCreatedFileIsDeletedAgain(t *testing.T) {
	root := vpTestEnv(t)
	dir := filepath.Join(root, "site", "wp-content", "ai1wm-backups")
	archive := filepath.Join(dir, "site.wpress")
	mustWrite(t, archive, "archive\n")
	htaccess := filepath.Join(dir, ".htaccess")

	if res := VirtualPatchExposedFile(archive); !res.Success {
		t.Fatalf("first patch: %+v", res)
	}
	after := countPrePatchBackups(t)

	// The plugin deletes the file CSM created, putting us back to no .htaccess.
	if err := os.Remove(htaccess); err != nil {
		t.Fatal(err)
	}
	if res := VirtualPatchExposedFile(archive); !res.Success {
		t.Fatalf("re-patch: %+v", res)
	}
	if got := countPrePatchBackups(t); got != after {
		t.Errorf("backups = %d, want %d: recreating the same file must not archive again", got, after)
	}
}
