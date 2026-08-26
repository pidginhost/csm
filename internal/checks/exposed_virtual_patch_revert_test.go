package checks

import (
	"encoding/json"
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
	if !strings.Contains(got, `\.wpress$`) || !strings.Contains(got, "Require all denied") {
		t.Errorf("parent .htaccess must deny the archive extension:\n%s", got)
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
