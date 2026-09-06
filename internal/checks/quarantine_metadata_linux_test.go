//go:build linux

package checks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestVirtualPatchBackupDistinguishesOriginalModificationTimes(t *testing.T) {
	root := vpTestEnv(t)
	archive, path := ai1wmSite(t, root)
	first := time.Date(2024, 2, 3, 4, 5, 6, 123456789, time.UTC)
	second := first.Add(time.Hour)
	for _, stamp := range []time.Time{first, second} {
		mustWrite(t, path, ai1wmPluginHtaccess)
		if err := os.Chtimes(path, stamp, stamp); err != nil {
			t.Fatal(err)
		}
		if result := VirtualPatchExposedFile(archive); !result.Success {
			t.Fatal(result)
		}
	}
	records := prePatchBackupsForPath(t, path)
	if len(records) != 2 {
		t.Fatalf("expected two distinct recovery timestamps, got=%v", records)
	}
	var selected *QuarantineMeta
	var selectedPath string
	for _, record := range records {
		if record.meta.OriginalModTime.Equal(second) {
			meta := record.meta
			selected, selectedPath = &meta, record.itemPath
		} else if !record.meta.OriginalModTime.Equal(first) {
			t.Fatalf("unexpected archived mtime: %s", record.meta.OriginalModTime)
		}
	}
	if selected == nil {
		t.Fatal("newer metadata snapshot missing")
	}
	if err := RestoreVirtualPatchBackup(selectedPath, virtualPatchRestoreTarget(t, path), *selected); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || !info.ModTime().Equal(second) {
		t.Fatalf("restored virtual-patch mtime=%v, error=%v", info, err)
	}
	if got := readFile(t, path); got != ai1wmPluginHtaccess {
		t.Fatalf("restored content=%q", got)
	}
}

func TestManualSpoolSidecarsPreserveAttributes(t *testing.T) {
	spool, qdir := t.TempDir(), t.TempDir()
	withEximSpoolDirs(t, []string{spool})
	withQuarantineDir(t, qdir)
	const msgID = "2jKPFm-000abc-1X"
	stamp := time.Date(2024, 2, 3, 4, 5, 6, 987654321, time.UTC)
	originals := make(map[string]os.FileInfo)
	for _, suffix := range []string{"-H", "-D"} {
		path := filepath.Join(spool, msgID+suffix)
		if err := os.WriteFile(path, []byte(suffix), 0640); err != nil {
			t.Fatal(err)
		}
		if os.Geteuid() == 0 {
			if err := os.Chown(path, 1001, 1002); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Chtimes(path, stamp, stamp); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		originals[path] = info
	}
	before := time.Now()
	if res := fixQuarantineSpoolMessage("phishing (message: " + msgID + ")"); !res.Success {
		t.Fatal(res)
	}
	after := time.Now()
	entries, err := os.ReadDir(qdir)
	if err != nil || len(entries) != 4 {
		t.Fatalf("quarantine entries=%v error=%v", entries, err)
	}
	seen := make(map[string]bool)
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".meta") {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(qdir, entry.Name()))
		if readErr != nil {
			t.Fatal(readErr)
		}
		var meta QuarantineMeta
		if decodeErr := json.Unmarshal(data, &meta); decodeErr != nil {
			t.Fatal(decodeErr)
		}
		info, ok := originals[meta.OriginalPath]
		if !ok || seen[meta.OriginalPath] {
			t.Fatalf("unexpected original: %s", meta.OriginalPath)
		}
		seen[meta.OriginalPath] = true
		stat := info.Sys().(*syscall.Stat_t)
		if meta.Owner != int(stat.Uid) || meta.Group != int(stat.Gid) || meta.Mode != info.Mode().String() || meta.Size != info.Size() || !meta.OriginalModTime.Equal(stamp) || meta.QuarantineAt.Before(before) || meta.QuarantineAt.After(after) || meta.Reason != "Phishing email quarantined via CSM Web UI" || meta.MessageID != msgID || meta.SpoolDir != spool {
			t.Fatalf("incorrect spool sidecar: %+v", meta)
		}
	}
	if len(seen) != 2 {
		t.Fatalf("captured originals=%v", seen)
	}
}
