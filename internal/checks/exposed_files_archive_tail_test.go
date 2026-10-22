package checks

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestArchiveContentRetainsEvidenceBeforeUnreadTail(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries []string
	}{
		{"shallow", []string{"wp-config.php"}},
		{"paired", []string{"snapshot/site/wp-config.php", "snapshot/site/wp-load.php"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "site.zip")
			writeZip(t, path, tc.entries...)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			end := append([]byte(nil), raw[len(raw)-zipDirectoryEndLen:]...)
			binary.LittleEndian.PutUint32(end[12:16], binary.LittleEndian.Uint32(end[12:16])+4)
			raw = append(raw[:len(raw)-zipDirectoryEndLen], []byte("junk")...)
			raw = append(raw, end...)
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if !archiveHoldsSiteBackup(path) {
				t.Fatal("unread directory tail hid already-read site backup evidence")
			}
		})
	}
}
