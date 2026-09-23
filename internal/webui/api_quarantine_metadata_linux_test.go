//go:build linux

package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
)

func TestRestorePreservesRecordedModificationTime(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mode      os.FileMode
		directory bool
	}{{"file", 0750, false}, {"directory", 0750, true}, {"no-permissions", 0, false}, {"special-permissions", os.ModeSetuid | os.ModeSetgid | 0750, false}} {
		name, directory := tc.name, tc.directory
		t.Run(name, func(t *testing.T) {
			qDir, restoreRoot := t.TempDir(), t.TempDir()
			withQuarantineDir(t, qDir)
			withQuarantineRestoreRoots(t, restoreRoot)
			qPath, destination := filepath.Join(qDir, "captured"), filepath.Join(restoreRoot, "restored")
			mode := tc.mode.String()
			contentPath := qPath
			if directory {
				mode = (tc.mode | os.ModeDir).String()
				if err := os.Mkdir(qPath, 0700); err != nil {
					t.Fatal(err)
				}
				contentPath = filepath.Join(qPath, "content")
			}
			if err := os.WriteFile(contentPath, []byte("original content"), 0600); err != nil {
				t.Fatal(err)
			}
			stamp := time.Date(2024, 2, 3, 4, 5, 6, 123456789, time.UTC)
			meta := checks.QuarantineMeta{OriginalPath: destination, Owner: os.Getuid(), Group: os.Getgid(), Mode: mode, Size: 16, OriginalModTime: stamp}
			if os.Geteuid() == 0 {
				meta.Owner, meta.Group = 1001, 1002
			}
			data, err := json.Marshal(meta)
			if err != nil {
				t.Fatal(err)
			}
			if writeErr := os.WriteFile(qPath+".meta", data, 0600); writeErr != nil {
				t.Fatal(writeErr)
			}
			w := httptest.NewRecorder()
			newRestoreServer(t).apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": "captured"}))
			if w.Code != http.StatusOK {
				t.Fatalf("restore status=%d, body=%s", w.Code, w.Body.String())
			}
			info, err := os.Stat(destination)
			if err != nil {
				t.Fatal(err)
			}
			st := info.Sys().(*syscall.Stat_t)
			if !info.ModTime().Equal(stamp) || info.Mode().String() != mode || int(st.Uid) != meta.Owner || int(st.Gid) != meta.Group {
				t.Fatalf("restored metadata=%+v, expected mtime=%s mode=%s owner=%d:%d", info, stamp, mode, meta.Owner, meta.Group)
			}
			if directory {
				destination = filepath.Join(destination, "content")
			}
			data, err = os.ReadFile(destination)
			if err != nil || string(data) != "original content" {
				t.Fatalf("restored content=%q, error=%v", data, err)
			}
		})
	}
}

func TestQuarantineListingSortsLegacyAndFractionalTimestamps(t *testing.T) {
	qDir := t.TempDir()
	withQuarantineDir(t, qDir)
	fixtures := []struct{ id, timestamp, field string }{
		{"unknown", "", ""},
		{"older-offset", "2026-09-05T12:00:00+03:00", "quarantined_at"},
		{"whole-second", "2026-09-05T10:00:00Z", "quarantined_at"},
		{"legacy-newest", "2026-09-05T10:00:00.2Z", "quarantine_at"},
		{"fractional", "2026-09-05T10:00:00.1Z", "quarantined_at"},
	}
	for _, fixture := range fixtures {
		data := map[string]any{"original_path": filepath.Join(t.TempDir(), "absent"), "reason": "test"}
		if fixture.field != "" {
			data[fixture.field] = fixture.timestamp
		}
		encoded, err := json.Marshal(data)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(qDir, fixture.id+".meta"), encoded, 0600); err != nil {
			t.Fatal(err)
		}
	}
	w := httptest.NewRecorder()
	(&Server{}).apiQuarantine(w, httptest.NewRequest(http.MethodGet, "/api/v1/quarantine", nil))
	var entries []struct {
		ID        string `json:"id"`
		Timestamp string `json:"quarantined_at"`
	}
	decodeItems(t, w.Body.Bytes(), &entries)
	want := []string{"legacy-newest", "fractional", "whole-second", "older-offset", "unknown"}
	if len(entries) != len(want) {
		t.Fatalf("entries=%v", entries)
	}
	for i, id := range want {
		if entries[i].ID != id {
			t.Fatalf("listing order=%v, want=%v", entries, want)
		}
	}
	if entries[0].Timestamp != "2026-09-05T10:00:00.2Z" || entries[3].Timestamp != "2026-09-05T09:00:00Z" || entries[4].Timestamp != "" {
		t.Fatalf("listing timestamps are inaccurate: %+v", entries)
	}
}

func TestRestoreLegacyModificationTimeAndTimestampFailure(t *testing.T) {
	oldRestore := restoreQuarantineModTime
	t.Cleanup(func() { restoreQuarantineModTime = oldRestore })
	for _, known := range []bool{false, true} {
		name := "historical-unknown"
		if known {
			name = "recorded-time-failure"
		}
		t.Run(name, func(t *testing.T) {
			qDir, root := t.TempDir(), t.TempDir()
			withQuarantineDir(t, qDir)
			withQuarantineRestoreRoots(t, root)
			qPath, destination := filepath.Join(qDir, "captured"), filepath.Join(root, "restored")
			if err := os.WriteFile(qPath, []byte("evidence"), 0600); err != nil {
				t.Fatal(err)
			}
			stamp := time.Date(2024, 1, 1, 0, 0, 0, 123456789, time.UTC)
			if err := os.Chtimes(qPath, stamp, stamp); err != nil {
				t.Fatal(err)
			}
			meta := checks.QuarantineMeta{OriginalPath: destination, Owner: os.Getuid(), Group: os.Getgid(), Mode: "-rw-------", QuarantineAt: stamp}
			if known {
				meta.OriginalModTime = stamp
			}
			data, marshalErr := json.Marshal(meta)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if err := os.WriteFile(qPath+".meta", data, 0600); err != nil {
				t.Fatal(err)
			}
			called := false
			restoreQuarantineModTime = func(_ *os.File, got time.Time) error {
				called = true
				if !got.Equal(stamp) {
					t.Errorf("timestamp=%s, want=%s", got, stamp)
				}
				return syscall.EIO
			}
			before := time.Now()
			w := httptest.NewRecorder()
			newRestoreServer(t).apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": "captured"}))
			if called != known {
				t.Fatalf("mtime setter called=%v, known=%v", called, known)
			}
			if known {
				if w.Code != http.StatusInternalServerError {
					t.Fatalf("timestamp failure status=%d body=%s", w.Code, w.Body.String())
				}
				for _, entry := range []struct{ path, want string }{{qPath, "evidence"}, {qPath + ".meta", string(data)}} {
					got, readErr := os.ReadFile(entry.path)
					if readErr != nil || string(got) != entry.want {
						t.Fatalf("recovery entry changed: %q error=%v", got, readErr)
					}
				}
			} else {
				if w.Code != http.StatusOK {
					t.Fatalf("historical restore status=%d body=%s", w.Code, w.Body.String())
				}
				info, err := os.Stat(destination)
				if err != nil {
					t.Fatal(err)
				}
				if info.ModTime().Before(before) || info.ModTime().After(time.Now()) {
					t.Fatalf("legacy mtime was fabricated: %s", info.ModTime())
				}
			}
		})
	}
}
