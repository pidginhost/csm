package ipmap

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

func testWriter(t *testing.T) *Writer {
	w := NewWriter(filepath.Join(t.TempDir(), "csm_ip.map"))
	w.chown = func(string, int) error { return nil }
	return w
}

func TestWriterWritesOnlyChanges(t *testing.T) {
	w := testWriter(t)
	m := Build(Sources{Entries: map[string][]string{Spam.Name: {"203.0.113.40"}}})
	if wrote, err := w.Write(m, 974, now); !wrote || err != nil {
		t.Fatalf("first write = %v, %v", wrote, err)
	}
	info, err := os.Stat(w.Path)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("map file %v, %v", info, err)
	}
	if wrote, err := w.Write(m, 974, now.Add(time.Minute)); wrote || err != nil {
		t.Fatalf("unchanged map rewritten: %v, %v", wrote, err)
	}
	st := w.State()
	if st.Gen == "" || !st.WrittenAt.Equal(now) || st.Err != nil {
		t.Fatalf("state %+v", st)
	}
	if w.Weight(addr("203.0.113.40")) != Spam.Tenths() {
		t.Fatal("lookup does not follow the written map")
	}
}

func TestWriterKeepsTheOldFileOnFailure(t *testing.T) {
	w := testWriter(t)
	old := Build(Sources{Entries: map[string][]string{Spam.Name: {"203.0.113.41"}}})
	if _, err := w.Write(old, 974, now); err != nil {
		t.Fatal(err)
	}
	before, readErr := os.ReadFile(w.Path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	previous := w.State()
	w.chown = func(string, int) error { return errors.New("operation not permitted") }
	if wrote, err := w.Write(Build(Sources{Entries: map[string][]string{Spam.Name: {"203.0.113.42"}}}), 974, now.Add(time.Minute)); wrote || err == nil {
		t.Fatalf("failed write = %v, %v", wrote, err)
	}
	after, readErr := os.ReadFile(w.Path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if st := w.State(); st.Gen != previous.Gen || !st.WrittenAt.Equal(previous.WrittenAt) {
		t.Fatalf("failed write advanced state: %+v", st)
	}
	if string(after) != string(before) || w.Weight(addr("203.0.113.41")) != Spam.Tenths() || w.State().Err == nil {
		t.Fatal("a failed write changed the file, the lookup or hid the error")
	}
	if matches, err := filepath.Glob(filepath.Join(filepath.Dir(w.Path), ".csm_ip.map.*")); err != nil || len(matches) != 0 {
		t.Fatalf("temporary files left: %v, %v", matches, err)
	}
}

func TestWriterNeedsRspamdGroup(t *testing.T) {
	w := testWriter(t)
	if wrote, err := w.Write(Build(Sources{}), -1, now); wrote || err == nil {
		t.Fatal("wrote a map rspamd cannot read")
	}
}

func TestWriterRemove(t *testing.T) {
	w := testWriter(t)
	if _, err := w.Write(Build(Sources{Entries: map[string][]string{CINS.Name: {"203.0.113.43"}}}), 974, now); err != nil {
		t.Fatal(err)
	}
	if err := w.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(w.Path); !os.IsNotExist(err) || w.State().Gen != "" || w.Weight(addr("203.0.113.43")) != 0 {
		t.Fatal("remove left the file or the state")
	}
	if err := w.Remove(); err != nil {
		t.Fatalf("second remove: %v", err)
	}
}

func TestWriterValidatesGroupForUnchangedMap(t *testing.T) {
	w := testWriter(t)
	m := Build(Sources{})
	if _, err := w.Write(m, 974, now); err != nil {
		t.Fatal(err)
	}
	if wrote, err := w.Write(m, -1, now.Add(time.Minute)); wrote || err == nil || w.State().Err == nil {
		t.Fatalf("unknown group accepted: wrote %v, error %v, state %+v", wrote, err, w.State())
	}
}

func TestWriterUpdatesGroupForUnchangedMap(t *testing.T) {
	w := testWriter(t)
	var groups []int
	w.chown = func(_ string, gid int) error {
		groups = append(groups, gid)
		return nil
	}
	m := Build(Sources{})
	if _, err := w.Write(m, 974, now); err != nil {
		t.Fatal(err)
	}
	if wrote, err := w.Write(m, 975, now.Add(time.Minute)); !wrote || err != nil {
		t.Fatalf("group change = %v, %v", wrote, err)
	}
	if len(groups) != 2 || groups[0] != 974 || groups[1] != 975 {
		t.Fatalf("groups = %v", groups)
	}
}

func TestWriterRecreatesMissingUnchangedMap(t *testing.T) {
	w := testWriter(t)
	m := Build(Sources{})
	if _, err := w.Write(m, 974, now); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(w.Path); err != nil {
		t.Fatal(err)
	}
	if wrote, err := w.Write(m, 974, now.Add(time.Minute)); !wrote || err != nil {
		t.Fatalf("missing file not recreated: %v, %v", wrote, err)
	}
	got, err := os.ReadFile(w.Path)
	want, _ := m.Render()
	if err != nil || string(got) != string(want) {
		t.Fatalf("recreated map = %q, %v", got, err)
	}
}

func TestWriterTracksPublishedMapOnDirectorySyncFailure(t *testing.T) {
	w := testWriter(t)
	old := Build(Sources{Entries: map[string][]string{Spam.Name: {"203.0.113.41"}}})
	if _, err := w.Write(old, 974, now); err != nil {
		t.Fatal(err)
	}
	failedSync := errors.New("directory sync failed")
	syncDir := w.syncDir
	w.syncDir = func(string) error { return failedSync }
	updated := Build(Sources{Entries: map[string][]string{Spam.Name: {"203.0.113.42"}}})
	at := now.Add(time.Minute)
	if wrote, err := w.Write(updated, 974, at); !wrote || !errors.Is(err, failedSync) {
		t.Fatalf("published write = %v, %v", wrote, err)
	}
	content, gen := updated.Render()
	got, err := os.ReadFile(w.Path)
	if err != nil || string(got) != string(content) {
		t.Fatalf("published map = %q, %v", got, err)
	}
	st := w.State()
	if st.Gen != gen || !st.WrittenAt.Equal(at) || !errors.Is(st.Err, failedSync) {
		t.Fatalf("state does not describe published map: %+v", st)
	}
	if w.Weight(addr("203.0.113.41")) != 0 || w.Weight(addr("203.0.113.42")) != Spam.Tenths() {
		t.Fatal("lookup does not describe published map")
	}
	w.syncDir = syncDir
	if wrote, err := w.Write(updated, 974, at.Add(time.Minute)); !wrote || err != nil || w.State().Err != nil {
		t.Fatalf("retry = %v, %v, state %+v", wrote, err, w.State())
	}
}

func TestWriterRealFileOperations(t *testing.T) {
	w := NewWriter(filepath.Join(t.TempDir(), "csm_ip.map"))
	m := Build(Sources{Entries: map[string][]string{Spam.Name: {"203.0.113.40"}}})
	if wrote, err := w.Write(m, os.Getgid(), now); !wrote || err != nil {
		t.Fatalf("write with real chown = %v, %v", wrote, err)
	}
	info, err := os.Stat(w.Path)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("published mode = %v, %v", info, err)
	}
	got, err := os.ReadFile(w.Path)
	want, _ := m.Render()
	if err != nil || string(got) != string(want) {
		t.Fatalf("published map = %q, %v", got, err)
	}
}

func TestWriterConcurrentAccess(t *testing.T) {
	w := testWriter(t)
	m := Build(Sources{Entries: map[string][]string{Spam.Name: {"203.0.113.40"}}})
	content, gen := m.Render()
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 10 {
				if _, err := w.Write(m, 974, now); err != nil {
					t.Error(err)
				}
				if got := w.Weight(addr("203.0.113.40")); got != 0 && got != Spam.Tenths() {
					t.Errorf("unexpected weight: %d", got)
				}
				if st := w.State(); st.Err != nil || (st.Gen != "" && st.Gen != gen) {
					t.Errorf("unexpected state: %+v", st)
				}
				if err := w.Remove(); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	if _, err := os.Stat(w.Path); !errors.Is(err, os.ErrNotExist) || w.State().Gen != "" || w.Weight(addr("203.0.113.40")) != 0 {
		t.Fatal("last remove did not clear the map and lookup")
	}
	if wrote, err := w.Write(m, 974, now); !wrote || err != nil {
		t.Fatalf("write after concurrent removals = %v, %v", wrote, err)
	}
	got, err := os.ReadFile(w.Path)
	if err != nil || string(got) != string(content) || w.State().Gen != gen || w.Weight(addr("203.0.113.40")) != Spam.Tenths() {
		t.Fatal("map and lookup disagree after concurrent access")
	}
}

func TestWriterRepairsMissingMap(t *testing.T) {
	w := testWriter(t)
	m := Build(Sources{Entries: map[string][]string{Spam.Name: {"203.0.113.44"}}})
	if _, err := w.Write(m, 974, now); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(w.Path); err != nil {
		t.Fatal(err)
	}
	if wrote, err := w.Write(m, 974, now.Add(time.Minute)); !wrote || err != nil {
		t.Fatalf("missing map was not rebuilt: wrote=%v err=%v", wrote, err)
	}
	want, _ := m.Render()
	if got, err := os.ReadFile(w.Path); err != nil || string(got) != string(want) {
		t.Fatalf("rebuilt map = %q, err=%v", got, err)
	}
}

func TestWriterRevalidatesGroupForUnchangedContent(t *testing.T) {
	w := testWriter(t)
	m := Build(Sources{})
	var groups []int
	w.chown = func(_ string, gid int) error { groups = append(groups, gid); return nil }
	if _, err := w.Write(m, 974, now); err != nil {
		t.Fatal(err)
	}
	if wrote, err := w.Write(m, -1, now.Add(time.Minute)); wrote || err == nil || w.State().Err == nil {
		t.Fatalf("unknown group was hidden by content cache: wrote=%v err=%v", wrote, err)
	}
	if _, err := w.Write(m, 974, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if wrote, err := w.Write(m, 975, now.Add(3*time.Minute)); !wrote || err != nil {
		t.Fatalf("changed group was ignored: wrote=%v err=%v", wrote, err)
	}
	if groups[len(groups)-1] != 975 {
		t.Fatalf("map groups = %v, want last group 975", groups)
	}
}

// An operator or package change to the published file's mode makes rspamd
// unable to read it; the next write restores it even with unchanged content.
func TestWriterRepairsAChangedMode(t *testing.T) {
	w := testWriter(t)
	m := Build(Sources{Entries: map[string][]string{Spam.Name: {"203.0.113.45"}}})
	if _, err := w.Write(m, 974, now); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(w.Path, 0o600); err != nil {
		t.Fatal(err)
	}
	if wrote, err := w.Write(m, 974, now.Add(time.Minute)); !wrote || err != nil {
		t.Fatalf("changed mode was not repaired: wrote=%v err=%v", wrote, err)
	}
	if info, err := os.Stat(w.Path); err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("repaired map %v, %v", info, err)
	}
	if wrote, err := w.Write(m, 974, now.Add(2*time.Minute)); wrote || err != nil {
		t.Fatalf("unchanged map rewritten after repair: wrote=%v err=%v", wrote, err)
	}
}
