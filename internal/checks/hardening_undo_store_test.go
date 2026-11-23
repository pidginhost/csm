package checks

import (
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// withHardeningUndoDir points the undo store at a path under t.TempDir()
// that does not exist yet and accepts the test user as its owner.
func withHardeningUndoDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "undo")
	prevDir, prevOwner := hardeningUndoDir, hardeningUndoOwner
	hardeningUndoDir, hardeningUndoOwner = dir, os.Getuid()
	t.Cleanup(func() { hardeningUndoDir, hardeningUndoOwner = prevDir, prevOwner })
	return dir
}

func TestHardeningUndoDirRechecksOpenedPermissions(t *testing.T) {
	dir := withHardeningUndoDir(t)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := checkOpenedUndoDir(root); err == nil {
		t.Fatal("accepted a directory made writable after opening")
	}
}

func TestHardeningUndoRejectsUnsafeRecordModes(t *testing.T) {
	for _, mode := range []fs.FileMode{0o666, 0o644, 0o400, 0o600 | os.ModeSetuid} {
		t.Run(mode.String(), func(t *testing.T) {
			dir := withHardeningUndoDir(t)
			rec := testHardeningUndoRecords()[0]
			if err := writeHardeningUndo(rec); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(dir, rec.Name+".json"), mode); err != nil {
				t.Fatal(err)
			}
			if _, ok, err := readHardeningUndo(rec.Name); ok || err == nil {
				t.Fatalf("accepted record with mode %v: ok=%v err=%v", mode, ok, err)
			}
			if err := writeHardeningUndo(rec); err == nil {
				t.Fatal("replaced a record with unsafe permissions")
			}
		})
	}
}

func TestHardeningUndoConcurrentWrites(t *testing.T) {
	dir := withHardeningUndoDir(t)
	const writers = 16
	recs := make([]HardeningUndoRecord, writers)
	for i := range recs {
		recs[i] = testHardeningUndoRecords()[7]
		recs[i].File.Previous = strings.Repeat(string(rune('a'+i)), 256*1024)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, rec := range recs {
		wg.Go(func() {
			<-start
			if err := writeHardeningUndo(rec); err != nil {
				t.Errorf("concurrent write: %v", err)
			}
		})
	}
	close(start)
	wg.Wait()
	got, ok, err := readHardeningUndo(recs[0].Name)
	if err != nil || !ok {
		t.Fatalf("read after concurrent writes: ok=%v err=%v", ok, err)
	}
	if !slices.ContainsFunc(recs, func(rec HardeningUndoRecord) bool { return reflect.DeepEqual(rec, got) }) {
		t.Fatal("stored record is not a complete submitted record")
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 1 || entries[0].Name() != recs[0].Name+".json" {
		t.Fatalf("unexpected records after concurrent writes: %v, %v", entries, err)
	}
}

func TestHardeningUndoSyncsDirectoryChanges(t *testing.T) {
	dir := withHardeningUndoDir(t)
	prev := hardeningUndoSync
	t.Cleanup(func() { hardeningUndoSync = prev })
	var synced []string
	hardeningUndoSync = func(f *os.File) error {
		synced = append(synced, filepath.Clean(f.Name()))
		return f.Sync()
	}
	rec := testHardeningUndoRecords()[0]
	if err := writeHardeningUndo(rec); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(synced, filepath.Dir(dir)) {
		t.Error("first write did not persist the store's parent directory")
	}
	if len(synced) == 0 || synced[len(synced)-1] != dir {
		t.Errorf("write did not finish by syncing the record directory: %v", synced)
	}
	synced = nil
	if err := deleteHardeningUndo(rec.Name); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(synced, []string{dir}) {
		t.Errorf("delete synced %v; want [%s]", synced, dir)
	}
	synced = nil
	if err := deleteHardeningUndo(rec.Name); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(synced, []string{dir}) {
		t.Errorf("delete retry synced %v; want [%s]", synced, dir)
	}
}

func TestHardeningUndoOpenedRecordOwner(t *testing.T) {
	dir := withHardeningUndoDir(t)
	rec := testHardeningUndoRecords()[0]
	if err := writeHardeningUndo(rec); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(filepath.Join(dir, rec.Name+".json"), &st); err != nil {
		t.Fatal(err)
	}
	if err := checkUndoRecordStat(&st); err != nil {
		t.Fatal(err)
	}
	st.Uid++
	if err := checkUndoRecordStat(&st); err == nil {
		t.Fatal("accepted an opened record owned by another user")
	}
}

func TestHardeningUndoAllowsLinkedParent(t *testing.T) {
	dir := withHardeningUndoDir(t)
	parentLink := filepath.Join(t.TempDir(), "parent")
	if err := os.Symlink(filepath.Dir(dir), parentLink); err != nil {
		t.Fatal(err)
	}
	hardeningUndoDir = filepath.Join(parentLink, "undo")
	rec := testHardeningUndoRecords()[0]
	if err := writeHardeningUndo(rec); err != nil {
		t.Fatal(err)
	}
	if got, ok, err := readHardeningUndo(rec.Name); err != nil || !ok || !reflect.DeepEqual(got, rec) {
		t.Fatalf("record under linked parent: %+v, %v, %v", got, ok, err)
	}
}

func TestHardeningUndoOpenRefusesSwappedLink(t *testing.T) {
	dir := withHardeningUndoDir(t)
	rec := testHardeningUndoRecords()[0]
	if err := writeHardeningUndo(rec); err != nil {
		t.Fatal(err)
	}
	root, err := openHardeningUndoDir(false)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	file := rec.Name + ".json"
	if err = undoRecordInfo(root, file); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(filepath.Join(dir, file), filepath.Join(dir, "kept")); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink("kept", filepath.Join(dir, file)); err != nil {
		t.Fatal(err)
	}
	// The link targets the very same inode the metadata check accepted.
	f, err := openUndoFile(root, file, os.O_RDONLY, 0)
	if err == nil {
		f.Close()
		t.Fatal("followed a link substituted after checking the record")
	}
	if !errors.Is(err, unix.ELOOP) {
		t.Fatalf("open error = %v; want ELOOP", err)
	}
}

func TestHardeningUndoRejectsCorruptRecords(t *testing.T) {
	dir := withHardeningUndoDir(t)
	rec := testHardeningUndoRecords()[0]
	if err := writeHardeningUndo(rec); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{`, `null`, `{"name":"cp_updates"}`} {
		if err := os.WriteFile(filepath.Join(dir, rec.Name+".json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, ok, err := readHardeningUndo(rec.Name); err == nil || ok || !reflect.DeepEqual(got, HardeningUndoRecord{}) {
			t.Fatalf("invalid record accepted: %+v, %v, %v", got, ok, err)
		}
		// Listing must not parse or read record contents.
		if names, err := HardeningUndoNames(); err != nil || !slices.Equal(names, []string{rec.Name}) {
			t.Fatalf("listing corrupt record = %v, %v", names, err)
		}
	}
}

func TestHardeningUndoReportsSyncFailures(t *testing.T) {
	for _, stage := range []string{"parent", "file", "rename", "delete"} {
		t.Run(stage, func(t *testing.T) {
			dir := withHardeningUndoDir(t)
			rec := testHardeningUndoRecords()[0]
			if err := writeHardeningUndo(rec); err != nil {
				t.Fatal(err)
			}
			prev := hardeningUndoSync
			t.Cleanup(func() { hardeningUndoSync = prev })
			wantErr := errors.New("sync failed")
			hardeningUndoSync = func(f *os.File) error {
				path := filepath.Clean(f.Name())
				if (stage == "parent" && path == filepath.Dir(dir)) ||
					(stage == "file" && filepath.Dir(path) == dir) ||
					((stage == "rename" || stage == "delete") && path == dir) {
					return wantErr
				}
				return f.Sync()
			}
			newer := rec
			newer.AppliedAt = rec.AppliedAt.Add(time.Hour)
			var err error
			if stage == "delete" {
				err = deleteHardeningUndo(rec.Name)
			} else {
				err = writeHardeningUndo(newer)
			}
			if !errors.Is(err, wantErr) {
				t.Fatalf("%s sync failure = %v; want %v", stage, err, wantErr)
			}
			got, ok, err := readHardeningUndo(rec.Name)
			if err != nil {
				t.Fatal(err)
			}
			if stage == "delete" {
				if ok {
					t.Fatal("record survived unlink")
				}
			} else {
				want := rec
				if stage == "rename" {
					want = newer
				}
				if !ok || !reflect.DeepEqual(got, want) {
					t.Fatalf("%s failure left unexpected record: %+v, %v", stage, got, ok)
				}
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range entries {
				if e.Name() != rec.Name+".json" {
					t.Errorf("temporary entry survived failure: %s", e.Name())
				}
			}
		})
	}
}

// testHardeningUndoRecords holds one record for every kind of fix.
func testHardeningUndoRecords() []HardeningUndoRecord {
	at := time.Date(2026, 11, 23, 9, 30, 0, 0, time.UTC)
	return []HardeningUndoRecord{
		{Name: "ssh_max_auth_tries", Category: "ssh", Kind: "ssh", AppliedAt: at, SSH: &sshUndoState{
			Keyword: "MaxAuthTries", AppliedValue: "4", DisabledLines: []string{"MaxAuthTries 6"},
		}},
		{Name: "os_sysctl_rp_filter", Category: "os", Kind: "sysctl", AppliedAt: at, Sysctl: &sysctlUndoState{
			Key: "net.ipv4.conf.all.rp_filter", PrevRuntime: "2", PrevLines: []string{"net.ipv4.conf.all.rp_filter = 2"}, AppliedValue: "1",
		}},
		{Name: "cp_max_emails_hour", Category: "cpanel", Kind: "tweak", AppliedAt: at, Tweak: &tweakUndoState{
			Key: "maxemailsperhour", Previous: "0", HadValue: true, Applied: "200",
		}},
		{Name: "php_expose_81", Category: "php", Kind: "php", AppliedAt: at, PHP: []phpUndoState{
			{Path: "/opt/cpanel/ea-php81/root/etc/php.d/zz-csm-hardening.ini", Key: "expose_php", PrevLine: "expose_php = On", HadKey: true, Applied: "Off"},
			{Path: "/etc/php/8.1/fpm/conf.d/zz-csm-hardening.ini", Key: "expose_php", Applied: "Off"},
		}},
		{Name: "os_tmp_permissions", Category: "os", Kind: "mode", AppliedAt: at, Mode: &modeUndoState{
			Path: "/tmp", Mode: 0o755, UID: 1000, GID: 1000, AppliedMode: 0o1777,
		}},
		{Name: "os_shadow_permissions", Category: "os", Kind: "mode", AppliedAt: at, Mode: &modeUndoState{
			Path: "/etc/shadow", Mode: 0o644, GID: 42, AppliedMode: 0o640, AppliedGID: 42,
		}},
		{Name: "cp_compilers", Category: "cpanel", Kind: "compilers", AppliedAt: at, Compilers: &compilersUndoState{
			Method: "chmod", Path: "/usr/bin/gcc", Mode: 0o755, AppliedMode: 0o750,
		}},
		{Name: "cp_updates", Category: "cpanel", Kind: "file", AppliedAt: at, File: &fileUndoState{
			Path: "/etc/cpupdate.conf", Previous: "UPDATES=manual\n", Applied: "UPDATES=daily\n",
		}},
	}
}

// undoTreeState maps every entry under dir to its mode and its content or
// link target, so a test can prove that nothing was written.
func undoTreeState(t *testing.T, dir string) map[string]string {
	t.Helper()
	state := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		var body []byte
		switch {
		case info.Mode().IsRegular():
			body, err = os.ReadFile(path)
		case info.Mode()&os.ModeSymlink != 0:
			var dest string
			dest, err = os.Readlink(path)
			body = []byte(dest)
		}
		state[path] = info.Mode().String() + " " + string(body)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func TestHardeningUndoStoreRoundTrip(t *testing.T) {
	dir := withHardeningUndoDir(t)
	recs := testHardeningUndoRecords()

	// Before the first apply the directory is absent. The daemon lists it
	// read-only, so readers report no records and create nothing.
	if rec, ok, err := readHardeningUndo(recs[0].Name); ok || err != nil {
		t.Fatalf("read before any write = %+v, %v, %v; want no record", rec, ok, err)
	}
	if names, err := HardeningUndoNames(); len(names) != 0 || err != nil {
		t.Fatalf("names before any write = %v, %v; want none", names, err)
	}
	if err := deleteHardeningUndo(recs[0].Name); err != nil {
		t.Fatalf("delete before any write: %v", err)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a reader created the record directory: %v", err)
	}

	var want []string
	for _, rec := range recs {
		if err := writeHardeningUndo(rec); err != nil {
			t.Fatalf("write %s: %v", rec.Name, err)
		}
		want = append(want, rec.Name)
	}
	slices.Sort(want)
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("record directory = %v, %v; want a 0700 directory", info, err)
	}
	for _, rec := range recs {
		got, ok, err := readHardeningUndo(rec.Name)
		if err != nil || !ok {
			t.Fatalf("read %s = ok %v, err %v", rec.Name, ok, err)
		}
		if !reflect.DeepEqual(got, rec) {
			t.Errorf("read %s =\n%+v\nwant\n%+v", rec.Name, got, rec)
		}
		info, err := os.Lstat(filepath.Join(dir, rec.Name+".json"))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Errorf("record file %s = %v, %v; want a 0600 regular file", rec.Name, info, err)
		}
	}
	if names, err := HardeningUndoNames(); err != nil || !slices.Equal(names, want) {
		t.Fatalf("names = %v, %v; want %v", names, err, want)
	}

	// The newest apply replaces the record.
	newer := recs[0]
	newer.AppliedAt = newer.AppliedAt.Add(time.Hour)
	newer.SSH = &sshUndoState{Keyword: "MaxAuthTries", PrevValue: "3", HadValue: true, AppliedValue: "4"}
	if err := writeHardeningUndo(newer); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if got, ok, err := readHardeningUndo(newer.Name); err != nil || !ok || !reflect.DeepEqual(got, newer) {
		t.Fatalf("read after rewrite = %+v, %v, %v; want %+v", got, ok, err, newer)
	}

	for _, rec := range recs {
		if err := deleteHardeningUndo(rec.Name); err != nil {
			t.Fatalf("delete %s: %v", rec.Name, err)
		}
		if got, ok, err := readHardeningUndo(rec.Name); ok || err != nil {
			t.Fatalf("read %s after delete = %+v, %v, %v; want no record", rec.Name, got, ok, err)
		}
	}
	if names, err := HardeningUndoNames(); len(names) != 0 || err != nil {
		t.Fatalf("names after delete = %v, %v; want none", names, err)
	}
	// No temporary file outlives a write.
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatalf("left in the record directory: %v, %v", entries, err)
	}
}

func TestHardeningUndoStoreRefusesUnsafePaths(t *testing.T) {
	rec := testHardeningUndoRecords()[0]
	cases := []struct {
		name string
		// unsafe turns a directory holding rec into the unsafe layout.
		unsafe func(t *testing.T, dir string)
		// A bad directory must also refuse listing and deleting.
		dirLevel bool
	}{
		{"directory is a symlink", func(t *testing.T, dir string) {
			target := dir + ".real"
			if err := os.Rename(dir, target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, dir); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"directory mode 0755", func(t *testing.T, dir string) {
			if err := os.Chmod(dir, 0o755); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"directory owned by another user", func(*testing.T, string) {
			hardeningUndoOwner = os.Getuid() + 1
		}, true},
		// Even links within the record directory are refused.
		{"record file is a symlink", func(t *testing.T, dir string) {
			file := filepath.Join(dir, rec.Name+".json")
			if err := os.Rename(file, filepath.Join(dir, "kept")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("kept", file); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"record file is a pipe", func(t *testing.T, dir string) {
			file := filepath.Join(dir, rec.Name+".json")
			if err := os.Rename(file, file+".kept"); err != nil {
				t.Fatal(err)
			}
			if err := unix.Mkfifo(file, 0o600); err != nil {
				t.Fatal(err)
			}
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := withHardeningUndoDir(t)
			if err := writeHardeningUndo(rec); err != nil {
				t.Fatal(err)
			}
			tc.unsafe(t, dir)
			before := undoTreeState(t, filepath.Dir(dir))

			changed := rec
			changed.AppliedAt = rec.AppliedAt.Add(time.Hour)
			if err := writeHardeningUndo(changed); err == nil {
				t.Error("write went through an unsafe path")
			}
			if got, ok, err := readHardeningUndo(rec.Name); ok || err == nil {
				t.Errorf("read through an unsafe path = %+v, %v, %v; want an error", got, ok, err)
			}
			if tc.dirLevel {
				if names, err := HardeningUndoNames(); err == nil {
					t.Errorf("listed an unsafe directory: %v", names)
				}
				if err := deleteHardeningUndo(rec.Name); err == nil {
					t.Error("deleted from an unsafe directory")
				}
			}
			if after := undoTreeState(t, filepath.Dir(dir)); !maps.Equal(before, after) {
				t.Errorf("files changed:\nbefore %v\nafter  %v", before, after)
			}
		})
	}
}

func TestHardeningUndoStoreRejectsUnknownNames(t *testing.T) {
	dir := withHardeningUndoDir(t)
	for _, name := range []string{
		"../x",
		"ssh_max_auth_tries/../../etc",
		"php_expose_81/../../etc", // PHP fixes match by prefix, so the suffix needs the check too
		"",
		"ssh_password_auth",        // a check with no automatic fix
		"php_disable_functions_81", // a PHP check with no automatic fix
		"php_expose_",              // a PHP fix prefix without an install
	} {
		rec := testHardeningUndoRecords()[0]
		rec.Name = name
		if err := writeHardeningUndo(rec); err == nil {
			t.Errorf("write %q succeeded", name)
		}
		if got, ok, err := readHardeningUndo(name); ok || err == nil {
			t.Errorf("read %q = %+v, %v, %v; want an error", name, got, ok, err)
		}
		if err := deleteHardeningUndo(name); err == nil {
			t.Errorf("delete %q succeeded", name)
		}
	}
	// A write that got as far as a path would have created the directory.
	if entries, err := os.ReadDir(filepath.Dir(dir)); err != nil || len(entries) != 0 {
		t.Fatalf("created next to the store: %v, %v", entries, err)
	}
}

func TestHardeningUndoNamesIgnoresStrayFiles(t *testing.T) {
	dir := withHardeningUndoDir(t)
	recs := testHardeningUndoRecords()
	for _, rec := range []HardeningUndoRecord{recs[0], recs[7]} {
		if err := writeHardeningUndo(rec); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"not_a_fix.json", ".ssh_use_dns.tmp", "ssh_use_dns", "cp_ssl_only.json.bak", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(recs[0].Name+".json", filepath.Join(dir, "ssh_x11_forwarding.json")); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "external.json")
	if err := os.WriteFile(outside, []byte("not a record"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "ssh_use_dns.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "os_sysctl_aslr.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	want := []string{"cp_updates", "ssh_max_auth_tries"}
	before := undoTreeState(t, dir)
	if names, err := HardeningUndoNames(); err != nil || !slices.Equal(names, want) {
		t.Fatalf("names = %v, %v; want %v", names, err, want)
	}
	if after := undoTreeState(t, dir); !maps.Equal(before, after) {
		t.Fatalf("listing changed records: before %v, after %v", before, after)
	}
}
