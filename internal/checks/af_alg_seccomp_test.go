package checks

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeFS captures filesystem mutations so tests can assert what was
// written, what was removed, and what directories were created without
// touching the real filesystem.
type fakeFS struct {
	exists  map[string]bool        // path -> present
	written map[string][]byte      // path -> contents written
	mkdirs  map[string]os.FileMode // dir path -> perm at MkdirAll time
	removed []string               // paths passed to Remove
}

func newFakeFS() *fakeFS {
	return &fakeFS{
		exists:  make(map[string]bool),
		written: make(map[string][]byte),
		mkdirs:  make(map[string]os.FileMode),
	}
}

func (f *fakeFS) attachToMockOS() *mockOS {
	return &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if f.exists[name] {
				return fakeFileInfo{name: filepath.Base(name), size: 1}, nil
			}
			return nil, os.ErrNotExist
		},
		writeFile: func(name string, data []byte, perm os.FileMode) error {
			f.written[name] = append([]byte(nil), data...)
			f.exists[name] = true
			return nil
		},
		mkdirAll: func(path string, perm os.FileMode) error {
			f.mkdirs[path] = perm
			return nil
		},
		remove: func(name string) error {
			if !f.exists[name] {
				return os.ErrNotExist
			}
			delete(f.exists, name)
			f.removed = append(f.removed, name)
			return nil
		},
	}
}

// systemctlMock returns a runAllowNonZero handler that reports unit
// existence based on the given allowlist and counts daemon-reload /
// reload-or-restart invocations the production code emits.
type systemctlMock struct {
	exists           map[string]bool
	daemonReloads    int
	reloadOrRestarts []string
}

func (s *systemctlMock) handler() func(string, ...string) ([]byte, error) {
	// Production code routes both `list-unit-files` (existence check) and
	// `reload-or-restart` through cmdExec.RunAllowNonZero, so this single
	// handler covers both. `daemon-reload` goes through cmdExec.Run and
	// is handled by runHandler() below.
	return func(name string, args ...string) ([]byte, error) {
		if name != "systemctl" {
			return nil, nil
		}
		if len(args) >= 2 && args[0] == "list-unit-files" {
			if s.exists[args[1]] {
				return []byte(args[1] + " enabled\n"), nil
			}
			return nil, nil
		}
		if len(args) >= 2 && args[0] == "reload-or-restart" {
			s.reloadOrRestarts = append(s.reloadOrRestarts, args[1])
			return nil, nil
		}
		return nil, nil
	}
}

func (s *systemctlMock) runHandler() func(string, ...string) ([]byte, error) {
	return func(name string, args ...string) ([]byte, error) {
		if name == "systemctl" && len(args) == 1 && args[0] == "daemon-reload" {
			s.daemonReloads++
			return nil, nil
		}
		return nil, nil
	}
}

func TestApplyAFAlgSeccompDropIns_WritesCorrectContent(t *testing.T) {
	fs := newFakeFS()
	withMockOS(t, fs.attachToMockOS())

	sc := &systemctlMock{exists: map[string]bool{
		"php-fpm.service": true,
		"crond.service":   true,
	}}
	withMockCmd(t, &mockCmd{
		runAllowNonZero: sc.handler(),
		run:             sc.runHandler(),
	})

	written, err := ApplyAFAlgSeccompDropIns()
	if err != nil {
		t.Fatalf("ApplyAFAlgSeccompDropIns: %v", err)
	}
	if len(written) != 2 {
		t.Fatalf("wrote drop-ins for %d units, want 2; got %v", len(written), written)
	}
	expectPath := func(unit string) string {
		return filepath.Join("/etc/systemd/system", unit+".d", SeccompDropInBaseName)
	}
	for _, u := range []string{"php-fpm.service", "crond.service"} {
		path := expectPath(u)
		body, ok := fs.written[path]
		if !ok {
			t.Errorf("expected drop-in for %s at %s", u, path)
			continue
		}
		if !strings.Contains(string(body), "RestrictAddressFamilies=~AF_ALG") {
			t.Errorf("drop-in for %s missing the RestrictAddressFamilies directive: %q", u, string(body))
		}
		if !strings.Contains(string(body), "managed by CSM") {
			t.Errorf("drop-in for %s should self-identify as CSM-managed for future operators", u)
		}
	}
	if sc.daemonReloads != 1 {
		t.Errorf("expected exactly one systemctl daemon-reload, got %d", sc.daemonReloads)
	}
	if len(sc.reloadOrRestarts) != 2 {
		t.Errorf("expected reload-or-restart for both units, got %v", sc.reloadOrRestarts)
	}
}

func TestApplyAFAlgSeccompDropIns_SkipsAlreadyCovered(t *testing.T) {
	fs := newFakeFS()
	// Pre-populate the file as if a prior CSM run already wrote it.
	covered := filepath.Join("/etc/systemd/system", "crond.service.d", SeccompDropInBaseName)
	fs.exists[covered] = true
	fs.written[covered] = []byte("(pre-existing)")

	withMockOS(t, fs.attachToMockOS())
	sc := &systemctlMock{exists: map[string]bool{"crond.service": true}}
	withMockCmd(t, &mockCmd{
		runAllowNonZero: sc.handler(),
		run:             sc.runHandler(),
	})

	written, err := ApplyAFAlgSeccompDropIns()
	if err != nil {
		t.Fatalf("ApplyAFAlgSeccompDropIns: %v", err)
	}
	if len(written) != 0 {
		t.Errorf("expected no new writes when drop-in already present; got %v", written)
	}
	// Idempotent re-run should not touch systemd.
	if sc.daemonReloads != 0 {
		t.Errorf("idempotent re-run must NOT call daemon-reload; got %d", sc.daemonReloads)
	}
	if len(sc.reloadOrRestarts) != 0 {
		t.Errorf("idempotent re-run must NOT restart units; got %v", sc.reloadOrRestarts)
	}
	// The pre-existing file must NOT have been overwritten.
	if string(fs.written[covered]) != "(pre-existing)" {
		t.Error("idempotent re-run must NOT overwrite an existing drop-in")
	}
}

func TestApplyAFAlgSeccompDropIns_SkipsUnitsNotInstalled(t *testing.T) {
	fs := newFakeFS()
	withMockOS(t, fs.attachToMockOS())
	// No units exist in systemctl's view.
	sc := &systemctlMock{exists: map[string]bool{}}
	withMockCmd(t, &mockCmd{
		runAllowNonZero: sc.handler(),
		run:             sc.runHandler(),
	})

	written, err := ApplyAFAlgSeccompDropIns()
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(written) != 0 {
		t.Errorf("nothing should have been written when no candidate units exist; got %v", written)
	}
}

func TestRemoveAFAlgSeccompDropIns_RemovesAllAndRestartsUnits(t *testing.T) {
	fs := newFakeFS()
	for _, u := range []string{"php-fpm.service", "crond.service"} {
		fs.exists[filepath.Join("/etc/systemd/system", u+".d", SeccompDropInBaseName)] = true
	}
	withMockOS(t, fs.attachToMockOS())
	sc := &systemctlMock{exists: map[string]bool{
		"php-fpm.service": true,
		"crond.service":   true,
	}}
	withMockCmd(t, &mockCmd{
		runAllowNonZero: sc.handler(),
		run:             sc.runHandler(),
	})

	removed, err := RemoveAFAlgSeccompDropIns()
	if err != nil {
		t.Fatalf("RemoveAFAlgSeccompDropIns: %v", err)
	}
	if len(removed) != 2 {
		t.Errorf("expected 2 removed, got %v", removed)
	}
	if sc.daemonReloads != 1 {
		t.Errorf("expected exactly one daemon-reload, got %d", sc.daemonReloads)
	}
	if len(sc.reloadOrRestarts) != 2 {
		t.Errorf("expected restart for each removed unit, got %v", sc.reloadOrRestarts)
	}
}

func TestRemoveAFAlgSeccompDropIns_NoOpWhenNothingPresent(t *testing.T) {
	fs := newFakeFS()
	withMockOS(t, fs.attachToMockOS())
	sc := &systemctlMock{exists: map[string]bool{}}
	withMockCmd(t, &mockCmd{
		runAllowNonZero: sc.handler(),
		run:             sc.runHandler(),
	})

	removed, err := RemoveAFAlgSeccompDropIns()
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(removed) != 0 {
		t.Errorf("nothing to remove yet got %v", removed)
	}
	if sc.daemonReloads != 0 {
		t.Errorf("must NOT touch systemd when there is nothing to remove")
	}
}

func TestSummarizeAFAlgSeccompCoverage_PartitionsCorrectly(t *testing.T) {
	fs := newFakeFS()
	covered := filepath.Join("/etc/systemd/system", "lshttpd.service.d", SeccompDropInBaseName)
	fs.exists[covered] = true
	withMockOS(t, fs.attachToMockOS())
	sc := &systemctlMock{exists: map[string]bool{
		"lshttpd.service": true,
		"crond.service":   true,
	}}
	withMockCmd(t, &mockCmd{
		runAllowNonZero: sc.handler(),
		run:             sc.runHandler(),
	})

	got := SummarizeAFAlgSeccompCoverage()
	wantCovered := []string{"lshttpd.service"}
	wantUncovered := []string{"crond.service"}
	if !sliceEqual(got.Covered, wantCovered) {
		t.Errorf("Covered = %v, want %v", got.Covered, wantCovered)
	}
	if !sliceEqual(got.Uncovered, wantUncovered) {
		t.Errorf("Uncovered = %v, want %v", got.Uncovered, wantUncovered)
	}
	// Every other candidate should be in NotInstalled.
	if len(got.NotInstalled) != len(afAlgSeccompCandidateUnits)-2 {
		t.Errorf("NotInstalled = %d entries, want %d (all candidates minus the two existing)",
			len(got.NotInstalled), len(afAlgSeccompCandidateUnits)-2)
	}
}

func TestApplyAFAlgSeccompDropIns_PropagatesWriteFailure(t *testing.T) {
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		mkdirAll: func(path string, perm os.FileMode) error {
			return errors.New("readonly filesystem")
		},
	})
	withMockCmd(t, &mockCmd{
		runAllowNonZero: (&systemctlMock{exists: map[string]bool{"php-fpm.service": true}}).handler(),
	})

	_, err := ApplyAFAlgSeccompDropIns()
	if err == nil {
		t.Fatal("expected write failure to propagate")
	}
	if !strings.Contains(err.Error(), "php-fpm.service") {
		t.Errorf("error should name the unit it failed on; got %v", err)
	}
}

func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
