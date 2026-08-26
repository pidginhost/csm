package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type shortCageFSWriter struct {
	calls int
	wrote []string
}

type shortCageFSTerminatorWriter struct {
	calls int
}

func (w *shortCageFSTerminatorWriter) WriteString(value string) (int, error) {
	w.calls++
	if w.calls == 1 {
		return len(value) - 1, nil
	}
	return 0, nil
}

func (w *shortCageFSWriter) WriteString(value string) (int, error) {
	w.calls++
	w.wrote = append(w.wrote, value)
	if w.calls == 1 {
		return len(value) - 2, errors.New("short append")
	}
	return len(value), nil
}

func withCageFSMountPoints(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "cagefs.mp")
	if contents != "" {
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	oldPath := cagefsMountPointsPath
	cagefsMountPointsPath = path
	t.Cleanup(func() { cagefsMountPointsPath = oldPath })
	return path
}

func withPHPShieldRuntimePaths(t *testing.T) (eventDir, logPath string) {
	t.Helper()
	eventDir = filepath.Join(t.TempDir(), "csm-php-shield")
	logPath = filepath.Join(eventDir, "events.log")
	socketPath := filepath.Join(eventDir, "events.sock")
	oldDir, oldSocket, oldLog := phpShieldEventDir, phpShieldEventSocketPath, phpShieldEventLogPath
	phpShieldEventDir, phpShieldEventSocketPath, phpShieldEventLogPath = eventDir, socketPath, logPath
	t.Cleanup(func() {
		phpShieldEventDir, phpShieldEventSocketPath, phpShieldEventLogPath = oldDir, oldSocket, oldLog
	})
	return eventDir, logPath
}

func TestEnsurePHPShieldCageFSMountSkipsHostWithoutCageFS(t *testing.T) {
	path := withCageFSMountPoints(t, "")
	if err := ensurePHPShieldCageFSMount(); err != nil {
		t.Fatalf("no CageFS: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("mount-points file must not be created on a host without CageFS")
	}
}

func TestEnsurePHPShieldCageFSMountAddsEventDirWithoutRemounting(t *testing.T) {
	existing := "/var/lib/mysql\n/opt\n@/var/spool/cron,700\n"
	path := withCageFSMountPoints(t, existing)
	if err := ensurePHPShieldCageFSMount(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	if !strings.Contains(got, "\n"+phpShieldEventDir+"\n") {
		t.Errorf("event dir not added as its own shared-mount line:\n%s", got)
	}
	if !strings.HasPrefix(got, existing) {
		t.Errorf("existing vendor entries were not preserved:\n%s", got)
	}
}

func TestEnsurePHPShieldCageFSMountIsIdempotent(t *testing.T) {
	existing := "/var/lib/mysql\n" + phpShieldEventDir + "\n"
	path := withCageFSMountPoints(t, existing)
	if err := ensurePHPShieldCageFSMount(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != existing {
		t.Errorf("already-configured file changed: got %q want %q", got, existing)
	}
}

func TestEnsurePHPShieldCageFSMountSerializesConcurrentInstallers(t *testing.T) {
	path := withCageFSMountPoints(t, "/var/lib/mysql\n")
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- ensurePHPShieldCageFSMount()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(data), "\n"+phpShieldEventDir+"\n"); got != 1 {
		t.Fatalf("event mount entry count = %d, want 1:\n%s", got, data)
	}
}

func TestEnsurePHPShieldCageFSMountRejectsIncompatibleEntry(t *testing.T) {
	for _, entry := range []string{
		"@" + phpShieldEventDir + ",1733",
		"*" + phpShieldEventDir,
		"%" + phpShieldEventDir,
	} {
		t.Run(entry[:1], func(t *testing.T) {
			existing := "/var/lib/mysql\n" + entry + " # operator entry\n"
			path := withCageFSMountPoints(t, existing)
			err := ensurePHPShieldCageFSMount()
			if err == nil || !strings.Contains(err.Error(), "requires a shared-source mount") {
				t.Fatalf("error = %v, want incompatible-mount diagnostic", err)
			}
			data, readErr := os.ReadFile(path) // #nosec G304 -- test temp file
			if readErr != nil {
				t.Fatal(readErr)
			}
			if got := string(data); got != existing {
				t.Errorf("operator entry changed: got %q want %q", got, existing)
			}
		})
	}
}

func TestEnsurePHPShieldCageFSMountAcceptsReadOnlySharedSource(t *testing.T) {
	existing := "!" + phpShieldEventDir + " # socket remains connectable\n"
	path := withCageFSMountPoints(t, existing)
	if err := ensurePHPShieldCageFSMount(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != existing {
		t.Fatalf("read-only operator entry changed: %q", data)
	}
}

func TestEnsurePHPShieldCageFSMountRejectsMixedSharedAndPerUserEntries(t *testing.T) {
	existing := phpShieldEventDir + "\n@" + phpShieldEventDir + ",0711\n"
	withCageFSMountPoints(t, existing)
	err := ensurePHPShieldCageFSMount()
	if err == nil || !strings.Contains(err.Error(), "per-user") {
		t.Fatalf("mixed mount error = %v, want conflict", err)
	}
}

func TestEnsurePHPShieldRuntimePathsFailsOnIncompatibleCageFSMount(t *testing.T) {
	withPHPShieldRuntimePaths(t)
	withCageFSMountPoints(t, "@"+phpShieldEventDir+",0711\n")
	err := ensurePHPShieldRuntimePaths()
	if err == nil || !strings.Contains(err.Error(), "requires a shared-source mount") {
		t.Fatalf("error = %v, want incompatible CageFS mount failure", err)
	}
}

func TestCageFSMountForPathParsesExactSupportedForms(t *testing.T) {
	dir := "/var/log/csm-php-shield"
	tests := []struct {
		name     string
		contents string
		kind     cagefsMountKind
		found    bool
	}{
		{name: "shared with comment", contents: "  " + dir + "  # managed by operator", kind: cagefsMountShared, found: true},
		{name: "read only", contents: "! " + dir, kind: cagefsMountReadOnly, found: true},
		{name: "per user mode", contents: "@" + dir + ",1733 # private", kind: cagefsMountPerUser, found: true},
		{name: "split uid", contents: "*" + dir, kind: cagefsMountByUID, found: true},
		{name: "longer path", contents: dir + "-old", found: false},
		{name: "shorter path", contents: "/var/log/csm", found: false},
		{name: "comment only", contents: "# " + dir, found: false},
		{name: "plain comma is path", contents: dir + ",1733", found: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kind, found := cagefsMountForPath(tc.contents, dir)
			if found != tc.found || kind != tc.kind {
				t.Fatalf("got (%q, %t), want (%q, %t)", kind, found, tc.kind, tc.found)
			}
		})
	}
}

func TestEnsurePHPShieldRuntimePathsCreatesSocketDirAndPrivateArchive(t *testing.T) {
	mpPath := withCageFSMountPoints(t, "/var/lib/mysql\n")
	eventDir, logPath := withPHPShieldRuntimePaths(t)
	if err := ensurePHPShieldRuntimePaths(); err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		path   string
		perm   os.FileMode
		sticky bool
	}{
		{path: eventDir, perm: 0o711},
		{path: logPath, perm: 0o600},
	} {
		info, err := os.Stat(check.path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != check.perm {
			t.Errorf("%s mode = %o, want %o", check.path, got, check.perm)
		}
		if got := info.Mode()&os.ModeSticky != 0; got != check.sticky {
			t.Errorf("%s sticky = %t, want %t", check.path, got, check.sticky)
		}
	}
	data, err := os.ReadFile(mpPath) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), eventDir) {
		t.Errorf("event tree not registered with CageFS:\n%s", data)
	}
}

func TestEnsurePHPShieldEventLogRejectsPlantedSymlink(t *testing.T) {
	eventDir, logPath := withPHPShieldRuntimePaths(t)
	if err := os.Mkdir(eventDir, 0o733); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("do not follow"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, logPath); err != nil {
		t.Fatal(err)
	}
	if err := ensurePHPShieldEventLog(); err == nil {
		t.Fatal("planted event-log symlink was accepted")
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "do not follow" {
		t.Fatalf("symlink target changed: %q", data)
	}
}

func TestEnsurePHPShieldEventLogRejectsPlantedSocketPathFile(t *testing.T) {
	eventDir, _ := withPHPShieldRuntimePaths(t)
	if err := os.Mkdir(eventDir, 0o733); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(phpShieldEventSocketPath, []byte("planted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensurePHPShieldEventLog(); err == nil {
		t.Fatal("planted regular event-socket path was accepted")
	}
	data, err := os.ReadFile(phpShieldEventSocketPath)
	if err != nil || string(data) != "planted" {
		t.Fatalf("planted socket path changed: data=%q error=%v", data, err)
	}
}

func TestEnsurePHPShieldCageFSMountSeparatesUnterminatedVendorLine(t *testing.T) {
	path := withCageFSMountPoints(t, "/var/lib/mysql")
	if err := ensurePHPShieldCageFSMount(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); !strings.Contains(got, "/var/lib/mysql\n"+phpShieldEventDir+"\n") {
		t.Errorf("appended line merged with vendor entry: %q", got)
	}
}

func TestEnsurePHPShieldCageFSMountRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real-cagefs.mp")
	if err := os.WriteFile(target, []byte("/var/lib/mysql\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "cagefs.mp")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	oldPath := cagefsMountPointsPath
	cagefsMountPointsPath = link
	t.Cleanup(func() { cagefsMountPointsPath = oldPath })
	if err := ensurePHPShieldCageFSMount(); err == nil {
		t.Fatal("symlinked CageFS mount-points file was accepted")
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "/var/lib/mysql\n" {
		t.Fatalf("symlink target changed: data=%q error=%v", data, err)
	}
}

func TestAppendCageFSMountEntryTerminatesPartialWrite(t *testing.T) {
	w := &shortCageFSWriter{}
	err := appendCageFSMountEntry(w, "\n/var/log/csm-php-shield\n")
	if err == nil || !strings.Contains(err.Error(), "short append") {
		t.Fatalf("error = %v, want short-write error", err)
	}
	if len(w.wrote) != 2 || w.wrote[1] != "\n" {
		t.Fatalf("writes = %q, want partial record followed by terminator", w.wrote)
	}
}

func TestAppendCageFSMountEntryReportsShortTerminator(t *testing.T) {
	w := &shortCageFSTerminatorWriter{}
	err := appendCageFSMountEntry(w, "\n/var/log/csm-php-shield\n")
	if err == nil || !strings.Contains(err.Error(), "terminating partial entry") {
		t.Fatalf("error = %v, want terminator failure", err)
	}
}
