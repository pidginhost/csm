package checks

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// procMock answers the handful of procfs reads the kill guards make.
type procMock struct {
	mockOS
	uid       string
	exe       string
	uptime    float64
	startTick int64
	fds       map[string]string
	stats     map[string]os.FileInfo
	lstats    map[string]os.FileInfo
}

func (m *procMock) ReadFile(name string) ([]byte, error) {
	switch {
	case name == "/proc/uptime":
		return []byte(strconv.FormatFloat(m.uptime, 'f', 2, 64) + " 0.00\n"), nil
	case strings.HasSuffix(name, "/status"):
		return []byte("Name:\tworker\nUid:\t" + m.uid + "\t" + m.uid + "\t" + m.uid + "\t" + m.uid + "\n"), nil
	case strings.HasSuffix(name, "/stat"):
		fields := make([]string, 52)
		for i := range fields {
			fields[i] = "0"
		}
		fields[0], fields[1], fields[2] = "4242", "(worker (pool))", "S"
		fields[21] = strconv.FormatInt(m.startTick, 10)
		return []byte(strings.Join(fields, " ")), nil
	}
	return nil, os.ErrNotExist
}

func (m *procMock) ReadDir(name string) ([]os.DirEntry, error) {
	if !strings.HasSuffix(name, "/fd") {
		return nil, os.ErrNotExist
	}
	var out []os.DirEntry
	for path := range m.fds {
		out = append(out, fdDirEntry{name: filepath.Base(path)})
	}
	return out, nil
}

type fdDirEntry struct{ name string }

func (e fdDirEntry) Name() string               { return e.name }
func (e fdDirEntry) IsDir() bool                { return false }
func (e fdDirEntry) Type() fs.FileMode          { return fs.ModeSymlink }
func (e fdDirEntry) Info() (fs.FileInfo, error) { return nil, os.ErrNotExist }

func (m *procMock) Readlink(name string) (string, error) {
	if strings.HasSuffix(name, "/exe") {
		return m.exe, nil
	}
	if target, ok := m.fds[name]; ok {
		return target, nil
	}
	return "", os.ErrNotExist
}

func (m *procMock) Stat(name string) (os.FileInfo, error) {
	if info, ok := m.stats[name]; ok {
		return info, nil
	}
	return nil, os.ErrNotExist
}

func (m *procMock) Lstat(name string) (os.FileInfo, error) {
	if info, ok := m.lstats[name]; ok {
		return info, nil
	}
	return nil, os.ErrNotExist
}

// A PID is recycled freely on a busy host. Auto-kill acting on a finding whose
// PID now belongs to a process started later destroys an unrelated process.
func TestAutoKillProcesses_SkipsProcessStartedAfterTheFinding(t *testing.T) {
	withSimulatedProcessSignal(t)
	old := osFS
	osFS = &procMock{uid: "1001", exe: "/tmp/evil", uptime: 1_000, startTick: 50_000}
	t.Cleanup(func() { osFS = old })

	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.KillProcesses = true

	// The finding was raised at uptime 100; the process started at 500.
	f := alert.Finding{
		Severity:  alert.Critical,
		Check:     "suspicious_process",
		PID:       4242,
		Timestamp: time.Now().Add(-900 * time.Second),
	}
	if actions := AutoKillProcesses(context.Background(), cfg, []alert.Finding{f}); len(actions) != 0 {
		t.Errorf("killed a process that started after the finding: %+v", actions)
	}
}

func TestProcessStartedBefore(t *testing.T) {
	old := osFS
	osFS = &procMock{uid: "1001", exe: "/tmp/evil", uptime: 1_000, startTick: 10_000}
	t.Cleanup(func() { osFS = old })

	if !processStartedBefore("4242", time.Now().Add(-800*time.Second)) {
		t.Error("a process started before the finding must be killable")
	}
	if processStartedBefore("4242", time.Now().Add(-950*time.Second)) {
		t.Error("a process started after the finding must not be killable")
	}
}

func TestProcessStartedBeforeRejectsSubsecondRecycle(t *testing.T) {
	old := osFS
	osFS = &procMock{uptime: 1_000, startTick: 99_950}
	t.Cleanup(func() { osFS = old })

	if processStartedBefore("4242", time.Now().Add(-time.Second)) {
		t.Fatal("a PID recycled half a second after the finding was accepted")
	}
}

// The kill in fixKillAndQuarantine exists to release the file being
// quarantined. A PID that no longer references that file is not that process.
func TestProcessUsesFile(t *testing.T) {
	old := osFS
	target := filepath.Join(t.TempDir(), "evil.php")
	if err := os.WriteFile(target, []byte("malware"), 0o600); err != nil {
		t.Fatal(err)
	}
	targetInfo, err := os.Lstat(target)
	if err != nil {
		t.Fatal(err)
	}
	osFS = &procMock{
		uid:    "1001",
		exe:    "/usr/bin/php",
		fds:    map[string]string{"/proc/4242/fd/7": target},
		stats:  map[string]os.FileInfo{"/proc/4242/fd/7": targetInfo},
		lstats: map[string]os.FileInfo{target: targetInfo},
	}
	t.Cleanup(func() { osFS = old })

	if !processUsesFile("4242", target) {
		t.Error("a process holding the file open must be recognised")
	}
	if processUsesFile("4242", filepath.Join(t.TempDir(), "other.php")) {
		t.Error("a process not referencing the file was treated as using it")
	}
}

func TestProcessUsesFileComparesObjectIdentity(t *testing.T) {
	old := osFS
	dir := t.TempDir()
	target := filepath.Join(dir, "evil.php")
	alias := filepath.Join(dir, "alias.php")
	if err := os.WriteFile(target, []byte("malware"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, alias); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(target)
	if err != nil {
		t.Fatal(err)
	}
	osFS = &procMock{
		exe:    "/usr/bin/php",
		fds:    map[string]string{"/proc/4242/fd/7": alias},
		stats:  map[string]os.FileInfo{"/proc/4242/fd/7": info},
		lstats: map[string]os.FileInfo{target: info},
	}
	t.Cleanup(func() { osFS = old })

	if !processUsesFile("4242", target) {
		t.Fatal("a hard-link spelling of the same open file was not recognised")
	}
}

func TestProcessUsesFileRejectsDeletedObjectAtReusedPath(t *testing.T) {
	old := osFS
	dir := t.TempDir()
	target := filepath.Join(dir, "evil.php")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldInfo, statErr := os.Lstat(target)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if removeErr := os.Remove(target); removeErr != nil {
		t.Fatal(removeErr)
	}
	if writeErr := os.WriteFile(target, []byte("replacement"), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	newInfo, statErr := os.Lstat(target)
	if statErr != nil {
		t.Fatal(statErr)
	}
	osFS = &procMock{
		exe:    "/usr/bin/php",
		fds:    map[string]string{"/proc/4242/fd/7": target + " (deleted)"},
		stats:  map[string]os.FileInfo{"/proc/4242/fd/7": oldInfo},
		lstats: map[string]os.FileInfo{target: newInfo},
	}
	t.Cleanup(func() { osFS = old })

	if processUsesFile("4242", target) {
		t.Fatal("a descriptor for a deleted inode was confused with its path replacement")
	}
}

func TestProcessUsesFileIdentityRejectsProcessUsingReplacement(t *testing.T) {
	old := osFS
	dir := t.TempDir()
	target := filepath.Join(dir, "evil.php")
	replacement := filepath.Join(dir, "replacement.php")
	if err := os.WriteFile(target, []byte("malware"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(replacement, []byte("unrelated"), 0o600); err != nil {
		t.Fatal(err)
	}
	targetInfo, err := os.Lstat(target)
	if err != nil {
		t.Fatal(err)
	}
	replacementInfo, err := os.Lstat(replacement)
	if err != nil {
		t.Fatal(err)
	}
	osFS = &procMock{
		fds:   map[string]string{"/proc/4242/fd/7": replacement},
		stats: map[string]os.FileInfo{"/proc/4242/fd/7": replacementInfo},
	}
	t.Cleanup(func() { osFS = old })

	if processUsesFileIdentity(4242, targetInfo) {
		t.Fatal("a process using only a replacement object matched the pinned target")
	}
}

func TestFixKillAndQuarantineValidatesPathBeforeKill(t *testing.T) {
	oldFS := osFS
	oldRoots := fixQuarantineAllowedRoots
	oldKill := signalProcess
	target := filepath.Join(t.TempDir(), "outside.php")
	if err := os.WriteFile(target, []byte("malware"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(target)
	if err != nil {
		t.Fatal(err)
	}
	osFS = &procMock{
		uid:       "1001",
		fds:       map[string]string{"/proc/4242/fd/7": target},
		stats:     map[string]os.FileInfo{"/proc/4242/fd/7": info},
		lstats:    map[string]os.FileInfo{target: info},
		startTick: 1,
		uptime:    1,
	}
	fixQuarantineAllowedRoots = []string{"/allowed"}
	killCalled := false
	signalProcess = func(context.Context, int, syscall.Signal, func() error) error {
		killCalled = true
		return nil
	}
	t.Cleanup(func() {
		osFS = oldFS
		fixQuarantineAllowedRoots = oldRoots
		signalProcess = oldKill
	})

	result := fixKillAndQuarantine(context.Background(), target, "PID: 4242")
	if result.Success || !strings.Contains(result.Error, "outside the allowed remediation roots") {
		t.Fatalf("invalid target result = %+v", result)
	}
	if killCalled {
		t.Fatal("process was signalled before the target path was rejected")
	}
}

func TestFixKillAndQuarantineReportsKillWhenQuarantineFails(t *testing.T) {
	oldFS := osFS
	oldRoots := fixQuarantineAllowedRoots
	oldQuarantineDir := quarantineDir
	oldKill := signalProcess
	dir := t.TempDir()
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "evil.php")
	replacement := filepath.Join(dir, "replacement.php")
	if writeErr := os.WriteFile(target, []byte("malware"), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	if writeErr := os.WriteFile(replacement, []byte("replacement"), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	replacementInfo, err := os.Lstat(replacement)
	if err != nil {
		t.Fatal(err)
	}
	osFS = &procMock{
		uid:    "1001",
		fds:    map[string]string{"/proc/4242/fd/7": replacement},
		stats:  map[string]os.FileInfo{"/proc/4242/fd/7": replacementInfo},
		lstats: map[string]os.FileInfo{target: replacementInfo},
	}
	fixQuarantineAllowedRoots = []string{dir}
	quarantineDir = filepath.Join(dir, "quarantine")
	signalProcess = func(_ context.Context, _ int, _ syscall.Signal, verify func() error) error { return verify() }
	t.Cleanup(func() {
		osFS = oldFS
		fixQuarantineAllowedRoots = oldRoots
		quarantineDir = oldQuarantineDir
		signalProcess = oldKill
	})

	result := fixKillAndQuarantine(context.Background(), target, "PID: 4242")
	if result.Success || result.Error == "" {
		t.Fatalf("quarantine identity mismatch was not reported: %+v", result)
	}
	if !strings.Contains(result.Action, "killed PID 4242") ||
		!strings.Contains(result.Description, "Process killed") {
		t.Fatalf("successful kill was hidden by quarantine failure: %+v", result)
	}
}
