package checks

import (
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	boot      int64
	startTick int64
	fds       map[string]string
}

func (m *procMock) ReadFile(name string) ([]byte, error) {
	switch {
	case name == "/proc/stat":
		return []byte("cpu 1 2 3\nbtime " + strconv.FormatInt(m.boot, 10) + "\n"), nil
	case strings.HasSuffix(name, "/status"):
		return []byte("Name:\tworker\nUid:\t" + m.uid + "\t" + m.uid + "\n"), nil
	case strings.HasSuffix(name, "/stat"):
		fields := make([]string, 52)
		for i := range fields {
			fields[i] = "0"
		}
		fields[0], fields[1], fields[2] = "4242", "(worker)", "S"
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

// A PID is recycled freely on a busy host. Auto-kill acting on a finding whose
// PID now belongs to a process started later destroys an unrelated process.
func TestAutoKillProcesses_SkipsProcessStartedAfterTheFinding(t *testing.T) {
	old := osFS
	osFS = &procMock{uid: "1001", exe: "/tmp/evil", boot: 1_000_000, startTick: 50_000}
	t.Cleanup(func() { osFS = old })

	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.KillProcesses = true

	// Finding raised 100 seconds after boot; the process started at 500.
	f := alert.Finding{
		Severity:  alert.Critical,
		Check:     "suspicious_process",
		PID:       4242,
		Timestamp: time.Unix(1_000_100, 0),
	}
	if actions := AutoKillProcesses(cfg, []alert.Finding{f}); len(actions) != 0 {
		t.Errorf("killed a process that started after the finding: %+v", actions)
	}
}

func TestProcessStartedBefore(t *testing.T) {
	old := osFS
	osFS = &procMock{uid: "1001", exe: "/tmp/evil", boot: 1_000_000, startTick: 10_000}
	t.Cleanup(func() { osFS = old })

	if !processStartedBefore("4242", time.Unix(1_000_200, 0)) {
		t.Error("a process started before the finding must be killable")
	}
	if processStartedBefore("4242", time.Unix(1_000_050, 0)) {
		t.Error("a process started after the finding must not be killable")
	}
}

// The kill in fixKillAndQuarantine exists to release the file being
// quarantined. A PID that no longer references that file is not that process.
func TestProcessUsesFile(t *testing.T) {
	old := osFS
	target := filepath.Join(t.TempDir(), "evil.php")
	osFS = &procMock{
		uid: "1001",
		exe: "/usr/bin/php",
		fds: map[string]string{"/proc/4242/fd/7": target},
	}
	t.Cleanup(func() { osFS = old })

	if !processUsesFile("4242", target) {
		t.Error("a process holding the file open must be recognised")
	}
	if processUsesFile("4242", filepath.Join(t.TempDir(), "other.php")) {
		t.Error("a process not referencing the file was treated as using it")
	}
}
