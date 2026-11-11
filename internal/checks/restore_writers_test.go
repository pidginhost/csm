package checks

import (
	"context"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

type fakeProc struct {
	ppid int
	uid  string
	exe  string
	tty  int
	// start is the process start in clock ticks since boot.
	start int64
}

// procTable is a /proc with several processes. Every process started long
// before the uptime it reports, so start-time checks pass unless a test says
// otherwise.
type procTable struct {
	mockOS
	procs  map[int]fakeProc
	uptime float64
}

func (m *procTable) proc(name string) (fakeProc, bool) {
	parts := strings.Split(name, "/")
	if len(parts) < 3 {
		return fakeProc{}, false
	}
	pid, err := strconv.Atoi(parts[2])
	if err != nil {
		return fakeProc{}, false
	}
	p, ok := m.procs[pid]
	return p, ok
}

func (m *procTable) ReadFile(name string) ([]byte, error) {
	if name == "/proc/uptime" {
		return []byte(strconv.FormatFloat(m.uptime, 'f', 2, 64) + " 0.00\n"), nil
	}
	p, ok := m.proc(name)
	if !ok {
		return nil, os.ErrNotExist
	}
	switch {
	case strings.HasSuffix(name, "/status"):
		return []byte("Name:\tproc\nUid:\t" + p.uid + "\t" + p.uid + "\t" + p.uid + "\t" + p.uid + "\n"), nil
	case strings.HasSuffix(name, "/stat"):
		fields := make([]string, 52)
		for i := range fields {
			fields[i] = "0"
		}
		fields[0], fields[1], fields[2] = "1", "(a (b) c)", "S"
		fields[3] = strconv.Itoa(p.ppid)
		fields[6] = strconv.Itoa(p.tty)
		fields[21] = strconv.FormatInt(p.start, 10)
		return []byte(strings.Join(fields, " ")), nil
	}
	return nil, os.ErrNotExist
}

func (m *procTable) Readlink(name string) (string, error) {
	p, ok := m.proc(name)
	if !ok || !strings.HasSuffix(name, "/exe") || p.exe == "" {
		return "", os.ErrNotExist
	}
	return p.exe, nil
}

func withProcTable(t *testing.T, procs map[int]fakeProc) *procTable {
	t.Helper()
	table := &procTable{procs: procs, uptime: 100000}
	withMockOS(t, table)
	return table
}

const (
	bashPath  = "/usr/bin/bash"
	curlPath  = "/usr/bin/curl"
	lsphpPath = "/opt/alt/php81/usr/bin/lsphp"
)

var restoreWrittenAt = time.Now()

// The incident shape: a web request started a bash loop, which outlived the
// request and was reparented to init. The loop writes the file itself.
func TestRestoreWriterChainStopsADetachedLoop(t *testing.T) {
	withProcTable(t, map[int]fakeProc{
		700: {ppid: 1, uid: "1001", exe: bashPath},
	})
	if got := RestoreWriterChain(700, restoreWrittenAt); !reflect.DeepEqual(got, []int{700}) {
		t.Fatalf("chain = %v, want the loop", got)
	}
}

// A loop that runs a downloader for each write: stopping only the writer
// leaves the loop to start another one.
func TestRestoreWriterChainIncludesTheLoopBehindAWriter(t *testing.T) {
	withProcTable(t, map[int]fakeProc{
		701: {ppid: 700, uid: "1001", exe: curlPath},
		700: {ppid: 1, uid: "1001", exe: bashPath},
	})
	if got := RestoreWriterChain(701, restoreWrittenAt); !reflect.DeepEqual(got, []int{701, 700}) {
		t.Fatalf("chain = %v, want writer then loop", got)
	}
}

// Started by a still-running request: the shell is stopped, the PHP worker
// that serves the site is not.
func TestRestoreWriterChainStopsAtThePHPWorker(t *testing.T) {
	withProcTable(t, map[int]fakeProc{
		701: {ppid: 700, uid: "1001", exe: bashPath},
		700: {ppid: 600, uid: "1001", exe: lsphpPath},
		600: {ppid: 1, uid: "1001", exe: lsphpPath},
	})
	if got := RestoreWriterChain(701, restoreWrittenAt); !reflect.DeepEqual(got, []int{701}) {
		t.Fatalf("chain = %v, want only the shell", got)
	}
}

// PHP code that loops inside a request writes the file from the worker.
func TestRestoreWriterChainStopsAPHPWorkerThatWritesItself(t *testing.T) {
	withProcTable(t, map[int]fakeProc{
		700: {ppid: 600, uid: "1001", exe: lsphpPath},
		600: {ppid: 1, uid: "1001", exe: lsphpPath},
	})
	if got := RestoreWriterChain(700, restoreWrittenAt); !reflect.DeepEqual(got, []int{700}) {
		t.Fatalf("chain = %v, want only the writing worker", got)
	}
}

func TestRestoreWriterChainAcceptsAWebServerOrigin(t *testing.T) {
	withProcTable(t, map[int]fakeProc{
		701: {ppid: 500, uid: "1001", exe: bashPath},
		500: {ppid: 1, uid: "99", exe: "/usr/local/lsws/bin/lshttpd"},
	})
	if got := RestoreWriterChain(701, restoreWrittenAt); !reflect.DeepEqual(got, []int{701}) {
		t.Fatalf("chain = %v, want the shell the web server started", got)
	}
}

// People and scheduled jobs are not stopped: their file is still handled,
// and an operator decides about the session.
func TestRestoreWriterChainLeavesSessionsAlone(t *testing.T) {
	cases := map[string]map[int]fakeProc{
		"terminal": {
			701: {ppid: 700, uid: "1001", exe: bashPath, tty: 34816},
			700: {ppid: 1, uid: "1001", exe: bashPath, tty: 34816},
		},
		"ssh command": {
			701: {ppid: 400, uid: "1001", exe: bashPath},
			400: {ppid: 300, uid: "1001", exe: "/usr/sbin/sshd"},
		},
		"cpanel file manager": {
			701: {ppid: 400, uid: "1001", exe: "/usr/bin/tar"},
			400: {ppid: 1, uid: "1001", exe: "/usr/local/cpanel/cpsrvd"},
		},
		"cron job": {
			701: {ppid: 700, uid: "1001", exe: bashPath},
			700: {ppid: 300, uid: "0", exe: "/usr/sbin/crond"},
		},
		"root writer": {
			701: {ppid: 1, uid: "0", exe: bashPath},
		},
		"writer gone": {},
		"unknown parent": {
			701: {ppid: 800, uid: "1001", exe: bashPath},
		},
	}
	for name, procs := range cases {
		t.Run(name, func(t *testing.T) {
			withProcTable(t, procs)
			if got := RestoreWriterChain(701, restoreWrittenAt); got != nil {
				t.Fatalf("chain = %v, want nothing to stop", got)
			}
		})
	}
}

// A writer number that a newer process took over after the write is not the
// writer.
func TestRestoreWriterChainRejectsARecycledPID(t *testing.T) {
	table := withProcTable(t, map[int]fakeProc{
		700: {ppid: 1, uid: "1001", exe: bashPath},
	})
	table.procs[700] = fakeProc{ppid: 1, uid: "1001", exe: bashPath, start: int64(table.uptime * 100)}
	if got := RestoreWriterChain(700, time.Now().Add(-time.Hour)); got != nil {
		t.Fatalf("chain = %v, want nothing for a process newer than the write", got)
	}
}

func restoreKillConfig() *config.Config {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.KillProcesses = true
	return cfg
}

// The loop is stopped before the writer, so it cannot start another one.
func TestAutoKillStopsRestoreWritersLoopFirst(t *testing.T) {
	withActionSink(t)
	calls := withSimulatedProcessSignal(t)
	withProcTable(t, map[int]fakeProc{
		701: {ppid: 700, uid: "1001", exe: curlPath},
		700: {ppid: 1, uid: "1001", exe: bashPath},
	})
	f := alert.Finding{Severity: alert.Critical, Check: RemovedFileRestoredCheck, Timestamp: time.Now(), WriterChain: []int{701, 700}}

	actions := AutoKillProcesses(context.Background(), restoreKillConfig(), []alert.Finding{f})

	if !reflect.DeepEqual(calls.signaled, []int{700, 701}) {
		t.Fatalf("signaled = %v, want loop then writer", calls.signaled)
	}
	if len(actions) != 2 {
		t.Fatalf("actions = %+v, want one per process", actions)
	}
}

// Kill-time checks still apply: a process that turned root or is a cPanel
// service by then is left alone.
func TestAutoKillRechecksRestoreWritersAtKillTime(t *testing.T) {
	withActionSink(t)
	calls := withSimulatedProcessSignal(t)
	withProcTable(t, map[int]fakeProc{
		701: {ppid: 1, uid: "0", exe: bashPath},
		702: {ppid: 1, uid: "1001", exe: "/usr/local/cpanel/cpsrvd"},
	})
	f := alert.Finding{Severity: alert.Critical, Check: RemovedFileRestoredCheck, Timestamp: time.Now(), WriterChain: []int{701, 702}}

	if actions := AutoKillProcesses(context.Background(), restoreKillConfig(), []alert.Finding{f}); len(actions) != 0 || len(calls.signaled) != 0 {
		t.Fatalf("actions = %+v signaled = %v, want nothing", actions, calls.signaled)
	}
}

func TestAutoKillLeavesRestoreWritersWhenKillIsOff(t *testing.T) {
	calls := withSimulatedProcessSignal(t)
	cfg := restoreKillConfig()
	cfg.AutoResponse.KillProcesses = false
	f := alert.Finding{Severity: alert.Critical, Check: RemovedFileRestoredCheck, Timestamp: time.Now(), WriterChain: []int{700}}

	if actions := AutoKillProcesses(context.Background(), cfg, []alert.Finding{f}); len(actions) != 0 || len(calls.requested) != 0 {
		t.Fatalf("kill_processes off still signaled: %+v %v", actions, calls.requested)
	}
}
