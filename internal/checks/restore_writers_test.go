package checks

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

type fakeProc struct {
	ppid        int
	uid         string
	credentials string
	exe         string
	tty         int
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
		credentials := p.credentials
		if credentials == "" {
			credentials = strings.Join([]string{p.uid, p.uid, p.uid, p.uid}, "\t")
		}
		return []byte("Name:\tproc\nUid:\t" + credentials + "\n"), nil
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
	f := alert.Finding{Severity: alert.Critical, Check: RemovedFileRestoredCheck, Timestamp: time.Now(), WriterObservedAt: time.Now(), WriterChain: []int{701, 700}}

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
	f := alert.Finding{Severity: alert.Critical, Check: RemovedFileRestoredCheck, Timestamp: time.Now(), WriterObservedAt: time.Now(), WriterChain: []int{701, 702}}

	if actions := AutoKillProcesses(context.Background(), restoreKillConfig(), []alert.Finding{f}); len(actions) != 0 || len(calls.signaled) != 0 {
		t.Fatalf("actions = %+v signaled = %v, want nothing", actions, calls.signaled)
	}
}

func TestAutoKillLeavesRestoreWritersWhenKillIsOff(t *testing.T) {
	calls := withSimulatedProcessSignal(t)
	cfg := restoreKillConfig()
	cfg.AutoResponse.KillProcesses = false
	f := alert.Finding{Severity: alert.Critical, Check: RemovedFileRestoredCheck, Timestamp: time.Now(), WriterObservedAt: time.Now(), WriterChain: []int{700}}

	if actions := AutoKillProcesses(context.Background(), cfg, []alert.Finding{f}); len(actions) != 0 || len(calls.requested) != 0 {
		t.Fatalf("kill_processes off still signaled: %+v %v", actions, calls.requested)
	}
}

func TestRestoreWriterChainRejectsUnsafeOrigins(t *testing.T) {
	cases := map[string]map[int]fakeProc{
		"unknown zero parent": {701: {ppid: 0, uid: "1001", exe: bashPath}},
		"negative parent":     {701: {ppid: -1, uid: "1001", exe: bashPath}},
		"PHP from SSH": {
			701: {ppid: 700, uid: "1001", exe: lsphpPath},
			700: {ppid: 1, uid: "1001", exe: "/usr/sbin/sshd"},
		},
		"shell below PHP from cron": {
			701: {ppid: 700, uid: "1001", exe: bashPath},
			700: {ppid: 600, uid: "1001", exe: lsphpPath},
			600: {ppid: 1, uid: "0", exe: "/usr/sbin/crond"},
		},
		"PHP with unknown parent": {701: {ppid: 700, uid: "1001", exe: lsphpPath}},
		"web parent with unreadable credentials": {
			701: {ppid: 700, uid: "1001", exe: bashPath},
			700: {ppid: 1, uid: "", exe: "/usr/sbin/httpd"},
		},
		"web parent with terminal": {
			701: {ppid: 700, uid: "1001", exe: bashPath},
			700: {ppid: 1, uid: "99", exe: "/usr/sbin/httpd", tty: 34816},
		},
		"web parent from cPanel": {
			701: {ppid: 700, uid: "1001", exe: bashPath},
			700: {ppid: 600, uid: "99", exe: "/usr/sbin/httpd"},
			600: {ppid: 1, uid: "1001", exe: "/usr/local/cpanel/cpsrvd"},
		},
		"web parent with unknown parent": {
			701: {ppid: 700, uid: "1001", exe: bashPath},
			700: {ppid: 600, uid: "99", exe: "/usr/sbin/httpd"},
		},
		"service under sbin":       {701: {ppid: 1, uid: "1001", exe: "/sbin/service"}},
		"web service under bin":    {701: {ppid: 1, uid: "1001", exe: "/usr/bin/nginx"}},
		"system service under bin": {701: {ppid: 1, uid: "1001", exe: "/usr/bin/dbus-daemon"}},
		"panel service under opt":  {701: {ppid: 1, uid: "1001", exe: "/opt/cpanel/bin/service"}},
		"panel PHP":                {701: {ppid: 1, uid: "1001", exe: "/usr/local/cpanel/3rdparty/bin/php-fpm"}},
	}
	for name, procs := range cases {
		t.Run(name, func(t *testing.T) {
			withProcTable(t, procs)
			if got := RestoreWriterChain(701, time.Now()); got != nil {
				t.Fatalf("unsafe chain accepted: %v", got)
			}
		})
	}
}

func TestAutoKillRestoreRechecksTerminalAndPHPParents(t *testing.T) {
	for _, transition := range []string{"terminal", "PHP parent", "SSH origin"} {
		t.Run(transition, func(t *testing.T) {
			withActionSink(t)
			calls := withSimulatedProcessSignal(t)
			table := withProcTable(t, map[int]fakeProc{
				701: {ppid: 700, uid: "1001", exe: curlPath},
				700: {ppid: 1, uid: "1001", exe: bashPath},
			})
			f := alert.Finding{Severity: alert.Critical, Check: RemovedFileRestoredCheck, Timestamp: time.Now(), WriterObservedAt: time.Now(), WriterChain: RestoreWriterChain(701, time.Now())}
			pinned := signalProcess
			signalProcess = func(ctx context.Context, pid int, sig syscall.Signal, verify func() error) error {
				return pinned(ctx, pid, sig, func() error {
					p := table.procs[700]
					switch transition {
					case "terminal":
						p.tty = 34816
					case "PHP parent":
						p.exe = lsphpPath
					case "SSH origin":
						p.ppid = 600
						table.procs[600] = fakeProc{ppid: 1, uid: "1001", exe: "/usr/sbin/sshd"}
					}
					table.procs[700] = p
					return verify()
				})
			}
			actions := AutoKillProcesses(context.Background(), restoreKillConfig(), []alert.Finding{f})
			var want []int
			if transition == "PHP parent" {
				want = []int{701}
			}
			if !reflect.DeepEqual(calls.signaled, want) || len(actions) != len(want) {
				t.Fatalf("signaled=%v actions=%v, want %v", calls.signaled, actions, want)
			}
		})
	}
}

func TestAutoKillRestoreRejectsReuseBeforeFinding(t *testing.T) {
	sink := withActionSink(t)
	calls := withSimulatedProcessSignal(t)
	table := withProcTable(t, map[int]fakeProc{700: {ppid: 1, uid: "1001", exe: bashPath}})
	seen := time.Now().Add(-time.Minute)
	f := alert.Finding{Severity: alert.Critical, Check: RemovedFileRestoredCheck,
		Timestamp: time.Now(), WriterObservedAt: seen, WriterChain: RestoreWriterChain(700, seen)}
	if !reflect.DeepEqual(f.WriterChain, []int{700}) {
		t.Fatalf("capture = %v", f.WriterChain)
	}
	// Reuse after the write but before the finding is timestamped.
	p := table.procs[700]
	p.start = int64((table.uptime - 30) * procClockTicks)
	table.procs[700] = p
	if actions := AutoKillProcesses(context.Background(), restoreKillConfig(), []alert.Finding{f}); len(actions) != 0 || len(calls.signaled) != 0 {
		t.Fatalf("signaled replacement: actions=%v signals=%v", actions, calls.signaled)
	}
	if len(sink.records) != 1 || sink.records[0].Result != actionlog.Refused {
		t.Fatalf("missing refusal: %+v", sink.records)
	}
}

func TestRestoreWriterChainRejectsPrivilegedCredentials(t *testing.T) {
	for _, creds := range []string{"0 1001 1001 1001", "1001 0 1001 1001", "1001 1001 0 1001", "1001 1001 1001 0", "1001 1001", "1001 x 1001 1001"} {
		t.Run(creds, func(t *testing.T) {
			withActionSink(t)
			calls := withSimulatedProcessSignal(t)
			table := withProcTable(t, map[int]fakeProc{700: {ppid: 1, uid: "1001", exe: bashPath}})
			f := alert.Finding{Severity: alert.Critical, Check: RemovedFileRestoredCheck,
				Timestamp: time.Now(), WriterObservedAt: time.Now(), WriterChain: RestoreWriterChain(700, time.Now())}
			p := table.procs[700]
			p.credentials = creds
			table.procs[700] = p
			if chain := RestoreWriterChain(700, time.Now()); chain != nil {
				t.Fatalf("unsafe capture: %v", chain)
			}
			if actions := AutoKillProcesses(context.Background(), restoreKillConfig(), []alert.Finding{f}); len(actions) != 0 || len(calls.signaled) != 0 {
				t.Fatalf("unsafe kill: actions=%v signals=%v", actions, calls.signaled)
			}
		})
	}
}

func TestRestoreWriterChainBoundsTheEntireAncestry(t *testing.T) {
	for _, webBoundary := range []bool{false, true} {
		procs := make(map[int]fakeProc)
		for i := 0; i <= maxRestoreChainDepth; i++ {
			procs[700+i] = fakeProc{ppid: 701 + i, uid: "1001", exe: bashPath}
		}
		procs[700+maxRestoreChainDepth] = fakeProc{ppid: 1, uid: "1001", exe: bashPath}
		if webBoundary {
			procs[701] = fakeProc{ppid: 702, uid: "1001", exe: lsphpPath}
		}
		withProcTable(t, procs)
		if chain := RestoreWriterChain(700, time.Now()); chain != nil {
			t.Fatalf("over-depth chain accepted: %v", chain)
		}
	}
}

func TestRestoreWriterChainNeverIncludesInit(t *testing.T) {
	withProcTable(t, map[int]fakeProc{1: {ppid: 1, uid: "1001", exe: bashPath}})
	if chain := RestoreWriterChain(1, time.Now()); chain != nil {
		t.Fatalf("init accepted: %v", chain)
	}
}

func TestAutoKillRestoreSurvivesWriterExitAndReparenting(t *testing.T) {
	withActionSink(t)
	calls := withSimulatedProcessSignal(t)
	table := withProcTable(t, map[int]fakeProc{
		701: {ppid: 700, uid: "1001", exe: curlPath},
		700: {ppid: 600, uid: "1001", exe: bashPath},
		600: {ppid: 1, uid: "1001", exe: bashPath},
	})
	f := alert.Finding{Severity: alert.Critical, Check: RemovedFileRestoredCheck,
		Timestamp: time.Now(), WriterObservedAt: time.Now(), WriterChain: RestoreWriterChain(701, time.Now())}
	delete(table.procs, 701)
	pinned := signalProcess
	signalProcess = func(ctx context.Context, pid int, sig syscall.Signal, verify func() error) error {
		err := pinned(ctx, pid, sig, verify)
		if err == nil {
			delete(table.procs, pid)
			for child, proc := range table.procs {
				if proc.ppid == pid {
					proc.ppid = 1
					table.procs[child] = proc
				}
			}
		}
		return err
	}
	actions := AutoKillProcesses(context.Background(), restoreKillConfig(), []alert.Finding{f})
	if !reflect.DeepEqual(calls.signaled, []int{600, 700}) || len(actions) != 2 {
		t.Fatalf("actions=%v signals=%v", actions, calls.signaled)
	}
}

func TestRestoreWriterEvidenceIsNotReplayed(t *testing.T) {
	f := alert.Finding{WriterChain: []int{700}, WriterObservedAt: time.Now()}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var replay alert.Finding
	if err := json.Unmarshal(data, &replay); err != nil {
		t.Fatal(err)
	}
	if len(replay.WriterChain) != 0 || !replay.WriterObservedAt.IsZero() {
		t.Fatalf("process evidence persisted: %s", data)
	}
}

func TestAutoKillLegacyPolicyAndActionText(t *testing.T) {
	for _, check := range []string{"fake_kernel_thread", "suspicious_process", "php_suspicious_execution"} {
		for _, exe := range []string{"/tmp/evil", bashPath, "/usr/local/cpanel/cpsrvd"} {
			t.Run(check+exe, func(t *testing.T) {
				sink := withActionSink(t)
				calls := withSimulatedProcessSignal(t)
				withProcTable(t, map[int]fakeProc{700: {ppid: 1, uid: "1001", exe: exe}})
				f := alert.Finding{Severity: alert.Critical, Check: check, PID: 700, Message: "original", Timestamp: time.Now()}
				actions := AutoKillProcesses(context.Background(), restoreKillConfig(), []alert.Finding{f})
				wantResult := actionlog.Refused
				if exe == "/tmp/evil" {
					wantResult = actionlog.Applied
					if !reflect.DeepEqual(calls.signaled, []int{700}) || len(actions) != 1 {
						t.Fatalf("actions=%v signals=%v", actions, calls.signaled)
					}
					if actions[0].Message != "AUTO-KILL: Process 700 killed (was: "+check+")" || actions[0].Details != "Original finding: original\nProcess: /tmp/evil (UID: 1001)" {
						t.Fatalf("action text changed: %+v", actions[0])
					}
				} else if len(actions) != 0 || len(calls.signaled) != 0 {
					t.Fatalf("safe exe killed: %v", actions)
				}
				if len(sink.records) != 1 {
					t.Fatalf("records=%+v", sink.records)
				}
				rec := sink.records[0]
				if rec.Op != "respond.kill_process" || rec.Target != "pid 700" || rec.ActorDetail != exe || rec.Reason != check || rec.Result != wantResult || rec.FindingID != alert.FindingID(f) {
					t.Fatalf("record changed: %+v", rec)
				}
			})
		}
	}
}

func TestRestoreWriterChainRejectsPHPWriterOwnerChange(t *testing.T) {
	table := withProcTable(t, map[int]fakeProc{700: {ppid: 1, uid: "1001", exe: lsphpPath}})
	reads := 0
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/proc/700/status" {
				reads++
				if reads > 1 {
					p := table.procs[700]
					p.uid = "0"
					table.procs[700] = p
				}
			}
			return table.ReadFile(name)
		},
		readlink: table.Readlink,
	})
	if chain := RestoreWriterChain(700, time.Now()); chain != nil {
		t.Fatalf("root PHP writer accepted: %v", chain)
	}
}

func TestAutoKillRestoreParentExecsPHPDuringVerification(t *testing.T) {
	withActionSink(t)
	calls := withSimulatedProcessSignal(t)
	table := withProcTable(t, map[int]fakeProc{
		701: {ppid: 700, uid: "1001", exe: curlPath},
		700: {ppid: 1, uid: "1001", exe: bashPath},
	})
	f := alert.Finding{Severity: alert.Critical, Check: RemovedFileRestoredCheck,
		Timestamp: time.Now(), WriterObservedAt: time.Now(), WriterChain: RestoreWriterChain(701, time.Now())}
	withMockOS(t, &mockOS{
		readFile: table.ReadFile,
		readlink: func(name string) (string, error) {
			exe, err := table.Readlink(name)
			if name == "/proc/700/exe" {
				p := table.procs[700]
				p.exe = lsphpPath
				table.procs[700] = p
			}
			return exe, err
		},
	})
	actions := AutoKillProcesses(context.Background(), restoreKillConfig(), []alert.Finding{f})
	if !reflect.DeepEqual(calls.signaled, []int{701}) || len(actions) != 1 {
		t.Fatalf("PHP parent killed: actions=%v signals=%v", actions, calls.signaled)
	}
}

func TestRestoreWriterChainProtectsServiceLocations(t *testing.T) {
	for _, exe := range []string{
		"/usr/local/sbin/service", "/usr/lib/openssh/sftp-server", "/lib/service/worker",
		"/usr/bin/redis-server", "/usr/bin/valkey-server", "/usr/bin/memcached",
		"/usr/bin/mysqld", "/usr/bin/mariadbd", "/usr/bin/postgres",
	} {
		t.Run(exe, func(t *testing.T) {
			withProcTable(t, map[int]fakeProc{700: {ppid: 1, uid: "1001", exe: exe}})
			if chain := RestoreWriterChain(700, time.Now()); chain != nil {
				t.Fatalf("service selected: %v", chain)
			}
		})
	}
}

func TestAutoKillRestorePHPWriterOnly(t *testing.T) {
	for _, exe := range []string{lsphpPath, "/usr/sbin/php-fpm", "/usr/local/lsws/lsphp83/bin/lsphp", "/opt/cpanel/ea-php83/root/usr/sbin/php-fpm"} {
		t.Run(exe, func(t *testing.T) {
			withActionSink(t)
			calls := withSimulatedProcessSignal(t)
			withProcTable(t, map[int]fakeProc{
				700: {ppid: 600, uid: "1001", exe: exe},
				600: {ppid: 1, uid: "0", exe: "/usr/sbin/php-fpm"},
			})
			f := alert.Finding{Severity: alert.Critical, Check: RemovedFileRestoredCheck,
				Timestamp: time.Now(), WriterObservedAt: time.Now(), WriterChain: RestoreWriterChain(700, time.Now())}
			if !reflect.DeepEqual(f.WriterChain, []int{700}) {
				t.Fatalf("chain=%v", f.WriterChain)
			}
			actions := AutoKillProcesses(context.Background(), restoreKillConfig(), []alert.Finding{f})
			if !reflect.DeepEqual(calls.signaled, []int{700}) || len(actions) != 1 {
				t.Fatalf("actions=%v signals=%v", actions, calls.signaled)
			}
		})
	}
}
