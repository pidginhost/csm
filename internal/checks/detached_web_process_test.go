package checks

import (
	"context"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// webProcTable adds open descriptors and the host's unix socket table to the
// fake /proc.
type webProcTable struct {
	*procTable
	fds  map[int][]string
	unix string
}

func (m *webProcTable) ReadFile(name string) ([]byte, error) {
	if name == "/proc/net/unix" {
		return []byte(m.unix), nil
	}
	return m.procTable.ReadFile(name)
}

func (m *webProcTable) Glob(pattern string) ([]string, error) {
	if pattern == "/proc/[0-9]*" {
		var out []string
		for pid := range m.procs {
			out = append(out, "/proc/"+strconv.Itoa(pid))
		}
		sort.Strings(out)
		return out, nil
	}
	if strings.HasPrefix(pattern, "/proc/") && strings.HasSuffix(pattern, "/fd/*") {
		pid, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(pattern, "/proc/"), "/fd/*"))
		if err != nil {
			return nil, err
		}
		var out []string
		for i := range m.fds[pid] {
			out = append(out, "/proc/"+strconv.Itoa(pid)+"/fd/"+strconv.Itoa(i))
		}
		return out, nil
	}
	return nil, nil
}

func (m *webProcTable) Readlink(name string) (string, error) {
	if i := strings.Index(name, "/fd/"); i >= 0 {
		pid, err1 := strconv.Atoi(strings.TrimPrefix(name[:i], "/proc/"))
		fd, err2 := strconv.Atoi(name[i+len("/fd/"):])
		if err1 != nil || err2 != nil || fd >= len(m.fds[pid]) {
			return "", os.ErrNotExist
		}
		return m.fds[pid][fd], nil
	}
	return m.procTable.Readlink(name)
}

const (
	phpCLIPath = "/opt/cpanel/ea-php84/root/usr/bin/php"
	lswsgiPath = "/opt/alt/python311/bin/lswsgi"
	// unixListening is __SO_ACCEPTCON in /proc/net/unix.
	webSocketTable = "Num       RefCount Protocol Flags    Type St Inode Path\n" +
		"0000000000000000: 00000002 00000000 00010000 0001 01 5001 /usr/local/lsws/extapp-sock/APVH_alice_Suea-php84.sock\n" +
		"0000000000000000: 00000002 00000000 00010000 0001 01 5002 /usr/local/lsws/extapp-sock/APVH_phpdev_.sock\n" +
		"0000000000000000: 00000002 00000000 00010000 0001 01 5003 /opt/cpanel/ea-php84/root/usr/var/run/php-fpm/f3a1.sock\n" +
		"0000000000000000: 00000003 00000000 00000000 0001 03 5004 /usr/local/lsws/extapp-sock/APVH_alice_Suea-php84.sock\n" +
		"0000000000000000: 00000002 00000000 00010000 0001 01 5005 @/tmp/.held-by-lsphp\n"
)

func socketFD(inode int) string { return "socket:[" + strconv.Itoa(inode) + "]" }

func withWebProcTable(t *testing.T, procs map[int]fakeProc, fds map[int][]string) *webProcTable {
	t.Helper()
	table := &webProcTable{procTable: &procTable{procs: procs, uptime: 100000}, fds: fds, unix: webSocketTable}
	withMockOS(t, table)
	return table
}

func detachedPIDs(findings []alert.Finding) map[int][]int {
	out := map[int][]int{}
	for _, f := range findings {
		if f.Check == DetachedWebProcessCheck {
			out[f.PID] = f.WriterChain
		}
	}
	return out
}

// The incident shape: a web request started a shell loop that outlived the
// request, was reparented to init and kept the PHP handler's listening
// socket it inherited. No other check matched a plain shell running a script.
func TestDetachedWebProcessesFindsLoopsAWebRequestLeftRunning(t *testing.T) {
	young := int64((100000 - 30) * procClockTicks)
	withWebProcTable(t, map[int]fakeProc{
		600: {ppid: 1, uid: "1001", exe: lsphpPath},
		700: {ppid: 1, uid: "1001", exe: bashPath},
		701: {ppid: 700, uid: "1001", exe: curlPath},
		710: {ppid: 600, uid: "1001", exe: bashPath},
		720: {ppid: 1, uid: "1002", exe: lswsgiPath},
		730: {ppid: 1, uid: "1001", exe: bashPath, start: young},
		740: {ppid: 1, uid: "0", exe: bashPath},
		750: {ppid: 1, uid: "1003", exe: phpCLIPath},
		760: {ppid: 1, uid: "1001", exe: bashPath},
		770: {ppid: 1, uid: "1001", exe: bashPath, tty: 34816},
		780: {ppid: 1, uid: "1001", exe: bashPath},
	}, map[int][]string{
		600: {socketFD(5001), socketFD(5005)},
		700: {"/dev/null", socketFD(5001)},
		701: {"pipe:[1]"},
		710: {socketFD(5001)},
		720: {socketFD(5002)},
		730: {socketFD(5001)},
		740: {socketFD(5001)},
		750: {socketFD(5003)},
		760: {socketFD(5004)},
		770: {socketFD(5001)},
		780: {socketFD(5005)},
	})

	got := detachedPIDs(CheckDetachedWebProcesses(context.Background(), &config.Config{}, nil))

	want := map[int][]int{
		700: nil,
		750: nil,
		// A terminal means a person: reported, never stopped.
		770: nil,
		// The listener path names no PHP handler, but a PHP worker holds it.
		780: nil,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("detached web processes = %v, want %v", got, want)
	}
}

func TestDetachedWebProcessFindingIsAdvisoryAndNamesTheProcess(t *testing.T) {
	withWebProcTable(t, map[int]fakeProc{
		700: {ppid: 1, uid: "1001", exe: bashPath},
	}, map[int][]string{700: {socketFD(5001)}})

	findings := CheckDetachedWebProcesses(context.Background(), &config.Config{}, nil)

	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want one", findings)
	}
	f := findings[0]
	if f.Severity != alert.Warning || f.PID != 700 || !f.WriterObservedAt.IsZero() || len(f.WriterChain) != 0 ||
		!strings.Contains(f.Message, bashPath) || !strings.Contains(f.Details, "APVH_alice_Suea-php84.sock") {
		t.Fatalf("finding = %+v", f)
	}
}

// Inherited sockets also occur in legitimate background jobs. They are not
// evidence of malicious behavior, even when process killing is enabled.
func TestAutoKillLeavesDetachedWebProcesses(t *testing.T) {
	withWebProcTable(t, map[int]fakeProc{
		701: {ppid: 700, uid: "1001", exe: curlPath},
		700: {ppid: 1, uid: "1001", exe: bashPath},
	}, map[int][]string{701: {socketFD(5001)}, 700: {socketFD(5001)}})
	findings := CheckDetachedWebProcesses(context.Background(), &config.Config{}, nil)
	var killed []int
	prev := signalProcess
	signalProcess = func(_ context.Context, pid int, _ syscall.Signal, verify func() error) error {
		if err := verify(); err != nil {
			return err
		}
		killed = append(killed, pid)
		return nil
	}
	t.Cleanup(func() { signalProcess = prev })
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.KillProcesses = true

	AutoKillProcesses(context.Background(), cfg, findings)

	if len(findings) != 2 || len(killed) != 0 {
		t.Fatalf("findings=%v killed=%v, want two advisory findings and no kills", findings, killed)
	}
	// Even stale findings from the previous policy cannot authorize a kill.
	legacy := []alert.Finding{{Check: DetachedWebProcessCheck, Severity: alert.Critical, PID: 701, Timestamp: time.Now(), WriterObservedAt: time.Now(), WriterChain: []int{701, 700}}}
	AutoKillProcesses(context.Background(), cfg, legacy)
	if len(killed) != 0 {
		t.Fatalf("killed from legacy socket evidence: %v", killed)
	}
}

func TestDetachedWebProcessFindingStampsOwner(t *testing.T) {
	root := t.TempDir()
	withAccountHomeRoots(t, root)
	writePasswdFixture(t, root)
	for uid, owner := range map[string]string{"1001": "alice", "1002": "bob", "65534": "", "4242": ""} {
		withWebProcTable(t, map[int]fakeProc{
			700: {ppid: 1, uid: uid, exe: bashPath},
		}, map[int][]string{700: {socketFD(5001)}})
		findings := CheckDetachedWebProcesses(context.Background(), &config.Config{}, nil)
		if len(findings) != 1 {
			t.Fatalf("uid %s: findings = %+v, want one", uid, findings)
		}
		if f := findings[0]; f.TenantID != owner || extractAccountFromFinding(f) != owner {
			t.Errorf("uid %s: tenant %q, correlation owner %q, want %q", uid, f.TenantID, extractAccountFromFinding(f), owner)
		}
	}
}

func TestDetachedWebProcessesLeaveActiveRequestDescendants(t *testing.T) {
	withWebProcTable(t, map[int]fakeProc{
		600: {ppid: 1, uid: "1001", exe: lsphpPath},
		700: {ppid: 600, uid: "1001", exe: bashPath},
		701: {ppid: 700, uid: "1001", exe: "/usr/bin/convert"},
	}, map[int][]string{600: {socketFD(5001)}, 700: {socketFD(5001)}, 701: {socketFD(5001)}})
	if got := CheckDetachedWebProcesses(context.Background(), &config.Config{}, nil); len(got) != 0 {
		t.Fatalf("active request reported as detached: %+v", got)
	}
}

func TestDetachedWebProcessesRequireCompleteAncestry(t *testing.T) {
	for _, parent := range []int{0, 700, 999} {
		t.Run(strconv.Itoa(parent), func(t *testing.T) {
			withWebProcTable(t, map[int]fakeProc{700: {ppid: parent, uid: "1001", exe: bashPath}}, map[int][]string{700: {socketFD(5001)}})
			if got := CheckDetachedWebProcesses(context.Background(), &config.Config{}, nil); len(got) != 0 {
				t.Fatalf("incomplete or cyclic ancestry reported: %+v", got)
			}
		})
	}
}

func TestDetachedWebProcessesFilterBeforeReadingFDs(t *testing.T) {
	table := withWebProcTable(t, map[int]fakeProc{
		600: {ppid: 1, uid: "0", exe: "/usr/bin/service"},
		700: {ppid: 1, uid: "1001", exe: bashPath, start: int64((100000 - 30) * procClockTicks)},
		800: {ppid: 1, uid: "0", exe: lsphpPath},
		900: {ppid: 1, uid: "1001", exe: bashPath},
	}, map[int][]string{800: {socketFD(5005)}, 900: {socketFD(5005)}})
	var reads []string
	withMockOS(t, &mockOS{readFile: table.ReadFile, readlink: table.Readlink, glob: func(pattern string) ([]string, error) {
		if strings.Contains(pattern, "/fd/") {
			reads = append(reads, pattern)
		}
		return table.Glob(pattern)
	}})
	findings := CheckDetachedWebProcesses(context.Background(), &config.Config{}, nil)
	if len(findings) != 1 || findings[0].PID != 900 {
		t.Fatalf("lost PHP holder evidence: %+v", findings)
	}
	if !reflect.DeepEqual(reads, []string{"/proc/800/fd/*", "/proc/900/fd/*"}) {
		t.Fatalf("unnecessary descriptor scans: %v", reads)
	}
}

func TestDetachedWebProcessesRejectChangedIdentity(t *testing.T) {
	for _, change := range []string{"pid reuse", "exec", "owner"} {
		t.Run(change, func(t *testing.T) {
			table := withWebProcTable(t, map[int]fakeProc{700: {ppid: 1, uid: "1001", exe: bashPath}}, map[int][]string{700: {socketFD(5001)}})
			withMockOS(t, &mockOS{readFile: table.ReadFile, glob: table.Glob, readlink: func(name string) (string, error) {
				target, err := table.Readlink(name)
				if strings.Contains(name, "/fd/") {
					p := table.procs[700]
					switch change {
					case "pid reuse":
						p.start++
					case "exec":
						p.exe = phpCLIPath
					case "owner":
						p.uid = "1002"
					}
					table.procs[700] = p
				}
				return target, err
			}})
			if got := CheckDetachedWebProcesses(context.Background(), &config.Config{}, nil); len(got) != 0 {
				t.Fatalf("mixed process evidence: %+v", got)
			}
		})
	}
}

func TestUnixListenersPreservePaths(t *testing.T) {
	for _, path := range []string{"/run/php fpm/pool.sock", "@php pool", "/run/php-fpm/pool.sock (deleted)"} {
		t.Run(path, func(t *testing.T) {
			table := withWebProcTable(t, nil, nil)
			table.unix = "Num RefCount Protocol Flags Type St Inode Path\n" + "0000: 00000002 00000000 00010000 0001 01 42 " + path + "\n"
			if got := unixListeners(); !reflect.DeepEqual(got, map[string]string{"42": path}) {
				t.Fatalf("listeners=%q, want full path %q", got, path)
			}
		})
	}
}
