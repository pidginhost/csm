//go:build linux

package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"golang.org/x/sys/unix"
)

func TestTmpVouchRejectsUnsafePlacement(t *testing.T) {
	for _, attack := range []string{"writable child", "foreign child", "symlink child", "writable file", "replaced file", "bind alias", "symlink work", "bind work"} {
		t.Run(attack, func(t *testing.T) {
			stubTmpExecWriters(t)
			work := tmpWorkDirForTest(t)
			ch := make(chan alert.Finding, 8)
			fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
			writeTmpExecAs(t, fm, filepath.Join(work, "proof"), tmpProvenPID)
			if got := drainFindings(ch); len(got) != 1 || got[0].Severity != alert.Warning {
				t.Fatalf("proof: %+v", got)
			}
			t.Cleanup(fm.tmpVouches.close)
			child := filepath.Join(work, "child")
			if err := os.Mkdir(child, 0o755); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(child, "tool")
			switch attack {
			case "writable child":
				chmodForTest(t, child, 0o777)
			case "foreign child":
				chownForTest(t, child)
			case "symlink child":
				alias := filepath.Join(work, "alias")
				if err := os.Symlink(child, alias); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(alias, "tool")
			case "symlink work", "bind work":
				alias := tmpWorkDirForTest(t)
				if attack == "symlink work" {
					alias = filepath.Join(alias, "link")
					if err := os.Symlink(work, alias); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := unix.Mount(work, alias, "", unix.MS_BIND, ""); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						if err := unix.Unmount(alias, 0); err != nil {
							t.Error(err)
						}
					})
				}
				path = filepath.Join(alias, "tool")
			case "bind alias":
				source := tmpWorkDirForTest(t)
				if err := unix.Mount(source, child, "", unix.MS_BIND, ""); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := unix.Unmount(child, 0); err != nil {
						t.Error(err)
					}
				})
			}
			makeTmpExec(t, path)
			fd := openRawFd(t, path)
			if attack == "writable file" {
				chmodForTest(t, path, 0o777)
			}
			if attack == "replaced file" {
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				makeTmpExec(t, path)
			}
			fm.analyzeFile(fileEvent{path: path, fd: fd, pid: tmpGonePID})
			got := drainFindings(ch)
			if len(got) != 1 || got[0].Severity != alert.Critical {
				t.Fatalf("unsafe placement: %+v, want one Critical", got)
			}
		})
	}
}

// A file that was not root-owned when its write was seen is never walked, even
// if root owns it by the time it is analyzed.
func TestTmpVouchAdmissionOwnerChanges(t *testing.T) {
	stubTmpExecWriters(t)
	path := filepath.Join(tmpWorkDirForTest(t), "tool")
	makeTmpExec(t, path)
	chownForTest(t, path)
	event := fileEvent{path: path, fd: openRawFd(t, path), pid: tmpProvenPID}
	captureTmpExecAncestry(&event)
	if err := os.Chown(path, 0, 0); err != nil {
		t.Fatal(err)
	}
	ch := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(event)
	got := drainFindings(ch)
	if len(got) != 1 || got[0].Severity != alert.Critical {
		t.Fatalf("changed ownership: %+v, want Critical", got)
	}
}

// A build keeps working on a file after the close that raised the event: the
// copy that fills a file created empty, the linker's chmod, a hard link that
// replaces a duplicate. The proof read at admission still belongs to that file,
// and a file still being written can still vouch for its work directory.
func TestTmpExecProofSurvivesBuildRewrites(t *testing.T) {
	for _, tt := range []struct {
		name    string
		rewrite func(t *testing.T, path string)
	}{
		{"content appended", func(t *testing.T, path string) {
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteString("echo more\n"); err != nil {
				t.Fatal(err)
			}
			_ = f.Close()
		}},
		{"mode changed", func(t *testing.T, path string) { chmodForTest(t, path, 0o700) }},
		{"hard link added", func(t *testing.T, path string) {
			if err := os.Link(path, path+".link"); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			stubTmpExecWriters(t)
			work := tmpWorkDirForTest(t)
			path := filepath.Join(work, "tool")
			makeTmpExec(t, path)
			event := fileEvent{path: path, fd: openRawFd(t, path), pid: tmpProvenPID}
			captureTmpExecAncestry(&event)
			tt.rewrite(t, path)
			tmpExecAncestry = func(int32) ancestryEvidence {
				t.Error("walked the writer again after admission")
				return ancestryEvidence{vanished: true}
			}
			ch := make(chan alert.Finding, 8)
			fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
			t.Cleanup(fm.tmpVouches.close)
			fm.analyzeFile(event)
			if got := drainFindings(ch); len(got) != 1 || got[0].Severity != alert.Warning {
				t.Fatalf("proven writer of a file the build rewrote: %+v, want one Warning", got)
			}
			gone := ancestryEvidence{vanished: true}
			sibling := filepath.Join(work, "sibling")
			makeTmpExec(t, sibling)
			endAlertCooldown(fm)
			fm.analyzeFile(fileEvent{path: sibling, fd: openRawFd(t, sibling), pid: tmpGonePID, tmpAncestry: &gone})
			if got := drainFindings(ch); len(got) != 1 || got[0].Severity != alert.Warning {
				t.Fatalf("exited writer beside it: %+v, want the grouped Warning", got)
			}
		})
	}
}

func TestTmpVouchDelayedProofCannotRenew(t *testing.T) {
	stubTmpExecWriters(t)
	work := tmpWorkDirForTest(t)
	proof := filepath.Join(work, "proof")
	makeTmpExec(t, proof)
	event := fileEvent{path: proof, fd: openRawFd(t, proof), pid: tmpProvenPID, at: time.Now().Add(-2 * tmpVouchTTL)}
	captureTmpExecAncestry(&event)
	ch := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(event)
	drainFindings(ch)
	writeTmpExecAs(t, fm, filepath.Join(work, "late"), tmpGonePID)
	got := drainFindings(ch)
	if len(got) != 1 || got[0].Severity != alert.Critical {
		t.Fatalf("stale proof renewed vouch: %+v", got)
	}
}

func TestTmpAncestryReadFailureIsNotExit(t *testing.T) {
	root := t.TempDir()
	overrideProcRoot(t, root)
	if err := os.MkdirAll(filepath.Join(root, "123", "comm"), 0o755); err != nil {
		t.Fatal(err)
	}
	if ev := procAncestryEvidence(123, nil); ev.vanished {
		t.Fatal("read error classified as exited writer")
	}
}

func TestTmpAncestryNonRootChainCannotUseVouch(t *testing.T) {
	root := fakeProc(t, map[int32]struct {
		comm string
		ppid int32
	}{123: {"helper", 124}})
	overrideProcRoot(t, root)
	if err := os.WriteFile(filepath.Join(root, "123", "status"), []byte("Name:\thelper\nPPid:\t124\nUid:\t65534\t0\t0\t0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if ev := procAncestryEvidence(123, nil); ev.vanished {
		t.Fatal("set-uid writer inherited an exited ancestor's vouch eligibility")
	}
}

func TestTmpVouchPinsDeletedDirectoryAndCloses(t *testing.T) {
	stubTmpExecWriters(t)
	work := tmpWorkDirForTest(t)
	path := filepath.Join(work, "proof")
	makeTmpExec(t, path)
	var v tmpVouches
	t.Cleanup(v.close)
	now := time.Now()
	v.grant(fileEvent{path: path, fd: openRawFd(t, path)}, "proof", now)
	if len(v.entries) != 1 {
		t.Fatal("missing proof")
	}
	pin := v.entries[0].dir
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(work); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(pin.Fd()), &st); err != nil || st.Nlink != 0 {
		t.Fatalf("deleted directory is not pinned: %v, links=%d", err, st.Nlink)
	}
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	makeTmpExec(t, path)
	event := fileEvent{path: path, fd: openRawFd(t, path)}
	if _, ok := v.covers(event, now); ok {
		t.Fatal("replacement inherited proof")
	}
	v.close()
	if _, err := pin.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("pin was not closed: %v", err)
	}
}

func TestTmpVouchedWriterDoesNotRefreshProof(t *testing.T) {
	stubTmpExecWriters(t)
	work := tmpWorkDirForTest(t)
	ch := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	t.Cleanup(fm.tmpVouches.close)
	writeTmpExecAs(t, fm, filepath.Join(work, "proof"), tmpProvenPID)
	drainFindings(ch)
	if len(fm.tmpVouches.entries) != 1 {
		t.Fatal("missing proof")
	}
	until := fm.tmpVouches.entries[0].until
	writeTmpExecAs(t, fm, filepath.Join(work, "covered"), tmpGonePID)
	if !fm.tmpVouches.entries[0].until.Equal(until) {
		t.Fatal("exited writer refreshed proof")
	}
	fm.tmpVouches.entries[0].until = time.Now().Add(-time.Second)
	writeTmpExecAs(t, fm, filepath.Join(work, "expired"), tmpGonePID)
	got := drainFindings(ch)
	if len(got) != 1 || got[0].Severity != alert.Critical {
		t.Fatalf("expired vouch: %+v", got)
	}
}

func TestTmpVouchUnsafeProofCannotVouchForSibling(t *testing.T) {
	stubTmpExecWriters(t)
	work := tmpWorkDirForTest(t)
	child := filepath.Join(work, "shared")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	chmodForTest(t, child, 0o777)
	ch := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	t.Cleanup(fm.tmpVouches.close)
	writeTmpExecAs(t, fm, filepath.Join(child, "proof"), tmpProvenPID)
	if got := drainFindings(ch); len(got) != 1 || got[0].Severity != alert.Warning {
		t.Fatalf("direct ancestry proof: %+v", got)
	}
	writeTmpExecAs(t, fm, filepath.Join(work, "unproven"), tmpGonePID)
	got := drainFindings(ch)
	if len(got) != 1 || got[0].Severity != alert.Critical {
		t.Fatalf("unsafe proof vouched for sibling: %+v", got)
	}
}

func TestTmpVouchConcurrentProofKeepsNewestExpiry(t *testing.T) {
	stubTmpExecWriters(t)
	work := tmpWorkDirForTest(t)
	path := filepath.Join(work, "tool")
	makeTmpExec(t, path)
	event := fileEvent{path: path, fd: openRawFd(t, path)}
	now := time.Now()
	var v tmpVouches
	t.Cleanup(v.close)
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			proof := event
			proof.at = now.Add(-time.Duration(i) * time.Second)
			v.grant(proof, "proof", now)
			if _, ok := v.covers(event, now); !ok {
				t.Error("concurrent proof lost coverage")
			}
		})
	}
	wg.Wait()
	if len(v.entries) != 1 || !v.entries[0].until.Equal(now.Add(tmpVouchTTL)) {
		t.Fatalf("out-of-order proof expiry: %+v", v.entries)
	}
}

func TestTmpExecCaptureDoesNotWalkSpecialFiles(t *testing.T) {
	stubTmpExecWriters(t)
	tmpExecAncestry = func(int32) ancestryEvidence { t.Error("walked a non-regular file"); return ancestryEvidence{} }
	work := tmpWorkDirForTest(t)
	fifo := filepath.Join(work, "fifo")
	if err := unix.Mkfifo(fifo, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{work, fifo} {
		fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		event := fileEvent{path: path, fd: fd, pid: tmpProvenPID}
		captureTmpExecAncestry(&event)
		_ = unix.Close(fd)
		if event.tmpAncestry != nil {
			t.Fatal("captured ancestry for a non-regular file")
		}
	}
}

// The event descriptor belongs to the writer's mount. A daemon that systemd
// gave its own mount namespace never shares a mount with the processes it
// watches, so a descriptor opened through another mount of the same directory
// is still the file the path names, and the vouch covers it.
func TestTmpVouchCoversDescriptorFromAnotherMount(t *testing.T) {
	stubTmpExecWriters(t)
	work := tmpWorkDirForTest(t)
	ch := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	t.Cleanup(fm.tmpVouches.close)
	writeTmpExecAs(t, fm, filepath.Join(work, "proof"), tmpProvenPID)
	if got := drainFindings(ch); len(got) != 1 || got[0].Severity != alert.Warning {
		t.Fatalf("proof: %+v", got)
	}
	alias := tmpWorkDirForTest(t)
	if err := unix.Mount(work, alias, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(alias, 0); err != nil {
			t.Error(err)
		}
	})
	path := filepath.Join(work, "tool")
	makeTmpExec(t, path)
	endAlertCooldown(fm)
	fm.analyzeFile(fileEvent{path: path, fd: openRawFd(t, filepath.Join(alias, "tool")), pid: tmpGonePID})
	got := drainFindings(ch)
	if len(got) != 1 || got[0].Severity != alert.Warning || got[0].FilePath != path {
		t.Fatalf("descriptor from another mount: %+v, want the grouped Warning", got)
	}
}

// occupantProc adds a process to a synthetic procfs: its working directory and
// the user it runs as.
func occupantProc(t *testing.T, root string, pid int32, cwd, uidLine string) {
	t.Helper()
	dir := filepath.Join(root, strconv.Itoa(int(pid)))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte("Name:\tmake\nPPid:\t1\n"+uidLine), 0o644); err != nil {
		t.Fatal(err)
	}
	if cwd != "" {
		if err := os.Symlink(cwd, filepath.Join(dir, "cwd")); err != nil {
			t.Fatal(err)
		}
	}
}

const rootUIDLine = "Uid:\t0\t0\t0\t0\n"

// A build driver stays in its work directory while the short-lived tools it
// starts write the files, so no writer there is ever proven. The directory is
// then vouched for by the driver itself: a running root process with proven
// ancestry working inside it.
func TestTmpExecutableVanishedWriterProvenByOccupant(t *testing.T) {
	stubTmpExecWriters(t)
	work := tmpWorkDirForTest(t)
	module := filepath.Join(work, "module", "blib")
	if err := os.MkdirAll(module, 0o755); err != nil {
		t.Fatal(err)
	}
	proc := t.TempDir()
	overrideProcRoot(t, proc)
	occupantProc(t, proc, tmpProvenPID, filepath.Dir(module), rootUIDLine)
	ch := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	t.Cleanup(fm.tmpVouches.close)

	first := filepath.Join(module, "first.so")
	writeTmpExecAs(t, fm, first, tmpGonePID)
	got := drainFindings(ch)
	if len(got) != 1 || got[0].Severity != alert.Warning || got[0].FilePath != first {
		t.Fatalf("exited writer beside a proven occupant: %+v, want one Warning", got)
	}
	for _, want := range []string{"initramfs build ancestry", "writer exited", "work directory"} {
		if !strings.Contains(got[0].Details, want) {
			t.Fatalf("Details = %q, want %q", got[0].Details, want)
		}
	}

	// The driver has finished; its proof still stands for the directory.
	if err := os.RemoveAll(filepath.Join(proc, strconv.Itoa(int(tmpProvenPID)))); err != nil {
		t.Fatal(err)
	}
	endAlertCooldown(fm)
	writeTmpExecAs(t, fm, filepath.Join(module, "second.so"), tmpGonePID)
	if got = drainFindings(ch); len(got) != 1 || got[0].Severity != alert.Warning {
		t.Fatalf("exited writer after the occupant left: %+v, want the grouped Warning", got)
	}

	planted := filepath.Join(module, "planted")
	writeTmpExecAs(t, fm, planted, tmpLivePID)
	if got = drainFindings(ch); len(got) != 1 || got[0].Severity != alert.Critical || got[0].FilePath != planted {
		t.Fatalf("running writer that proves nothing: %+v, want its own Critical", got)
	}
}

// Only a root process with proven ancestry, working inside this very work
// directory, vouches for it.
func TestTmpExecutableOccupantMustBeProvenRootInside(t *testing.T) {
	for _, tt := range []struct {
		name    string
		pid     int32
		uidLine string
		cwd     func(t *testing.T, work string) string
		prepare func(t *testing.T, work string)
	}{
		{name: "occupant proves nothing", pid: tmpLivePID, uidLine: rootUIDLine},
		{name: "occupant is not root", pid: tmpProvenPID, uidLine: "Uid:\t1000\t1000\t1000\t1000\n"},
		{name: "occupant only has root as effective user", pid: tmpProvenPID, uidLine: "Uid:\t1000\t0\t0\t0\n"},
		{name: "occupant has no readable credentials", pid: tmpProvenPID},
		{name: "occupant works in another directory", pid: tmpProvenPID, uidLine: rootUIDLine,
			cwd: func(t *testing.T, _ string) string { return tmpWorkDirForTest(t) }},
		{name: "occupant works in the temporary root", pid: tmpProvenPID, uidLine: rootUIDLine,
			cwd: func(*testing.T, string) string { return "/tmp" }},
		{name: "occupant has no working directory", pid: tmpProvenPID, uidLine: rootUIDLine,
			cwd: func(*testing.T, string) string { return "" }},
		{name: "occupant works in a writable child", pid: tmpProvenPID, uidLine: rootUIDLine,
			cwd: func(t *testing.T, work string) string {
				child := filepath.Join(work, "shared")
				if err := os.Mkdir(child, 0o755); err != nil {
					t.Fatal(err)
				}
				chmodForTest(t, child, 0o777)
				return child
			}},
		{name: "occupant works below a foreign child", pid: tmpProvenPID, uidLine: rootUIDLine,
			cwd: func(t *testing.T, work string) string {
				child := filepath.Join(work, "foreign")
				cwd := filepath.Join(child, "private")
				if err := os.MkdirAll(cwd, 0o755); err != nil {
					t.Fatal(err)
				}
				chownForTest(t, child)
				return cwd
			}},
		{name: "cwd link points outside through a symlink", pid: tmpProvenPID, uidLine: rootUIDLine,
			cwd: func(t *testing.T, work string) string {
				alias := filepath.Join(work, "alias")
				if err := os.Symlink(tmpWorkDirForTest(t), alias); err != nil {
					t.Fatal(err)
				}
				return alias
			}},
		{name: "cwd link names a missing child", pid: tmpProvenPID, uidLine: rootUIDLine,
			cwd: func(_ *testing.T, work string) string { return filepath.Join(work, "missing") }},
		{name: "work directory is writable by others", pid: tmpProvenPID, uidLine: rootUIDLine,
			prepare: func(t *testing.T, work string) { chmodForTest(t, work, 0o777) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			stubTmpExecWriters(t)
			work := tmpWorkDirForTest(t)
			if tt.prepare != nil {
				tt.prepare(t, work)
			}
			cwd := work
			if tt.cwd != nil {
				cwd = tt.cwd(t, work)
			}
			proc := t.TempDir()
			overrideProcRoot(t, proc)
			occupantProc(t, proc, tt.pid, cwd, tt.uidLine)
			ch := make(chan alert.Finding, 8)
			fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
			t.Cleanup(fm.tmpVouches.close)
			path := filepath.Join(work, "tool")
			writeTmpExecAs(t, fm, path, tmpGonePID)
			got := drainFindings(ch)
			if len(got) != 1 || got[0].Severity != alert.Critical || got[0].FilePath != path {
				t.Fatalf("findings = %+v, want one Critical", got)
			}
		})
	}
}

// A work directory nobody proven works in is not rescanned for every file of
// a burst.
func TestTmpOccupantScansAreSpaced(t *testing.T) {
	stubTmpExecWriters(t)
	work := tmpWorkDirForTest(t)
	path := filepath.Join(work, "tool")
	makeTmpExec(t, path)
	event := fileEvent{path: path, fd: openRawFd(t, path), pid: tmpGonePID}
	proc := t.TempDir()
	overrideProcRoot(t, proc)
	var v tmpVouches
	t.Cleanup(v.close)
	now := time.Unix(1_700_000_000, 0)

	if _, ok := v.occupied(event, now); ok {
		t.Fatal("an empty process table vouched for the directory")
	}
	occupantProc(t, proc, tmpProvenPID, work, rootUIDLine)
	if _, ok := v.occupied(event, now.Add(tmpOccupantScanGap-time.Second)); ok {
		t.Fatal("rescanned before the gap had passed")
	}
	if reason, ok := v.occupied(event, now.Add(tmpOccupantScanGap)); !ok || reason != "initramfs build ancestry" {
		t.Fatalf("occupied = (%q, %v) after the gap, want the occupant's proof", reason, ok)
	}
	if _, ok := v.covers(event, now.Add(tmpOccupantScanGap+tmpVouchTTL-time.Second)); !ok {
		t.Fatal("the occupant's proof did not vouch for the directory")
	}
}

// Overflow must neither forget active cooldowns nor let an untracked directory
// scan on every write. Expired entries must free capacity again.
func TestTmpOccupantScanOverflowKeepsCooldowns(t *testing.T) {
	stubTmpExecWriters(t)
	proc := t.TempDir()
	overrideProcRoot(t, proc)
	var v tmpVouches
	t.Cleanup(v.close)
	now := time.Unix(1_700_000_000, 0)
	var events []fileEvent
	for range tmpVouchCap + 1 {
		path := filepath.Join(tmpWorkDirForTest(t), "tool")
		makeTmpExec(t, path)
		event := fileEvent{path: path, fd: openRawFd(t, path), pid: tmpGonePID}
		events = append(events, event)
		if _, ok := v.occupied(event, now); ok {
			t.Fatal("empty process table provided proof")
		}
	}
	for i, event := range events {
		occupantProc(t, proc, tmpProvenPID+int32(i), filepath.Dir(event.path), rootUIDLine)
	}
	walks := 0
	tmpExecAncestry = func(int32) ancestryEvidence {
		walks++
		return ancestryEvidence{initramfsBuilder: true}
	}
	for _, event := range events {
		if _, ok := v.occupied(event, now.Add(time.Second)); ok {
			t.Error("overflow permitted a scan before cooldown expired")
		}
	}
	if walks != 0 {
		t.Errorf("overflow performed %d ancestry walks, want zero", walks)
	}
	if len(v.scanned) != tmpVouchCap {
		t.Errorf("cooldowns = %d, want %d", len(v.scanned), tmpVouchCap)
	}
	if _, ok := v.occupied(events[len(events)-1], now.Add(tmpOccupantScanGap)); !ok {
		t.Fatal("expired cooldowns did not release scan capacity")
	}
}

// Occupant descriptors may use another mount of the same work directory, but
// a mount inside it must not import an unrelated process's proof.
func TestTmpOccupantMountPlacement(t *testing.T) {
	for _, nested := range []bool{false, true} {
		t.Run(strconv.FormatBool(nested), func(t *testing.T) {
			stubTmpExecWriters(t)
			work := tmpWorkDirForTest(t)
			source, target := work, tmpWorkDirForTest(t)
			if nested {
				source, target = target, filepath.Join(work, "mounted")
				if err := os.Mkdir(target, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := unix.Mount(source, target, "", unix.MS_BIND, ""); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := unix.Unmount(target, 0); err != nil {
					t.Error(err)
				}
			})
			proc := t.TempDir()
			overrideProcRoot(t, proc)
			occupantProc(t, proc, tmpProvenPID, target, rootUIDLine)
			ch := make(chan alert.Finding, 8)
			fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
			t.Cleanup(fm.tmpVouches.close)
			writeTmpExecAs(t, fm, filepath.Join(work, "tool"), tmpGonePID)
			want := alert.Warning
			if nested {
				want = alert.Critical
			}
			if got := drainFindings(ch); len(got) != 1 || got[0].Severity != want {
				t.Fatalf("findings = %+v, want one %v", got, want)
			}
		})
	}
}

func TestTmpOccupantConcurrentMissScansOnce(t *testing.T) {
	stubTmpExecWriters(t)
	work := tmpWorkDirForTest(t)
	path := filepath.Join(work, "tool")
	makeTmpExec(t, path)
	event := fileEvent{path: path, fd: openRawFd(t, path), pid: tmpGonePID}
	proc := t.TempDir()
	overrideProcRoot(t, proc)
	occupantProc(t, proc, tmpLivePID, work, rootUIDLine)
	var walks atomic.Int32
	tmpExecAncestry = func(int32) ancestryEvidence {
		walks.Add(1)
		return ancestryEvidence{}
	}
	var v tmpVouches
	t.Cleanup(v.close)
	now := time.Now()
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if _, ok := v.occupied(event, now); ok {
				t.Error("unproven occupant supplied proof")
			}
		})
	}
	wg.Wait()
	if got := walks.Load(); got != 1 {
		t.Fatalf("concurrent burst scanned %d times, want one", got)
	}
}

// An installer creates each file, removes it when a fast copy is refused, and
// has a copy tool write it again. The first write then belongs to a file with
// no name left. It was in the work directory when the kernel reported it, so
// its proven writer still vouches and its exited writer is still covered.
func TestTmpVouchAcceptsFileRemovedByTheBuild(t *testing.T) {
	stubTmpExecWriters(t)
	work := tmpWorkDirForTest(t)
	ch := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	t.Cleanup(fm.tmpVouches.close)

	// removed returns a descriptor for an executable whose name is taken by
	// a new file, as after create, remove and copy.
	removed := func(name string) (string, int) {
		path := filepath.Join(work, name)
		makeTmpExec(t, path)
		fd := openRawFd(t, path)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		makeTmpExec(t, path)
		return path, fd
	}

	path, fd := removed("bash")
	fm.analyzeFile(fileEvent{path: path, fd: fd, pid: tmpProvenPID})
	if got := drainFindings(ch); len(got) != 1 || got[0].Severity != alert.Warning {
		t.Fatalf("proven writer of a removed file: %+v, want one Warning", got)
	}
	endAlertCooldown(fm)
	writeTmpExecAs(t, fm, path, tmpGonePID)
	if got := drainFindings(ch); len(got) != 1 || got[0].Severity != alert.Warning {
		t.Fatalf("copy written by an exited tool: %+v, want the grouped Warning", got)
	}
	endAlertCooldown(fm)
	path, fd = removed("hook.sh")
	fm.analyzeFile(fileEvent{path: path, fd: fd, pid: tmpGonePID})
	if got := drainFindings(ch); len(got) != 1 || got[0].Severity != alert.Warning {
		t.Fatalf("exited writer of a removed file: %+v, want the grouped Warning", got)
	}
}

// A removed file is covered only on the same terms as a named one: root-owned,
// not writable by others, in a directory chain that passes every check.
func TestTmpVouchRemovedFileStillNeedsSafePlacement(t *testing.T) {
	for _, tt := range []struct {
		name    string
		prepare func(t *testing.T, work, path string)
	}{
		{"file writable by others", func(t *testing.T, _, path string) { chmodForTest(t, path, 0o777) }},
		{"file owned by another user", func(t *testing.T, _, path string) { chownForTest(t, path) }},
		{"directory writable by others", func(t *testing.T, work, _ string) { chmodForTest(t, work, 0o777) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			stubTmpExecWriters(t)
			work := tmpWorkDirForTest(t)
			ch := make(chan alert.Finding, 8)
			fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
			t.Cleanup(fm.tmpVouches.close)
			writeTmpExecAs(t, fm, filepath.Join(work, "proof"), tmpProvenPID)
			if got := drainFindings(ch); len(got) != 1 || got[0].Severity != alert.Warning {
				t.Fatalf("proof: %+v", got)
			}
			path := filepath.Join(work, "tool")
			makeTmpExec(t, path)
			tt.prepare(t, work, path)
			fd := openRawFd(t, path)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			gone := ancestryEvidence{vanished: true}
			fm.analyzeFile(fileEvent{path: path, fd: fd, pid: tmpGonePID, tmpAncestry: &gone})
			got := drainFindings(ch)
			if len(got) != 1 || got[0].Severity != alert.Critical {
				t.Fatalf("removed file: %+v, want one Critical", got)
			}
		})
	}
}
