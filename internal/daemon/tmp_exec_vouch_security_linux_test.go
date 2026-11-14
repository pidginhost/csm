//go:build linux

package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"golang.org/x/sys/unix"
)

func TestTmpVouchRejectsUnsafePlacement(t *testing.T) {
	for _, attack := range []string{"writable child", "foreign child", "symlink child", "writable file", "replaced file", "bind alias", "symlink work", "bind work", "event mount alias"} {
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
			if attack == "event mount alias" {
				alias := tmpWorkDirForTest(t)
				if err := unix.Mount(work, alias, "", unix.MS_BIND, ""); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := unix.Unmount(alias, 0); err != nil {
						t.Error(err)
					}
				})
				fd = openRawFd(t, filepath.Join(alias, "child", "tool"))
			}
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

func TestTmpVouchAdmissionOwnerChanges(t *testing.T) {
	for _, initialRoot := range []bool{false, true} {
		t.Run(map[bool]string{false: "becomes root", true: "changes back to root"}[initialRoot], func(t *testing.T) {
			stubTmpExecWriters(t)
			path := filepath.Join(tmpWorkDirForTest(t), "tool")
			makeTmpExec(t, path)
			if !initialRoot {
				chownForTest(t, path)
			}
			event := fileEvent{path: path, fd: openRawFd(t, path), pid: tmpProvenPID}
			captureTmpExecAncestry(&event)
			chownForTest(t, path)
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
