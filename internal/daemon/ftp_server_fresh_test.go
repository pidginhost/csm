package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// setFTPServerFresh fixes whether the running pure-ftpd started after its
// configuration last changed.
func setFTPServerFresh(t *testing.T, fresh bool) {
	t.Helper()
	old := pureFTPDServerFresh
	pureFTPDServerFresh = func([]string) bool { return fresh }
	t.Cleanup(func() { pureFTPDServerFresh = old })
}

// pure-ftpd reads DontResolve only when it starts. A server started before
// its configuration last changed may still resolve names whatever the file
// says now, so its root failures only alert, and the daemon says so once.
func TestFTPNumericPeerProbeNeedsFreshServer(t *testing.T) {
	logs := captureCSMLog(t)
	setFTPServerFresh(t, false)
	probe := newFTPNumericPeerProbe(func() ([]string, []string) { return []string{"pure-ftpd.conf"}, nil })
	if first, again := probe(), probe(); first || again {
		t.Fatal("a server that predates its configuration was trusted")
	}
	setFTPServerFresh(t, true)
	if !probe() {
		t.Fatal("a server started after its configuration was rejected")
	}
	setFTPServerFresh(t, false)
	if probe() {
		t.Fatal("a stale server was trusted again")
	}
	const warning = "pure-ftpd started before its configuration last changed"
	if got := strings.Count(logs(), warning); got != 2 {
		t.Fatalf("stale warnings = %d, want one per change into the stale state", got)
	}
}

// The freshness check rescans processes only when the server it remembers
// is gone, at most once per rescan period, and fails closed meanwhile, when
// no server runs, or when a source cannot be read.
func TestPureFTPDFreshness(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "pure-ftpd.conf")
	if err := os.WriteFile(conf, []byte("DontResolve yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	changed := time.Now()
	clock := &staticClock{t: changed}
	type server struct {
		pid     int
		started time.Time
	}
	running := server{10, changed.Add(time.Hour)}
	scans := 0
	alive := map[int]time.Time{10: running.started}
	fresh := newPureFTPDFreshness(func() (int, time.Time, bool) {
		scans++
		return running.pid, running.started, running.pid != 0
	}, func(pid int) (time.Time, bool) {
		at, ok := alive[pid]
		return at, ok
	}, clock.Now)

	if first, again := fresh([]string{conf}), fresh([]string{conf}); !first || !again {
		t.Fatal("a server started after the configuration was rejected")
	}
	if scans != 1 {
		t.Fatalf("scans = %d, want the server remembered while it runs", scans)
	}

	// The remembered server exited and an older one is left.
	delete(alive, 10)
	running = server{11, changed.Add(-time.Hour)}
	alive[11] = running.started
	if fresh([]string{conf}) || scans != 1 {
		t.Fatalf("within the rescan period: scans = %d, want a closed answer without a scan", scans)
	}
	clock.advance(pureFTPDRescanEvery)
	if fresh([]string{conf}) {
		t.Fatal("a server older than its configuration was trusted")
	}
	if scans != 2 {
		t.Fatalf("scans = %d, want a rescan after the server exited", scans)
	}

	delete(alive, 11)
	running = server{}
	clock.advance(pureFTPDRescanEvery)
	if first, again := fresh([]string{conf}), fresh([]string{conf}); first || again {
		t.Fatal("no running server was trusted")
	}
	if scans != 3 {
		t.Fatalf("scans = %d, want one scan per period while no server runs", scans)
	}

	running = server{12, changed.Add(time.Hour)}
	alive[12] = running.started
	clock.advance(pureFTPDRescanEvery)
	if fresh([]string{conf, filepath.Join(filepath.Dir(conf), "gone")}) {
		t.Fatal("an unreadable source was trusted")
	}
	if !fresh([]string{conf}) {
		t.Fatal("a server started after the configuration was rejected after a rescan")
	}
}

func TestPureFTPDFreshnessChangeDuringScan(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "pure-ftpd.conf")
	if err := os.WriteFile(conf, []byte("DontResolve yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	started := time.Now().Add(time.Hour)
	scans := 0
	fresh := newPureFTPDFreshness(func() (int, time.Time, bool) {
		scans++
		later := started.Add(time.Hour)
		if err := os.Chtimes(conf, later, later); err != nil {
			t.Fatal(err)
		}
		return 10, started, true
	}, func(int) (time.Time, bool) { return started, true }, time.Now)
	if fresh([]string{conf}) {
		t.Fatal("a configuration changed during the scan was approved")
	}
	if fresh([]string{conf}) || scans != 1 {
		t.Fatal("a future modification time bypassed freshness or caused a rescan")
	}
}

func TestPureFTPDFreshnessValidatesScannedProcess(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "pure-ftpd.conf")
	if err := os.WriteFile(conf, []byte("DontResolve yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	started := time.Now().Add(time.Hour)
	fresh := newPureFTPDFreshness(func() (int, time.Time, bool) { return 10, started, true },
		func(int) (time.Time, bool) { return time.Time{}, false }, time.Now)
	if fresh([]string{conf}) {
		t.Fatal("a process that exited during the scan was approved")
	}
}

func TestFTPNumericPeerProbeChangeDuringFreshness(t *testing.T) {
	enabled := true
	old := pureFTPDServerFresh
	pureFTPDServerFresh = func([]string) bool { enabled = false; return true }
	t.Cleanup(func() { pureFTPDServerFresh = old })
	probe := newFTPNumericPeerProbe(func() ([]string, []string) {
		if enabled {
			return []string{"pure-ftpd.conf"}, nil
		}
		return []string{"pure-ftpd.conf"}, []string{"pure-ftpd.conf"}
	})
	if probe() {
		t.Fatal("DontResolve disabled during the process probe was approved")
	}
}

func TestPureFTPDFreshnessConcurrentSourceChanges(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "pure-ftpd.conf")
	if err := os.WriteFile(conf, []byte("DontResolve yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	started := time.Now().Add(time.Hour)
	scans := 0
	fresh := newPureFTPDFreshness(func() (int, time.Time, bool) {
		scans++
		return 10, started, true
	}, func(int) (time.Time, bool) { return started, true }, time.Now)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if !fresh([]string{conf}) {
				t.Error("a confirmed server was rejected")
			}
		})
	}
	wg.Wait()
	if scans != 1 {
		t.Fatalf("concurrent entries caused %d scans, want 1", scans)
	}
	// Equality must fail closed: whole-second boot time cannot prove that
	// this process began after the source changed.
	for _, changed := range []time.Time{started, started.Add(time.Second)} {
		if err := os.Chtimes(conf, changed, changed); err != nil {
			t.Fatal(err)
		}
		if fresh([]string{conf}) {
			t.Fatal("a remembered process cached approval across a source change")
		}
	}
	if scans != 1 {
		t.Fatalf("source changes caused %d scans, want 1", scans)
	}
}
