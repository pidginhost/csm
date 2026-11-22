package daemon

import (
	"os"
	"path/filepath"
	"strings"
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
