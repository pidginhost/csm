package checks

import (
	"bytes"
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/metrics"
	"github.com/pidginhost/csm/internal/store"
	"github.com/pidginhost/csm/internal/yara"
)

// runYARADeepWindow runs one deep YARA window over cfg's roots and returns the
// contents it scanned. With stopAfterFirst the soft deadline passes after the
// first scanned file, as it does when the heavy-check budget runs out.
func runYARADeepWindow(t *testing.T, ctx context.Context, cfg *config.Config, stopAfterFirst bool) []string {
	t.Helper()
	base := time.Now().Add(time.Hour)
	clock := base
	backend := &recordingYARABackend{}
	if stopAfterFirst {
		backend.onScan = func() { clock = clock.Add(2 * yaraDeepDeadlineMargin) }
	}
	yara.SetActive(backend)
	t.Cleanup(func() { yara.SetActive(nil) })
	useYARADeepClock(t, &clock)
	ctx, cancel := context.WithDeadline(ctx, base.Add(yaraDeepDeadlineMargin+time.Minute))
	defer cancel()
	CheckYARADeep(ctx, cfg, nil)
	return backend.scanned
}

func queuedSignatureRescan(t *testing.T, db *store.DB) uint64 {
	t.Helper()
	gen, err := db.SignatureRescanPending()
	if err != nil {
		t.Fatal(err)
	}
	return gen
}

func queueSignatureRescan(t *testing.T, db *store.DB) uint64 {
	t.Helper()
	gen, err := db.PutSignatureFilesWithRescan(nil)
	if err != nil {
		t.Fatal(err)
	}
	return gen
}

func signatureRescansCompleted(t *testing.T) float64 {
	t.Helper()
	var buf bytes.Buffer
	if err := metrics.WriteOpenMetrics(&buf); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(buf.String(), "\n") {
		if value, ok := strings.CutPrefix(line, "csm_signature_rescans_total "); ok {
			n, err := strconv.ParseFloat(value, 64)
			if err != nil {
				t.Fatal(err)
			}
			return n
		}
	}
	return 0
}

// rescanRoot lays out three files in walk order: a/one, m/two, z/three.
func rescanRoot(t *testing.T) (*config.Config, string) {
	t.Helper()
	root := t.TempDir()
	first := writeYARADeepFile(t, root, "a/one.dat", "clean one")
	writeYARADeepFile(t, root, "m/two.dat", "clean two")
	writeYARADeepFile(t, root, "z/three.dat", "clean three")
	return &config.Config{AccountRoots: []string{root}}, first
}

func wantScanned(t *testing.T, got []string, want ...string) {
	t.Helper()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("scanned %q, want %q", got, want)
	}
}

// A rules update does not restart the walk: restarting on every update would
// never reach the paths that sort last when updates come faster than a pass.
// The queued rescan clears only after the walk has come back round to where
// it stood at the update, so every file was scanned with the new rules.
func TestYARADeepSignatureRescanWaitsForFullPass(t *testing.T) {
	db := useRollingStore(t)
	cfg, first := rescanRoot(t)
	// The old rules already covered a/one in the current pass.
	putYARADeepCursor(t, db, first, time.Now().UTC())
	gen := queueSignatureRescan(t, db)
	before := signatureRescansCompleted(t)

	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, true), "clean two")
	if queuedSignatureRescan(t, db) != gen {
		t.Fatal("rescan cleared before the pass wrapped")
	}
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, false), "clean three")
	if queuedSignatureRescan(t, db) != gen {
		t.Fatal("rescan cleared before a/one was scanned with the new rules")
	}
	if got := signatureRescansCompleted(t); got != before {
		t.Fatalf("completed rescans = %v before the pass reached a/one, want %v", got, before)
	}
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, true), "clean one")
	if got := queuedSignatureRescan(t, db); got != 0 {
		t.Fatalf("rescan still queued (%d) after every file was scanned with the new rules", got)
	}
	if got := signatureRescansCompleted(t); got != before+1 {
		t.Fatalf("completed rescans = %v, want %v", got, before+1)
	}
}

func TestYARADeepSignatureRescanFromPassStart(t *testing.T) {
	db := useRollingStore(t)
	cfg, _ := rescanRoot(t)
	gen := queueSignatureRescan(t, db)

	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, true), "clean one")
	if queuedSignatureRescan(t, db) != gen {
		t.Fatal("rescan cleared by a partial pass")
	}
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, false), "clean two", "clean three")
	if got := queuedSignatureRescan(t, db); got != 0 {
		t.Fatalf("rescan still queued (%d) after a pass that started with the new rules completed", got)
	}
}

// An update during the pass makes the files already scanned stale again, so
// the newer generation needs its own full pass from where the walk stands.
func TestYARADeepSignatureRescanNewerUpdateNeedsItsOwnPass(t *testing.T) {
	db := useRollingStore(t)
	cfg, _ := rescanRoot(t)
	queueSignatureRescan(t, db)

	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, true), "clean one")
	newer := queueSignatureRescan(t, db)
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, false), "clean two", "clean three")
	if queuedSignatureRescan(t, db) != newer {
		t.Fatal("finishing the older pass cleared the newer rescan")
	}
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, true), "clean one")
	if got := queuedSignatureRescan(t, db); got != 0 {
		t.Fatalf("newer rescan still queued (%d) after its full pass", got)
	}
}

// The newer generation must not inherit the older one's wrap: the files the
// walk covered before the newer update are stale again.
func TestYARADeepSignatureRescanNewerUpdateAfterWrapNeedsItsOwnPass(t *testing.T) {
	db := useRollingStore(t)
	cfg, first := rescanRoot(t)
	putYARADeepCursor(t, db, first, time.Now().UTC())
	queueSignatureRescan(t, db)

	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, false), "clean two", "clean three")
	newer := queueSignatureRescan(t, db)
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, true), "clean one")
	if queuedSignatureRescan(t, db) != newer {
		t.Fatal("the newer rescan cleared before its own pass wrapped")
	}
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, false), "clean two", "clean three")
	if got := queuedSignatureRescan(t, db); got != 0 {
		t.Fatalf("newer rescan still queued (%d) after its full pass", got)
	}
}

// Turning rescans off pauses the queue without losing the pass progress.
func TestYARADeepSignatureRescanKillSwitchPausesQueue(t *testing.T) {
	db := useRollingStore(t)
	cfg, first := rescanRoot(t)
	putYARADeepCursor(t, db, first, time.Now().UTC())
	gen := queueSignatureRescan(t, db)

	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, false), "clean two", "clean three")
	off := false
	cfg.Detection.RescanOnSignatureUpdate = &off
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, true), "clean one")
	if queuedSignatureRescan(t, db) != gen {
		t.Fatal("disabled rescans cleared the queue")
	}
	on := true
	cfg.Detection.RescanOnSignatureUpdate = &on
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, true), "clean two")
	if got := queuedSignatureRescan(t, db); got != 0 {
		t.Fatalf("re-enabled rescan still queued (%d) after its pass completed", got)
	}
}

// With rescans off the update is not tracked at all, so turning them back on
// starts the pass from where the walk then stands.
func TestYARADeepSignatureRescanQueuedWhileOffStartsWhenEnabled(t *testing.T) {
	db := useRollingStore(t)
	cfg, _ := rescanRoot(t)
	off := false
	cfg.Detection.RescanOnSignatureUpdate = &off
	gen := queueSignatureRescan(t, db)

	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, true), "clean one")
	on := true
	cfg.Detection.RescanOnSignatureUpdate = &on
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, false), "clean two", "clean three")
	if queuedSignatureRescan(t, db) != gen {
		t.Fatal("rescan cleared although a/one was scanned while rescans were off")
	}
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, true), "clean one")
	if got := queuedSignatureRescan(t, db); got != 0 {
		t.Fatalf("rescan still queued (%d) after its pass completed", got)
	}
}

// A window cut short by its context writes no progress, so it cannot finish
// the pass either.
func TestYARADeepSignatureRescanCancelledWindowKeepsQueue(t *testing.T) {
	db := useRollingStore(t)
	cfg, _ := rescanRoot(t)
	gen := queueSignatureRescan(t, db)

	ctx, cancel := context.WithCancel(context.Background())
	backend := &recordingYARABackend{onScan: cancel}
	yara.SetActive(backend)
	t.Cleanup(func() { yara.SetActive(nil) })
	CheckYARADeep(ctx, cfg, nil)
	if queuedSignatureRescan(t, db) != gen {
		t.Fatal("a cancelled window cleared the rescan")
	}
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, false), "clean one", "clean two", "clean three")
	if got := queuedSignatureRescan(t, db); got != 0 {
		t.Fatalf("rescan still queued (%d) after its pass completed", got)
	}
}

// An unreadable queue record says nothing about what is owed. The watcher
// repairs it with a fresh generation; the walk must not clear it meanwhile.
func TestYARADeepSignatureRescanCorruptQueueIsLeftForRepair(t *testing.T) {
	db := useRollingStore(t)
	cfg, _ := rescanRoot(t)
	queueSignatureRescan(t, db)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := bolt.Open(db.Path(), 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	err = raw.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("sig_watch")).Put([]byte("rescan"), []byte("{"))
	})
	if closeErr := raw.Close(); err != nil || closeErr != nil {
		t.Fatalf("corrupt fixture: %v, close: %v", err, closeErr)
	}
	reopened, err := store.Open(filepath.Dir(db.Path()))
	if err != nil {
		t.Fatal(err)
	}
	store.SetGlobal(reopened)
	t.Cleanup(func() { _ = reopened.Close() })

	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, false), "clean one", "clean two", "clean three")
	if _, err := reopened.SignatureRescanPending(); err == nil {
		t.Fatal("the walk rewrote a queue record it could not read")
	}
}
