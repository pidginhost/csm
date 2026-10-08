package checks

import (
	"bytes"
	"context"
	"os"
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

// An update arriving in the completing window must keep its own queue and
// must not count the older generation as completed.
func TestYARADeepSignatureRescanUpdateDuringCompletion(t *testing.T) {
	db := useRollingStore(t)
	cfg, first := rescanRoot(t)
	putYARADeepCursor(t, db, first, time.Now().UTC())
	queueSignatureRescan(t, db)
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, false), "clean two", "clean three")
	before := signatureRescansCompleted(t)
	var newer uint64
	backend := &recordingYARABackend{onScan: func() {
		if newer == 0 {
			newer = queueSignatureRescan(t, db)
		}
	}}
	yara.SetActive(backend)
	t.Cleanup(func() { yara.SetActive(nil) })
	CheckYARADeep(context.Background(), cfg, nil)
	wantScanned(t, backend.scanned, "clean one", "clean two", "clean three")
	if newer == 0 || queuedSignatureRescan(t, db) != newer {
		t.Fatal("completing the older lap cleared the update that arrived during it")
	}
	if got := signatureRescansCompleted(t); got != before {
		t.Fatalf("superseded lap counted as completed: got %v, want %v", got, before)
	}
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, false), "clean one", "clean two", "clean three")
	if queuedSignatureRescan(t, db) != 0 || signatureRescansCompleted(t) != before+1 {
		t.Fatal("the newer generation did not complete exactly once after its own pass")
	}
}

// A sibling consumer completing the shared walk cannot acknowledge YARA
// coverage while the YARA backend is unavailable.
func TestYARADeepSignatureRescanWaitsForBackend(t *testing.T) {
	db := useRollingStore(t)
	cfg, first := rescanRoot(t)
	putYARADeepCursor(t, db, first, time.Now().UTC())
	gen := queueSignatureRescan(t, db)
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, false), "clean two", "clean three")
	before := signatureRescansCompleted(t)
	prior, ok, err := db.GetScanCursor("", yaraDeepCursorCheck)
	if err != nil || !ok {
		t.Fatalf("YARA cursor missing before backend outage: ok=%v err=%v", ok, err)
	}
	root := cfg.AccountRoots[0]
	jsPath := writeYARADeepFile(t, root, "a/keylogger.js", jsKeyloggerFixture)
	restore := useNilYARABackend(t)
	findings := CheckYARADeep(context.Background(), cfg, nil)
	jsFindings := jsFindingsByCheck(findings, "js_keylogger_dataflow")
	if len(jsFindings) != 1 || jsFindings[0].FilePath != jsPath {
		t.Fatalf("sibling consumer did not finish its scan during outage: %+v", findings)
	}
	if queuedSignatureRescan(t, db) != gen || signatureRescansCompleted(t) != before {
		t.Fatal("a completed sibling scan acknowledged the unavailable YARA consumer")
	}
	if cur, ok, err := db.GetScanCursor("", yaraDeepCursorCheck); err != nil || !ok || cur != prior {
		t.Fatalf("backend outage changed YARA progress: got %+v, want %+v, err=%v", cur, prior, err)
	}
	restore()
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, false), jsKeyloggerFixture, "clean one", "clean two", "clean three")
	if queuedSignatureRescan(t, db) != 0 || signatureRescansCompleted(t) != before+1 {
		t.Fatal("recovered backend did not complete its pending generation exactly once")
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

// A prefix cursor covers the whole subtree. Reaching its first child after
// wrapping cannot acknowledge the remaining children scanned with old rules.
func TestYARADeepSignatureRescanSubtreeCursor(t *testing.T) {
	for _, multipleRoots := range []bool{false, true} {
		for _, laggingJS := range []bool{false, true} {
			name := "single root"
			if multipleRoots {
				name = "multiple roots"
			}
			if laggingJS {
				name += "/lagging JS"
			}
			t.Run(name, func(t *testing.T) {
				db := useRollingStore(t)
				root := t.TempDir()
				writeYARADeepFile(t, root, "a/one.dat", "clean one")
				writeYARADeepFile(t, root, "a/two.dat", "mal two")
				writeYARADeepFile(t, root, "z/three.dat", "clean three")
				cfg := &config.Config{AccountRoots: []string{root}}
				if multipleRoots {
					cfg.AccountRoots = []string{filepath.Join(root, "z"), filepath.Join(root, "a")}
				}
				if !laggingJS {
					cfg.DisabledChecks = []string{"js_taint_deep"}
				}
				prefix := filepath.Join(root, "a") + string(filepath.Separator)
				putYARADeepCursor(t, db, prefix, time.Now().UTC())
				gen := queueSignatureRescan(t, db)
				// Both consumers resume after a/ for the initial tail. On the
				// return lap JS may lag while YARA resumes at a/one.dat.
				if err := db.PutScanCursor(store.ScanCursorRecord{Check: jsTaintDeepCursorCheck, LastPath: prefix}); err != nil {
					t.Fatal(err)
				}
				before := signatureRescansCompleted(t)
				wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, false), "clean three")
				if queuedSignatureRescan(t, db) != gen {
					t.Fatal("tail completion cleared the rescan before wrapping")
				}
				wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, true), "clean one")
				if queuedSignatureRescan(t, db) != gen || signatureRescansCompleted(t) != before {
					t.Fatal("first child cleared the rescan while a/two.dat still needed scanning")
				}
				if laggingJS {
					if err := db.PutScanCursor(store.ScanCursorRecord{Check: jsTaintDeepCursorCheck}); err != nil {
						t.Fatal(err)
					}
				}
				wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, true), "mal two")
				wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, false), "clean three")
				if queuedSignatureRescan(t, db) != 0 || signatureRescansCompleted(t) != before+1 {
					t.Fatal("covered subtree did not complete exactly one rescan")
				}
			})
		}
	}
}

// A new root behind the current cursor has not been covered by the return
// lap. Its arrival must extend the proof without restarting the walk.
func TestYARADeepSignatureRescanAddedRootBehindCursor(t *testing.T) {
	db := useRollingStore(t)
	root := t.TempDir()
	first := writeYARADeepFile(t, root, "m/one.dat", "clean one")
	second := writeYARADeepFile(t, root, "m/two.dat", "clean two")
	writeYARADeepFile(t, root, "z/three.dat", "clean three")
	cfg := &config.Config{AccountRoots: []string{filepath.Join(root, "m"), filepath.Join(root, "z")}}
	putYARADeepCursor(t, db, second, time.Now().UTC())
	gen := queueSignatureRescan(t, db)
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, false), "clean three")
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, true), "clean one")
	if queuedSignatureRescan(t, db) != gen {
		t.Fatal("return lap cleared before reaching the original cursor")
	}
	writeYARADeepFile(t, root, "a/new.dat", "mal new root")
	cfg.AccountRoots = append(cfg.AccountRoots, filepath.Join(root, "a"))
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, true), "clean two")
	if queuedSignatureRescan(t, db) != gen {
		t.Fatal("new root behind the cursor was skipped but the rescan cleared")
	}
	cur, ok, err := db.GetScanCursor("", yaraDeepCursorCheck)
	if err != nil || !ok || cur.LastPath != second || cur.RulesFrom != first || cur.RulesWrapped {
		t.Fatalf("root change lost forward progress or reused the old lap: %+v, %v", cur, err)
	}
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, false), "clean three")
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, true), "mal new root")
	if queuedSignatureRescan(t, db) != gen {
		t.Fatal("new lap cleared before covering its starting point")
	}
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, true), "clean one")
	if queuedSignatureRescan(t, db) != 0 {
		t.Fatal("rescan remained queued after the added root and lap were covered")
	}
}

type rescanRootStatOS struct {
	OS
	failedRoot string
}

func (f rescanRootStatOS) Stat(path string) (os.FileInfo, error) {
	if path == f.failedRoot {
		return nil, os.ErrPermission
	}
	return f.OS.Stat(path)
}

// A failed root lookup is not proof that no files remain to be covered.
func TestYARADeepSignatureRescanRootLookupFailure(t *testing.T) {
	db := useRollingStore(t)
	cfg, _ := rescanRoot(t)
	gen := queueSignatureRescan(t, db)
	prev := osFS
	osFS = rescanRootStatOS{OS: prev, failedRoot: cfg.AccountRoots[0]}
	t.Cleanup(func() { osFS = prev })
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, false))
	if queuedSignatureRescan(t, db) != gen {
		t.Fatal("unresolved root was acknowledged as fully scanned")
	}
	osFS = prev
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, false), "clean one", "clean two", "clean three")
	if queuedSignatureRescan(t, db) != 0 {
		t.Fatal("recovered root did not complete the rescan")
	}
}

func TestYARADeepSignatureRescanRootLookupFailureAfterWrap(t *testing.T) {
	for _, pause := range []bool{false, true} {
		name := "tracking enabled"
		if pause {
			name = "tracking paused"
		}
		t.Run(name, func(t *testing.T) {
			db := useRollingStore(t)
			root := t.TempDir()
			writeYARADeepFile(t, root, "a/early.dat", "mal early")
			writeYARADeepFile(t, root, "m/one.dat", "clean one")
			second := writeYARADeepFile(t, root, "m/two.dat", "clean two")
			writeYARADeepFile(t, root, "z/three.dat", "clean three")
			cfg := &config.Config{AccountRoots: []string{
				filepath.Join(root, "a"), filepath.Join(root, "m"), filepath.Join(root, "z"),
			}}
			putYARADeepCursor(t, db, second, time.Now().UTC())
			gen := queueSignatureRescan(t, db)
			wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, false), "clean three")
			if pause {
				off := false
				cfg.Detection.RescanOnSignatureUpdate = &off
			}
			prev := osFS
			osFS = rescanRootStatOS{OS: prev, failedRoot: filepath.Join(root, "a")}
			t.Cleanup(func() { osFS = prev })
			wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, true), "clean one")
			osFS = prev
			cfg.Detection.RescanOnSignatureUpdate = nil
			wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, true), "clean two")
			if queuedSignatureRescan(t, db) != gen {
				t.Fatal("recovered lookup reused a lap that skipped the early root")
			}
			wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, false), "clean three")
			wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, true), "mal early")
			if queuedSignatureRescan(t, db) != gen {
				t.Fatal("rescan cleared before reaching the recovered lap's origin")
			}
			wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, true), "clean one")
			if queuedSignatureRescan(t, db) != 0 {
				t.Fatal("recovered lap did not complete")
			}
		})
	}
}

func TestYARADeepSignatureRescanRemovedOriginRoot(t *testing.T) {
	db := useRollingStore(t)
	root := t.TempDir()
	writeYARADeepFile(t, root, "m/one.dat", "clean one")
	second := writeYARADeepFile(t, root, "m/two.dat", "clean two")
	writeYARADeepFile(t, root, "z/three.dat", "clean three")
	cfg := &config.Config{AccountRoots: []string{filepath.Join(root, "m"), filepath.Join(root, "z")}}
	putYARADeepCursor(t, db, second, time.Now().UTC())
	queueSignatureRescan(t, db)
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, false), "clean three")
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, true), "clean one")
	cfg.AccountRoots = []string{filepath.Join(root, "z")}
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, false), "clean three")
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, false), "clean three")
	if queuedSignatureRescan(t, db) != 0 {
		t.Fatal("removed origin root left the rescan pending indefinitely")
	}
}

// Equivalent root spellings must not discard a lap that already wrapped.
func TestYARADeepSignatureRescanReorderedRootsKeepLap(t *testing.T) {
	db := useRollingStore(t)
	root := t.TempDir()
	writeYARADeepFile(t, root, "m/one.dat", "clean one")
	second := writeYARADeepFile(t, root, "m/two.dat", "clean two")
	writeYARADeepFile(t, root, "z/three.dat", "clean three")
	cfg := &config.Config{AccountRoots: []string{filepath.Join(root, "m"), filepath.Join(root, "z")}}
	putYARADeepCursor(t, db, second, time.Now().UTC())
	queueSignatureRescan(t, db)
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, false), "clean three")
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, true), "clean one")
	cfg.AccountRoots = []string{filepath.Join(root, "z"), filepath.Join(root, "m") + "/.", filepath.Join(root, "m")}
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, true), "clean two")
	if queuedSignatureRescan(t, db) != 0 {
		t.Fatal("equivalent roots discarded the completed lap")
	}
}

func TestYARADeepSignatureRescanRestartKeepsLap(t *testing.T) {
	db := useRollingStore(t)
	cfg, first := rescanRoot(t)
	putYARADeepCursor(t, db, first, time.Now().UTC())
	queueSignatureRescan(t, db)
	before := signatureRescansCompleted(t)
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, false), "clean two", "clean three")
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(filepath.Dir(db.Path()))
	if err != nil {
		t.Fatal(err)
	}
	store.SetGlobal(reopened)
	t.Cleanup(func() { _ = reopened.Close() })
	wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, true), "clean one")
	if queuedSignatureRescan(t, reopened) != 0 || signatureRescansCompleted(t) != before+1 {
		t.Fatal("restart lost the lap or counted its completion more than once")
	}
}

// filepath.Glob suppresses I/O errors, including those encountered before
// producing a match. A hidden root must not look like an empty scan scope.
type rescanHiddenRootOS struct {
	OS
	pattern string
	parent  string
}

func (f rescanHiddenRootOS) Glob(pattern string) ([]string, error) {
	if pattern == f.pattern {
		return nil, nil
	}
	return f.OS.Glob(pattern)
}

func (f rescanHiddenRootOS) Lstat(path string) (os.FileInfo, error) {
	if strings.HasPrefix(path, f.parent+string(filepath.Separator)) {
		return nil, os.ErrPermission
	}
	return f.OS.Lstat(path)
}

func (f rescanHiddenRootOS) Stat(path string) (os.FileInfo, error) {
	if strings.HasPrefix(path, f.parent+string(filepath.Separator)) {
		return nil, os.ErrPermission
	}
	return f.OS.Stat(path)
}

func (f rescanHiddenRootOS) ReadDir(path string) ([]os.DirEntry, error) {
	if path == f.parent {
		return nil, os.ErrPermission
	}
	return f.OS.ReadDir(path)
}

func TestYARADeepSignatureRescanHiddenGlobRoot(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		want    []string
	}{
		{"a/public", []string{"mal hidden", "clean visible"}},
		{"a/*", []string{"mal hidden", "mal nested", "clean visible"}},
		{"*/public", []string{"mal hidden", "clean visible"}},
		{"*/*/public", []string{"mal nested", "clean visible"}},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			db := useRollingStore(t)
			root := t.TempDir()
			writeYARADeepFile(t, root, "a/public/hidden.dat", "mal hidden")
			writeYARADeepFile(t, root, "a/site/public/hidden.dat", "mal nested")
			writeYARADeepFile(t, root, "z/visible.dat", "clean visible")
			cfg := &config.Config{AccountRoots: []string{filepath.Join(root, tc.pattern), filepath.Join(root, "z")}}
			gen := queueSignatureRescan(t, db)
			before := signatureRescansCompleted(t)
			prev := osFS
			osFS = rescanHiddenRootOS{OS: prev, pattern: cfg.AccountRoots[0], parent: filepath.Join(root, "a")}
			t.Cleanup(func() { osFS = prev })
			wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, false), "clean visible")
			if queuedSignatureRescan(t, db) != gen || signatureRescansCompleted(t) != before {
				t.Fatal("glob I/O failure was acknowledged as an empty scan scope")
			}
			osFS = prev
			wantScanned(t, runYARADeepWindow(t, context.Background(), cfg, false), tc.want...)
			if queuedSignatureRescan(t, db) != 0 || signatureRescansCompleted(t) != before+1 {
				t.Fatal("recovered root discovery did not complete exactly one rescan")
			}
		})
	}
}
