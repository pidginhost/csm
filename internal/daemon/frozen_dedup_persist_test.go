package daemon

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

const (
	frozenTestIDReported   = "1aaaaa-000000AAAAA-0aa"
	frozenTestIDWhileDown  = "1bbbbb-000000BBBBB-0bb"
	frozenTestIDNewArrival = "1ccccc-000000CCCCC-0cc"
)

func openFrozenDedupTestStore(t *testing.T) *store.DB {
	t.Helper()
	prev := store.Global()
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	store.SetGlobal(db)
	t.Cleanup(func() {
		store.SetGlobal(prev)
		_ = db.Close()
	})
	return db
}

// frozenTestMainlog drives a real LogWatcher over a temporary exim mainlog,
// the same path the daemon uses, and returns the frozen findings each append
// produced.
type frozenTestMainlog struct {
	t       *testing.T
	path    string
	alertCh chan alert.Finding
	watcher *LogWatcher
}

func newFrozenTestMainlog(t *testing.T, path string) *frozenTestMainlog {
	t.Helper()
	alertCh := make(chan alert.Finding, 16)
	w, err := NewLogWatcher(path, &config.Config{}, parseEximLogLine, alertCh)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Stop)
	return &frozenTestMainlog{t: t, path: path, alertCh: alertCh, watcher: w}
}

func (m *frozenTestMainlog) appendFrozenFindings(line string) int {
	m.t.Helper()
	f, err := os.OpenFile(m.path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		m.t.Fatal(err)
	}
	if _, err := f.WriteString(line + "\n"); err != nil {
		_ = f.Close()
		m.t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		m.t.Fatal(err)
	}
	m.watcher.readNewLines()
	count := 0
	for {
		select {
		case got := <-m.alertCh:
			if got.Check == "exim_frozen_realtime" {
				count++
			}
		default:
			return count
		}
	}
}

func frozenTestLine(id, action string) string {
	return time.Now().UTC().Format("2006-01-02 15:04:05") + " " + id + " " + action
}

// Exim re-logs "Message is frozen" for every still-frozen message on the first
// queue run after a daemon restart. A message reported before the restart must
// stay suppressed, while a message that froze while the daemon was down has
// never been reported and must still raise its finding.
func TestEximFrozenRestartDoesNotReAlertReportedMessages(t *testing.T) {
	openFrozenDedupTestStore(t)
	resetEximFrozenDedup()
	t.Cleanup(resetEximFrozenDedup)
	path := filepath.Join(t.TempDir(), "exim_mainlog")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	before := newFrozenTestMainlog(t, path)
	if got := before.appendFrozenFindings(frozenTestLine(frozenTestIDReported, "Frozen (delivery error message)")); got != 1 {
		t.Fatalf("initial freeze produced %d findings, want 1", got)
	}
	d := &Daemon{}
	d.persistEximFrozenDedup()

	// Restart: in-memory state is gone, and the new watcher starts at EOF,
	// so the freeze line of a message that froze while the daemon was down
	// is never read.
	resetEximFrozenDedup()
	if err := appendRawLine(path, frozenTestLine(frozenTestIDWhileDown, "Frozen (delivery error message)")); err != nil {
		t.Fatal(err)
	}
	d.restoreEximFrozenDedup()
	after := newFrozenTestMainlog(t, path)

	if got := after.appendFrozenFindings(frozenTestLine(frozenTestIDReported, "Message is frozen")); got != 0 {
		t.Errorf("queue run after restart re-reported an already reported message (%d findings)", got)
	}
	if got := after.appendFrozenFindings(frozenTestLine(frozenTestIDWhileDown, "Message is frozen")); got != 1 {
		t.Errorf("message frozen while the daemon was down produced %d findings, want 1", got)
	}
	if got := after.appendFrozenFindings(frozenTestLine(frozenTestIDWhileDown, "Message is frozen")); got != 0 {
		t.Errorf("second queue run re-reported the message frozen while down (%d findings)", got)
	}
}

func appendRawLine(path, line string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(line + "\n"); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// An unfreeze clears the ID; the persisted snapshot must drop it too, or a
// restart would suppress the finding for a later re-freeze.
func TestEximFrozenPersistDropsUnfrozenMessages(t *testing.T) {
	db := openFrozenDedupTestStore(t)
	resetEximFrozenDedup()
	t.Cleanup(resetEximFrozenDedup)
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

	eximFrozenShouldAlert("2026-09-30 12:00:00 "+frozenTestIDReported+" Frozen (delivery error message)", now)
	if err := saveEximFrozenDedup(db); err != nil {
		t.Fatalf("save: %v", err)
	}
	eximFrozenShouldAlert("2026-09-30 12:01:00 "+frozenTestIDReported+" Unfrozen by forced delivery", now.Add(time.Minute))
	if err := saveEximFrozenDedup(db); err != nil {
		t.Fatalf("save: %v", err)
	}

	resetEximFrozenDedup()
	if err := loadEximFrozenDedup(db, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("load: %v", err)
	}
	if !eximFrozenShouldAlert("2026-09-30 12:02:00 "+frozenTestIDReported+" Frozen (delivery error message)", now.Add(2*time.Minute)) {
		t.Fatal("re-freeze after an unfreeze was suppressed by stale persisted state")
	}
}

// The TTL keeps bounding persisted state: an ID whose last sighting aged past
// it while the daemon was down is not restored.
func TestEximFrozenRestoreDropsExpiredEntries(t *testing.T) {
	db := openFrozenDedupTestStore(t)
	resetEximFrozenDedup()
	t.Cleanup(resetEximFrozenDedup)
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

	if err := db.SaveEximFrozenSeen(map[string]time.Time{
		frozenTestIDReported:  now.Add(-eximFrozenDedupTTL),
		frozenTestIDWhileDown: now.Add(-eximFrozenDedupTTL + time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if err := loadEximFrozenDedup(db, now); err != nil {
		t.Fatalf("load: %v", err)
	}
	eximFrozenDedup.mu.Lock()
	_, expiredRestored := eximFrozenDedup.seen[frozenTestIDReported]
	eximFrozenDedup.mu.Unlock()
	if expiredRestored {
		t.Error("expired persisted ID occupies a slot in the restored table")
	}
	if !eximFrozenShouldAlert("2026-09-30 12:00:00 "+frozenTestIDReported+" Message is frozen", now) {
		t.Error("expired persisted ID still suppressed the finding")
	}
	if eximFrozenShouldAlert("2026-09-30 12:00:00 "+frozenTestIDWhileDown+" Message is frozen", now) {
		t.Error("persisted ID inside the TTL did not suppress the repeat")
	}
}

// A last-seen time ahead of the clock (the clock stepped back across the
// restart, or the record is damaged) must not stretch suppression past the
// TTL; it counts as seen now.
func TestEximFrozenRestoreClampsFutureLastSeen(t *testing.T) {
	db := openFrozenDedupTestStore(t)
	resetEximFrozenDedup()
	t.Cleanup(resetEximFrozenDedup)
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

	if err := db.SaveEximFrozenSeen(map[string]time.Time{
		frozenTestIDReported: now.Add(30 * 24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if err := loadEximFrozenDedup(db, now); err != nil {
		t.Fatalf("load: %v", err)
	}
	line := "2026-10-01 12:00:00 " + frozenTestIDReported + " Frozen (delivery error message)"
	if !eximFrozenShouldAlert(line, now.Add(eximFrozenDedupTTL)) {
		t.Fatal("future last-seen time kept the ID suppressed past the TTL")
	}
}

func TestEximFrozenRestorePersistsCorrections(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		seen map[string]time.Time
		want map[string]time.Time
	}{
		{
			name: "future timestamp",
			seen: map[string]time.Time{frozenTestIDReported: now.Add(30 * 24 * time.Hour)},
			want: map[string]time.Time{frozenTestIDReported: now},
		},
		{
			name: "expired ID",
			seen: map[string]time.Time{frozenTestIDReported: now.Add(-24 * time.Hour)},
			want: map[string]time.Time{},
		},
		{
			name: "malformed ID",
			seen: map[string]time.Time{"not-a-queue-id": now, frozenTestIDReported: now},
			want: map[string]time.Time{frozenTestIDReported: now},
		},
	}
	oversized := make(map[string]time.Time, eximFrozenDedupMaxEntries+2)
	bounded := make(map[string]time.Time, eximFrozenDedupMaxEntries)
	for i := 0; i < eximFrozenDedupMaxEntries+2; i++ {
		lastSeen := now.Add(-time.Hour + time.Duration(i)*time.Millisecond)
		oversized[frozenTestID(i)] = lastSeen
		if i >= 2 {
			bounded[frozenTestID(i)] = lastSeen
		}
	}
	tests = append(tests, struct {
		name string
		seen map[string]time.Time
		want map[string]time.Time
	}{name: "excess IDs", seen: oversized, want: bounded})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := openFrozenDedupTestStore(t)
			resetEximFrozenDedup()
			t.Cleanup(resetEximFrozenDedup)
			if err := db.SaveEximFrozenSeen(tt.seen); err != nil {
				t.Fatal(err)
			}
			if err := loadEximFrozenDedup(db, now); err != nil {
				t.Fatal(err)
			}
			// No mainlog event is needed to make restored corrections durable.
			if err := saveEximFrozenDedup(db); err != nil {
				t.Fatal(err)
			}
			got, err := db.LoadEximFrozenSeen()
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("saved %d IDs, want %d after restore cleanup", len(got), len(tt.want))
			}
			for id, want := range tt.want {
				if !got[id].Equal(want) {
					t.Errorf("saved %s at %v, want %v", id, got[id], want)
				}
			}
			before := db.WriteTxID()
			if err := saveEximFrozenDedup(db); err != nil {
				t.Fatal(err)
			}
			if db.WriteTxID() != before {
				t.Fatal("saved unchanged corrections twice")
			}
		})
	}
}

func TestEximFrozenRestartsDoNotExtendCorrectedTimestamp(t *testing.T) {
	db := openFrozenDedupTestStore(t)
	resetEximFrozenDedup()
	t.Cleanup(resetEximFrozenDedup)
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	if err := db.SaveEximFrozenSeen(map[string]time.Time{
		frozenTestIDReported: now.Add(30 * 24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{now, now.Add(23 * time.Hour)} {
		resetEximFrozenDedup()
		if err := loadEximFrozenDedup(db, at); err != nil {
			t.Fatal(err)
		}
		if err := saveEximFrozenDedup(db); err != nil {
			t.Fatal(err)
		}
	}
	if !eximFrozenShouldAlert("2026-10-01 12:00:00 "+frozenTestIDReported+" Message is frozen", now.Add(24*time.Hour)) {
		t.Fatal("another restart extended suppression beyond a day after the clock correction")
	}
}

// Only IDs the parser could have produced are restored; anything else in the
// bucket is damage and must not occupy capacity.
func TestEximFrozenRestoreIgnoresMalformedIDs(t *testing.T) {
	db := openFrozenDedupTestStore(t)
	resetEximFrozenDedup()
	t.Cleanup(resetEximFrozenDedup)
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

	if err := db.SaveEximFrozenSeen(map[string]time.Time{
		"not-a-queue-id":     now,
		frozenTestIDReported: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := loadEximFrozenDedup(db, now); err != nil {
		t.Fatalf("load: %v", err)
	}
	eximFrozenDedup.mu.Lock()
	defer eximFrozenDedup.mu.Unlock()
	if _, ok := eximFrozenDedup.seen["not-a-queue-id"]; ok {
		t.Error("malformed ID was restored")
	}
	if _, ok := eximFrozenDedup.seen[frozenTestIDReported]; !ok {
		t.Error("valid ID was not restored")
	}
}

// A snapshot larger than the cap (written before the cap shrank, or damaged)
// restores only the most recently seen IDs.
func TestEximFrozenRestoreKeepsMostRecentWithinCap(t *testing.T) {
	db := openFrozenDedupTestStore(t)
	resetEximFrozenDedup()
	t.Cleanup(resetEximFrozenDedup)
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

	persisted := make(map[string]time.Time, eximFrozenDedupMaxEntries+2)
	for i := 0; i < eximFrozenDedupMaxEntries+2; i++ {
		persisted[frozenTestID(i)] = now.Add(-time.Hour + time.Duration(i)*time.Millisecond)
	}
	if err := db.SaveEximFrozenSeen(persisted); err != nil {
		t.Fatal(err)
	}
	if err := loadEximFrozenDedup(db, now); err != nil {
		t.Fatalf("load: %v", err)
	}
	eximFrozenDedup.mu.Lock()
	defer eximFrozenDedup.mu.Unlock()
	if got := len(eximFrozenDedup.seen); got != eximFrozenDedupMaxEntries {
		t.Fatalf("restored %d IDs, want cap %d", got, eximFrozenDedupMaxEntries)
	}
	for _, oldest := range []string{frozenTestID(0), frozenTestID(1)} {
		if _, ok := eximFrozenDedup.seen[oldest]; ok {
			t.Errorf("oldest ID %s restored over newer ones", oldest)
		}
	}
	if _, ok := eximFrozenDedup.seen[frozenTestID(eximFrozenDedupMaxEntries+1)]; !ok {
		t.Error("newest ID was not restored")
	}
	// The restored order must match the last sightings, so the first eviction
	// after a restart drops the stalest restored ID.
	if front := eximFrozenDedup.order.Front().Value.(*eximFrozenSighting).id; front != frozenTestID(2) {
		t.Errorf("stalest restored ID is %s, want %s", front, frozenTestID(2))
	}
}

// seedEximFrozenSighting records id as seen at lastSeen, most recently of all.
func seedEximFrozenSighting(id string, lastSeen time.Time) {
	eximFrozenDedup.mu.Lock()
	defer eximFrozenDedup.mu.Unlock()
	eximFrozenDedup.seen[id] = eximFrozenDedup.order.PushBack(&eximFrozenSighting{id: id, lastSeen: lastSeen})
}

func frozenTestID(i int) string {
	s := strconv.Itoa(i)
	for len(s) < 6 {
		s = "0" + s
	}
	return "1ddddd-" + s + "-0dd"
}

// At capacity the dedup must drop the ID no queue run has refreshed for the
// longest: that is the message most likely already gone (exim logs no unfreeze
// when a frozen message is removed). A message still being re-logged by queue
// runs must keep its record, or each new freeze would re-arm a live one.
func TestEximFrozenDedupEvictsLeastRecentlySeen(t *testing.T) {
	resetEximFrozenDedup()
	t.Cleanup(resetEximFrozenDedup)
	start := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	for i := 0; i < eximFrozenDedupMaxEntries; i++ {
		seedEximFrozenSighting(frozenTestID(i), start.Add(time.Duration(i)*time.Millisecond))
	}
	eximFrozenDedup.mu.Lock()
	eximFrozenDedup.nextPrune = start.Add(eximFrozenDedupPruneInterval)
	eximFrozenDedup.mu.Unlock()
	// A queue run re-logs the first-seen message, so it is no longer the
	// stalest; the second-seen one is.
	if eximFrozenShouldAlert("2026-09-30 12:00:01 "+frozenTestID(0)+" Message is frozen", start.Add(time.Second)) {
		t.Fatal("queue-run repeat of a tracked ID must not alert")
	}
	stalest := frozenTestID(1)

	if !eximFrozenShouldAlert("2026-09-30 12:00:02 "+frozenTestIDNewArrival+" Frozen (delivery error message)", start.Add(2*time.Second)) {
		t.Fatal("new queue ID at capacity must alert")
	}
	eximFrozenDedup.mu.Lock()
	defer eximFrozenDedup.mu.Unlock()
	if _, ok := eximFrozenDedup.seen[stalest]; ok {
		t.Error("least recently seen ID survived eviction")
	}
	if got := eximFrozenDedup.order.Len(); got != eximFrozenDedupMaxEntries {
		t.Errorf("dedup order has %d entries, want cap %d", got, eximFrozenDedupMaxEntries)
	}
	for _, live := range []string{frozenTestID(0), frozenTestID(2), frozenTestID(eximFrozenDedupMaxEntries - 1), frozenTestIDNewArrival} {
		if _, ok := eximFrozenDedup.seen[live]; !ok {
			t.Errorf("recently seen ID %s was evicted", live)
		}
	}
}

// Saving is a whole-bucket rewrite; with nothing changed since the last save
// the periodic persist must not write at all.
func TestEximFrozenPersistSkipsUnchangedState(t *testing.T) {
	db := openFrozenDedupTestStore(t)
	resetEximFrozenDedup()
	t.Cleanup(resetEximFrozenDedup)
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

	eximFrozenShouldAlert("2026-09-30 12:00:00 "+frozenTestIDReported+" Frozen (delivery error message)", now)
	if err := saveEximFrozenDedup(db); err != nil {
		t.Fatalf("save: %v", err)
	}
	before := db.WriteTxID()
	if err := saveEximFrozenDedup(db); err != nil {
		t.Fatalf("save: %v", err)
	}
	if got := db.WriteTxID(); got != before {
		t.Fatalf("unchanged state committed %d write transaction(s)", got-before)
	}

	// A queue-run repeat refreshes the last-seen time, which the snapshot
	// must carry so the TTL after a restart counts from the latest sighting.
	later := now.Add(time.Hour)
	eximFrozenShouldAlert("2026-09-30 13:00:00 "+frozenTestIDReported+" Message is frozen", later)
	if err := saveEximFrozenDedup(db); err != nil {
		t.Fatalf("save: %v", err)
	}
	persisted, err := db.LoadEximFrozenSeen()
	if err != nil {
		t.Fatal(err)
	}
	if !persisted[frozenTestIDReported].Equal(later) {
		t.Fatalf("persisted last seen = %v, want refreshed %v", persisted[frozenTestIDReported], later)
	}
}

// Without a state store the daemon keeps working in memory only.
func TestEximFrozenPersistenceWithoutStoreIsNoop(t *testing.T) {
	prev := store.Global()
	store.SetGlobal(nil)
	t.Cleanup(func() { store.SetGlobal(prev) })
	resetEximFrozenDedup()
	t.Cleanup(resetEximFrozenDedup)

	d := &Daemon{}
	d.restoreEximFrozenDedup()
	eximFrozenShouldAlert(frozenTestLine(frozenTestIDReported, "Frozen (delivery error message)"), time.Now())
	d.persistEximFrozenDedup()
}

// A crash skips the shutdown save, so the periodic writer is what bounds the
// IDs a crash can lose. It must save changed state while the daemon runs and
// exit on stop.
func TestEximFrozenPeriodicPersistenceSavesChangedState(t *testing.T) {
	db := openFrozenDedupTestStore(t)
	resetEximFrozenDedup()
	t.Cleanup(resetEximFrozenDedup)
	prevInterval := eximFrozenDedupPersistInterval
	eximFrozenDedupPersistInterval = 5 * time.Millisecond
	t.Cleanup(func() { eximFrozenDedupPersistInterval = prevInterval })

	d := &Daemon{stopCh: make(chan struct{})}
	d.startEximFrozenDedupPersistence()
	eximFrozenShouldAlert(frozenTestLine(frozenTestIDReported, "Frozen (delivery error message)"), time.Now())

	deadline := time.Now().Add(5 * time.Second)
	for {
		persisted, err := db.LoadEximFrozenSeen()
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := persisted[frozenTestIDReported]; ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("periodic writer never saved the reported message")
		}
		time.Sleep(5 * time.Millisecond)
	}

	close(d.stopCh)
	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("periodic writer did not exit on stop")
	}
}

// The restore must happen when the log watchers start, before the first
// mainlog line is read.
func TestStartLogWatchersRestoresFrozenDedup(t *testing.T) {
	db := openFrozenDedupTestStore(t)
	resetEximFrozenDedup()
	t.Cleanup(resetEximFrozenDedup)
	if err := db.SaveEximFrozenSeen(map[string]time.Time{frozenTestIDReported: time.Now()}); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	d := New(cfg, nil, nil, "")
	d.hijackDetector = NewPasswordHijackDetector(cfg, d.alertCh, d.stopCh)
	d.startLogWatchers()
	t.Cleanup(func() {
		close(d.stopCh)
		d.wg.Wait()
	})

	eximFrozenDedup.mu.Lock()
	_, restored := eximFrozenDedup.seen[frozenTestIDReported]
	eximFrozenDedup.mu.Unlock()
	if !restored {
		t.Fatal("starting the log watchers did not restore the persisted frozen-message table")
	}
}

// Between prune sweeps an expired ID must still re-arm on its own lookup; the
// sweep only reclaims table space.
func TestEximFrozenExpiryBetweenPruneSweeps(t *testing.T) {
	resetEximFrozenDedup()
	t.Cleanup(resetEximFrozenDedup)
	start := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	freeze := func(id string, at time.Time) bool {
		return eximFrozenShouldAlert(at.Format("2006-01-02 15:04:05")+" "+id+" Frozen (delivery error message)", at)
	}

	if !freeze(frozenTestIDReported, start) {
		t.Fatal("initial freeze should alert")
	}
	// This sweep runs 30 minutes before the first ID expires and schedules
	// the next one an hour later.
	if !freeze(frozenTestIDWhileDown, start.Add(eximFrozenDedupTTL-30*time.Minute)) {
		t.Fatal("second message should alert")
	}
	if !freeze(frozenTestIDReported, start.Add(eximFrozenDedupTTL)) {
		t.Fatal("ID past the TTL stayed suppressed until the next sweep")
	}
}

// The sweep drops IDs whose last sighting is past the TTL, so messages that
// left the queue without an unfreeze line do not hold table slots.
func TestEximFrozenPruneSweepReclaimsExpiredIDs(t *testing.T) {
	resetEximFrozenDedup()
	t.Cleanup(resetEximFrozenDedup)
	start := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	freeze := func(id string, at time.Time) {
		eximFrozenShouldAlert(at.Format("2006-01-02 15:04:05")+" "+id+" Frozen (delivery error message)", at)
	}

	freeze(frozenTestIDReported, start)
	freeze(frozenTestIDWhileDown, start.Add(2*time.Hour))
	freeze(frozenTestIDNewArrival, start.Add(eximFrozenDedupTTL+time.Minute))

	eximFrozenDedup.mu.Lock()
	defer eximFrozenDedup.mu.Unlock()
	if _, ok := eximFrozenDedup.seen[frozenTestIDReported]; ok {
		t.Error("sweep kept an ID past the TTL")
	}
	if got := eximFrozenDedup.order.Len(); got != 2 {
		t.Errorf("table holds %d IDs after the sweep, want 2", got)
	}
}

func TestEximFrozenEvictionFollowsObservationsAfterClockStepBack(t *testing.T) {
	resetEximFrozenDedup()
	t.Cleanup(resetEximFrozenDedup)
	start := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	freeze := func(id string, at time.Time) bool {
		return eximFrozenShouldAlert(at.Format("2006-01-02 15:04:05")+" "+id+" Message is frozen", at)
	}
	for i := 0; i < eximFrozenDedupMaxEntries; i++ {
		if !freeze(frozenTestID(i), start.Add(time.Duration(i)*time.Millisecond)) {
			t.Fatalf("new ID %d was suppressed", i)
		}
	}
	back := start.Add(-2 * time.Hour)
	if freeze(frozenTestID(0), back) {
		t.Fatal("clock step back re-reported a tracked message")
	}
	if !freeze(frozenTestIDNewArrival, back.Add(time.Second)) {
		t.Fatal("overflow hid a new freeze after the clock step back")
	}
	if freeze(frozenTestID(0), back.Add(2*time.Second)) {
		t.Fatal("eviction discarded the recently observed message because its timestamp was earlier")
	}
	if !freeze(frozenTestID(1), back.Add(3*time.Second)) {
		t.Fatal("overflow did not evict the least recently observed message")
	}
}

func TestEximFrozenPruneScansPastNewerTimestamp(t *testing.T) {
	db := openFrozenDedupTestStore(t)
	resetEximFrozenDedup()
	t.Cleanup(resetEximFrozenDedup)
	start := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	freeze := func(id string, at time.Time) {
		eximFrozenShouldAlert(at.Format("2006-01-02 15:04:05")+" "+id+" Message is frozen", at)
	}
	freeze(frozenTestIDReported, start)
	// The list follows observation order, so its timestamps need not increase.
	freeze(frozenTestIDWhileDown, start.Add(-2*time.Hour))
	freeze(frozenTestIDNewArrival, start.Add(22*time.Hour))
	if err := saveEximFrozenDedup(db); err != nil {
		t.Fatal(err)
	}
	got, err := db.LoadEximFrozenSeen()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("saved %d IDs, want only the two unexpired messages", len(got))
	}
	for _, id := range []string{frozenTestIDReported, frozenTestIDNewArrival} {
		if _, ok := got[id]; !ok {
			t.Errorf("unexpired message %s was pruned", id)
		}
	}
}

func TestEximFrozenPeriodicStopLeavesFinalSaveToCaller(t *testing.T) {
	db := openFrozenDedupTestStore(t)
	resetEximFrozenDedup()
	t.Cleanup(resetEximFrozenDedup)
	prevInterval := eximFrozenDedupPersistInterval
	eximFrozenDedupPersistInterval = time.Hour
	t.Cleanup(func() { eximFrozenDedupPersistInterval = prevInterval })
	d := &Daemon{stopCh: make(chan struct{})}
	eximFrozenShouldAlert(frozenTestLine(frozenTestIDReported, "Message is frozen"), time.Now())
	close(d.stopCh)
	d.startEximFrozenDedupPersistence()
	d.wg.Wait()
	got, err := db.LoadEximFrozenSeen()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatal("periodic writer saved on stop instead of leaving the save to shutdown")
	}
	d.persistEximFrozenDedup()
	got, err = db.LoadEximFrozenSeen()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatal("final save lost the unsaved freeze")
	}
	if _, ok := got[frozenTestIDReported]; !ok {
		t.Fatal("final save omitted the reported message")
	}
}

func TestEximFrozenPersistRetriesFailedSave(t *testing.T) {
	db := openFrozenDedupTestStore(t)
	resetEximFrozenDedup()
	t.Cleanup(resetEximFrozenDedup)
	eximFrozenShouldAlert(frozenTestLine(frozenTestIDReported, "Message is frozen"), time.Now())
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := saveEximFrozenDedup(db); err == nil {
		t.Fatal("save to a closed database succeeded")
	}
	reopened, err := store.Open(filepath.Dir(db.Path()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := saveEximFrozenDedup(reopened); err != nil {
		t.Fatal(err)
	}
	resetEximFrozenDedup()
	if err := loadEximFrozenDedup(reopened, time.Now()); err != nil {
		t.Fatal(err)
	}
	if eximFrozenShouldAlert(frozenTestLine(frozenTestIDReported, "Message is frozen"), time.Now()) {
		t.Fatal("failed save was marked clean, so the retry lost the reported message")
	}
}
