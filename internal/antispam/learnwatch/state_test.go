package learnwatch

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

type stateFixture struct {
	*State
	now time.Time
}

func newState(t *testing.T) *stateFixture {
	t.Helper()
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	f := &stateFixture{now: t0}
	f.State = NewState(db, func() time.Time { return f.now })
	return f
}

var (
	spamKey = FolderKey{UID: 1001, Folder: ".spam"}
	curDir  = DirIdent{Dev: 1, Ino: 100, MtimeNs: 5, CtimeNs: 5}
)

func meta(ino uint64) Meta {
	return Meta{Dev: 1, Ino: ino, UID: 1001, Nlink: 1, Size: 10, MtimeNs: 7, CtimeNs: 7}
}

func (f *stateFixture) do(t *testing.T, fn func(tx StateTx) error) {
	t.Helper()
	if err := f.Update(fn); err != nil {
		t.Fatal(err)
	}
}

func (f *stateFixture) open(t *testing.T, k FolderKey, id DirIdent) (baseline bool) {
	t.Helper()
	f.do(t, func(tx StateTx) (err error) {
		baseline, _, err = tx.Open(k, "cur", id)
		return err
	})
	return baseline
}

func (f *stateFixture) observe(t *testing.T, k FolderKey, name string, m Meta) bool {
	t.Helper()
	base, ok := BaseName(name)
	if !ok {
		t.Fatalf("bad name %q", name)
	}
	var cand bool
	f.do(t, func(tx StateTx) (err error) {
		cand, err = tx.Observe(k, base, m)
		return err
	})
	return cand
}

func (f *stateFixture) entry(t *testing.T, k FolderKey, base string) (SeenEntry, bool) {
	t.Helper()
	var e SeenEntry
	var ok bool
	if err := f.View(func(tx StateTx) (err error) {
		e, ok, err = tx.Seen(k, base)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return e, ok
}

// baselined opens .spam/cur and completes an empty baseline.
func (f *stateFixture) baselined(t *testing.T, k FolderKey) {
	t.Helper()
	if !f.open(t, k, curDir) {
		t.Fatal("first open did not start a baseline")
	}
	f.do(t, func(tx StateTx) error { return tx.FinishBaseline(k) })
}

func TestBaselineReadsNothing(t *testing.T) {
	f := newState(t)
	if !f.open(t, spamKey, curDir) {
		t.Fatal("first open did not start a baseline")
	}
	for i, name := range []string{"a:2,S", "b:2,", "c"} {
		if f.observe(t, spamKey, name, meta(uint64(10+i))) {
			t.Fatalf("baseline entry %s became a candidate", name)
		}
	}
	if e, ok := f.entry(t, spamKey, "b"); !ok || e.Status != StatusBaseline || e.Ino != 11 {
		t.Fatalf("entry %+v, %v", e, ok)
	}
	f.do(t, func(tx StateTx) error { return tx.FinishBaseline(spamKey) })
	if f.observe(t, spamKey, "a:2,RS", meta(10)) {
		t.Fatal("a baselined message became a candidate after the baseline")
	}
}

func TestNewArrivalAfterBaselineIsCandidate(t *testing.T) {
	f := newState(t)
	f.baselined(t, spamKey)
	if !f.observe(t, spamKey, "new1", meta(20)) {
		t.Fatal("new arrival was not a candidate")
	}
	if e, ok := f.entry(t, spamKey, "new1"); !ok || e.Status != StatusPending || !e.FirstSeen.Equal(t0) {
		t.Fatalf("entry %+v", e)
	}
	if !f.observe(t, spamKey, "new1", meta(20)) {
		t.Fatal("a pending entry stopped being a candidate before it was marked")
	}
}

func TestSeenSurvivesFlagRename(t *testing.T) {
	f := newState(t)
	f.baselined(t, spamKey)
	cands := 0
	for _, name := range []string{"x", "x:2,", "x:2,S"} {
		if f.observe(t, spamKey, name, meta(30)) {
			cands++
			f.do(t, func(tx StateTx) error { return tx.Mark(spamKey, "x", StatusSubmitted) })
		}
	}
	if cands != 1 {
		t.Fatalf("%d candidates for one message", cands)
	}
}

func TestSameBaseDifferentInodeIsCandidate(t *testing.T) {
	f := newState(t)
	f.baselined(t, spamKey)
	f.observe(t, spamKey, "x", meta(30))
	f.do(t, func(tx StateTx) error { return tx.Mark(spamKey, "x", StatusSubmitted) })
	if !f.observe(t, spamKey, "x:2,S", meta(31)) {
		t.Fatal("a different inode under a seen name was not a candidate")
	}
	if e, _ := f.entry(t, spamKey, "x"); e.Status != StatusPending || e.Ino != 31 {
		t.Fatalf("entry %+v", e)
	}
}

func TestSeenInodeEditedIsNotCandidate(t *testing.T) {
	f := newState(t)
	f.baselined(t, spamKey)
	f.observe(t, spamKey, "x", meta(30))
	f.do(t, func(tx StateTx) error { return tx.Mark(spamKey, "x", StatusSubmitted) })
	edited := meta(30)
	edited.Size, edited.MtimeNs, edited.CtimeNs = 99, 9, 9
	if f.observe(t, spamKey, "x:2,S", edited) {
		t.Fatal("an edit to a submitted inode became a candidate")
	}
}

func TestReplacedFolderIdentityRebaselines(t *testing.T) {
	f := newState(t)
	f.baselined(t, spamKey)
	replaced := curDir
	replaced.Ino = 200
	if !f.open(t, spamKey, replaced) {
		t.Fatal("a replaced folder did not start a new baseline")
	}
	if f.observe(t, spamKey, "old-corpus", meta(40)) {
		t.Fatal("entry of a replaced folder became a candidate during its baseline")
	}
	var st FolderState
	if err := f.View(func(tx StateTx) (err error) {
		st, _, err = tx.Folder(spamKey)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if st.BaselineDone || st.Epoch != 2 {
		t.Fatalf("state %+v", st)
	}
}

func TestMissingFolderKeepsState(t *testing.T) {
	f := newState(t)
	f.baselined(t, spamKey)
	f.observe(t, spamKey, "x", meta(30))
	f.do(t, func(tx StateTx) error { return tx.Mark(spamKey, "x", StatusSubmitted) })
	// A pass that finds the folder missing records nothing; when the same
	// directory reappears it resumes.
	f.now = t0.Add(time.Hour)
	if f.open(t, spamKey, curDir) {
		t.Fatal("a reappearing folder with the same identity started a baseline")
	}
	if e, ok := f.entry(t, spamKey, "x"); !ok || e.Status != StatusSubmitted {
		t.Fatalf("entry %+v, %v", e, ok)
	}
}

func TestOpenReportsUnchangedOnlyAfterCompleteListing(t *testing.T) {
	f := newState(t)
	f.baselined(t, spamKey)
	var unchanged bool
	open := func() {
		f.do(t, func(tx StateTx) (err error) {
			_, unchanged, err = tx.Open(spamKey, "cur", curDir)
			return err
		})
	}
	if open(); unchanged {
		t.Fatal("never-listed folder reported unchanged")
	}
	f.do(t, func(tx StateTx) error { return tx.Listed(spamKey, "cur", curDir) })
	if open(); !unchanged {
		t.Fatal("listed folder with the same timestamps reported changed")
	}
	touched := curDir
	touched.MtimeNs++
	f.do(t, func(tx StateTx) (err error) {
		_, unchanged, err = tx.Open(spamKey, "cur", touched)
		return err
	})
	if unchanged {
		t.Fatal("folder with a new mtime reported unchanged")
	}
}

func TestSkippedStaysSkipped(t *testing.T) {
	f := newState(t)
	f.baselined(t, spamKey)
	f.observe(t, spamKey, "big", meta(50))
	f.do(t, func(tx StateTx) error { return tx.Mark(spamKey, "big", SkippedStatus(ReadSkipOversize.String())) })
	if f.observe(t, spamKey, "big:2,S", meta(50)) {
		t.Fatal("a skipped entry became a candidate again")
	}
	if e, _ := f.entry(t, spamKey, "big"); e.Status != "skipped:oversize" {
		t.Fatalf("entry %+v", e)
	}
}

func TestPruneAfter90Days(t *testing.T) {
	f := newState(t)
	f.baselined(t, spamKey)
	f.observe(t, spamKey, "old", meta(60))
	f.do(t, func(tx StateTx) error { return tx.Mark(spamKey, "old", StatusSubmitted) })
	f.observe(t, spamKey, "waiting", meta(61))
	f.now = t0.Add(80 * 24 * time.Hour)
	f.observe(t, spamKey, "recent", meta(62))
	f.do(t, func(tx StateTx) error { return tx.Mark(spamKey, "recent", StatusSubmitted) })
	f.now = t0.Add(SeenRetention + time.Hour)
	var pruned int
	f.do(t, func(tx StateTx) (err error) {
		pruned, err = tx.Prune()
		return err
	})
	if pruned != 1 {
		t.Fatalf("pruned %d", pruned)
	}
	if _, ok := f.entry(t, spamKey, "old"); ok {
		t.Fatal("absent entry kept past retention")
	}
	if _, ok := f.entry(t, spamKey, "waiting"); !ok {
		t.Fatal("pending entry pruned")
	}
	if _, ok := f.entry(t, spamKey, "recent"); !ok {
		t.Fatal("recent entry pruned")
	}
}

func TestObserveRefreshesLastSeenDaily(t *testing.T) {
	f := newState(t)
	f.baselined(t, spamKey)
	f.observe(t, spamKey, "kept", meta(70))
	f.do(t, func(tx StateTx) error { return tx.Mark(spamKey, "kept", StatusSubmitted) })
	for day := 1; day <= 120; day++ {
		f.now = t0.Add(time.Duration(day) * 24 * time.Hour)
		f.observe(t, spamKey, "kept:2,S", meta(70))
	}
	f.do(t, func(tx StateTx) error { _, err := tx.Prune(); return err })
	if _, ok := f.entry(t, spamKey, "kept"); !ok {
		t.Fatal("an entry still present in its folder was pruned")
	}
}

func TestOptOutReentryRebaselines(t *testing.T) {
	f := newState(t)
	f.baselined(t, spamKey)
	other := FolderKey{UID: 1002, Folder: ".spam"}
	f.baselined(t, other)
	f.observe(t, spamKey, "unsent", meta(80))
	f.observe(t, other, "kept", meta(81))
	f.do(t, func(tx StateTx) error { return tx.ResetOnOptOut(1001) })
	if _, ok := f.entry(t, spamKey, "unsent"); ok {
		t.Fatal("opt-out kept unsent work")
	}
	if _, ok := f.entry(t, other, "kept"); !ok {
		t.Fatal("opt-out of one account dropped another account's state")
	}
	if !f.open(t, spamKey, curDir) {
		t.Fatal("re-entry did not start a new baseline")
	}
	if f.observe(t, spamKey, "unsent", meta(80)) {
		t.Fatal("re-entry learned from the pre-baseline corpus")
	}
}
