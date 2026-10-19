package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/antispam/learn"
	"github.com/pidginhost/csm/internal/antispam/learnwatch"
	"github.com/pidginhost/csm/internal/antispam/reconcile"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/store"
)

func useLearningDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "learning")
	saved := learningDir
	learningDir = dir
	t.Cleanup(func() { learningDir = saved })
	return dir
}

// writeKeys stands in for a generated key set (hostfacts tests cover the
// generation, which needs root-owned directories).
func writeKeys(t *testing.T, dir, prefix string) string {
	t.Helper()
	keys := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keys, antispam.KeyPrefix), []byte(prefix), 0o600); err != nil {
		t.Fatal(err)
	}
	return prefix
}

func TestFreshNamespaceRequiresLearningDisabled(t *testing.T) {
	d := newLearningDaemon(t)
	dir := useLearningDir(t)
	writeKeys(t, dir, "csmfz_00000000000000000000000000000001")
	if _, err := (&ControlListener{d: d}).handleAntispamLearnFresh(nil); err == nil || !strings.Contains(err.Error(), "disable") {
		t.Fatalf("fresh namespace with learning enabled: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("refused request moved the learning directory: %v", err)
	}
}

func TestFreshNamespaceArchivesAndClears(t *testing.T) {
	d := newDaemonForListener(t)
	_, closeDB := openTestBoltStore(t, t.TempDir())
	t.Cleanup(closeDB)
	db := store.Global()
	dir := useLearningDir(t)
	old := writeKeys(t, dir, "csmfz_00000000000000000000000000000001")
	if err := learn.Open(db).Bind("gen-old", old); err != nil {
		t.Fatal(err)
	}
	if err := learn.Open(db).MarkDeclaredRestore(t0Fresh); err != nil {
		t.Fatal(err)
	}
	k := learnwatch.FolderKey{UID: 1001, Folder: ".spam"}
	if err := learnwatch.NewState(db, nil).Update(func(tx learnwatch.StateTx) error {
		_, _, err := tx.Open(k, "cur", learnwatch.DirIdent{Dev: 1, Ino: 2})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := (&ControlListener{d: d}).handleAntispamLearnFresh(nil)
	if err != nil {
		t.Fatal(err)
	}
	res := raw.(control.AntispamLearnFreshResult)
	if !strings.HasPrefix(res.Archived, dir+".old-") {
		t.Fatalf("archived to %q", res.Archived)
	}
	if _, err = os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("learning directory still in place: %v", err)
	}
	if _, err = os.Stat(filepath.Join(res.Archived, "keys", antispam.KeyPrefix)); err != nil {
		t.Fatalf("old key set not kept: %v", err)
	}
	if err = db.LearnView(func(tx store.LearnTx) error {
		for _, b := range append(append([]string{}, store.LearnBuckets...), store.WatchBuckets...) {
			if iterErr := tx.ForEach(b, func(_, _ []byte) error {
				t.Errorf("bucket %s kept a record", b)
				return nil
			}); iterErr != nil {
				return iterErr
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// With no key set left at the learning path, the next enable generates
	// new hash keys, transport keys and prefix.
	if _, err = os.Stat(filepath.Join(dir, "keys", antispam.KeyPrefix)); !os.IsNotExist(err) {
		t.Fatalf("old key set still reachable: %v", err)
	}
	if err = learn.Open(db).Bind("gen-new", "csmfz_new"); err != nil {
		t.Fatalf("a fresh ledger did not accept a new binding: %v", err)
	}
}

func TestDeclaredRestoreHoldsLearningUntilDisabled(t *testing.T) {
	withFakeEngines(t)
	withFakeWatchers(t)
	d := newLearningDaemon(t)
	if err := learn.Open(store.Global()).MarkDeclaredRestore(t0Fresh); err != nil {
		t.Fatal(err)
	}
	mismatch := func() bool {
		for _, p := range d.learnerProblems() {
			if p.Key == antispam.ReasonStateMismatch {
				return true
			}
		}
		return false
	}
	if !mismatch() {
		t.Fatal("a declared restore did not hold learning before the engine started")
	}
	d.cfg.EmailProtection.Antispam.Learning.Enabled = false
	d.syncLearner(learnedOutcome(antispam.LearningGate{}, reconcile.LearnerTarget{}))
	if held, err := learn.Open(store.Global()).DeclaredRestore(); err != nil || held {
		t.Fatalf("disabling learning did not confirm the restore: %v, %v", held, err)
	}
	d.cfg.EmailProtection.Antispam.Learning.Enabled = true
	if mismatch() {
		t.Fatal("re-enabled learning still held")
	}
}

var t0Fresh = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
