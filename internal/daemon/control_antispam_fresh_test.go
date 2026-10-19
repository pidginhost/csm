package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/antispam/learn"
	"github.com/pidginhost/csm/internal/antispam/learnwatch"
	"github.com/pidginhost/csm/internal/antispam/reconcile"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/platform"
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

func TestFreshNamespaceResetFailureRestoresKeys(t *testing.T) {
	d := newDaemonForListener(t)
	db, closeDB := openTestBoltStore(t, t.TempDir())
	t.Cleanup(closeDB)
	dir := useLearningDir(t)
	writeKeys(t, dir, "csmfz_old")
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := d.freshLearningNamespace(t0Fresh); err == nil {
		t.Fatal("reset with a closed database succeeded")
	}
	if got, err := os.ReadFile(filepath.Join(dir, "keys", antispam.KeyPrefix)); err != nil || string(got) != "csmfz_old" {
		t.Fatalf("failed reset moved the keys: %q, %v", got, err)
	}
}

func TestDeclaredRestoreReadFailureHoldsLearning(t *testing.T) {
	d := newLearningDaemon(t)
	if err := store.Global().LearnUpdate(func(tx store.LearnTx) error {
		return tx.Put(store.LearnMetaBucket, []byte("declared_restore"), []byte("invalid"))
	}); err != nil {
		t.Fatal(err)
	}
	problems := d.learnerProblems()
	if len(problems) != 1 || problems[0].Key != antispam.ReasonStateMismatch {
		t.Fatalf("unreadable restore hold permits installation: %+v", problems)
	}
}

func TestDeclaredRestoreObserveDoesNotConfirm(t *testing.T) {
	d := newLearningDaemon(t)
	ledger := learn.Open(store.Global())
	if err := ledger.MarkDeclaredRestore(t0Fresh); err != nil {
		t.Fatal(err)
	}
	d.cfg.Mode = "observe"
	d.cfg.EmailProtection.Antispam.Learning.Enabled = false
	d.syncLearner(reconcile.Outcome{})
	if held, err := ledger.DeclaredRestore(); err != nil || !held {
		t.Fatalf("observe mode confirmed restore: held=%v, err=%v", held, err)
	}
}

func TestFreshNamespaceWaitsForReconcile(t *testing.T) {
	d := newLearningDaemon(t)
	dir := useLearningDir(t)
	writeKeys(t, dir, "csmfz_old")
	d.stopCh = make(chan struct{})
	usePanel(t, platform.PanelCPanel)
	useActiveConfig(t, d.cfg)
	stop := antispamTestShutdown(t, d)
	entered, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	t.Cleanup(unblock)
	useAntispamReconciler(t, reconcile.Reconciler{
		EnsureKeys: func(context.Context, string) (bool, error) {
			close(entered)
			<-release
			if err := os.MkdirAll(filepath.Join(dir, "keys"), 0o700); err != nil {
				return false, err
			}
			if err := os.WriteFile(filepath.Join(dir, "keys", antispam.KeyPrefix), []byte("csmfz_inflight"), 0o600); err != nil {
				return false, err
			}
			return false, errors.New("key generation did not complete")
		},
		LoadKeys: func(string) (antispam.LearningKeys, error) {
			return antispam.LearningKeys{}, errors.New("unexpected key read")
		},
		Collect: func(context.Context, string) antispam.HostFacts {
			return antispam.HostFacts{Record: antispam.RecordFacts{Missing: true}}
		},
		Now: time.Now,
	})
	d.startAntispam()
	waitPass(t, entered)
	cfg := *d.currentCfg()
	cfg.EmailProtection.Antispam.Learning.Enabled = false
	config.SetActive(&cfg)
	d.syncLearner(reconcile.Outcome{})
	finished := make(chan error, 1)
	go func() {
		_, err := d.freshLearningNamespace(t0Fresh)
		finished <- err
	}()
	select {
	case err := <-finished:
		t.Errorf("reset overtook a pass that can still write keys: %v", err)
		finished <- err
	case <-time.After(100 * time.Millisecond):
	}
	unblock()
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	stop()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("an old reconcile pass recreated reset keys: %v", err)
	}
}

var t0Fresh = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
