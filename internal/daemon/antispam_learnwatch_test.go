//go:build linux

package daemon

import (
	"context"
	"fmt"
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
	"github.com/pidginhost/csm/internal/store"
)

// fakeWatcher records its config and how long Run ran.
type fakeWatcher struct {
	cfg     learnwatch.WatcherConfig
	mu      sync.Mutex
	running bool
	stopped chan struct{}
}

func (w *fakeWatcher) Run(ctx context.Context) {
	w.mu.Lock()
	w.running = true
	w.mu.Unlock()
	<-ctx.Done()
	close(w.stopped)
}

func (w *fakeWatcher) Pass(context.Context) learnwatch.PassReport { return learnwatch.PassReport{} }

func (w *fakeWatcher) Last() (learnwatch.PassReport, time.Time) {
	return learnwatch.PassReport{}, time.Time{}
}

func withFakeWatchers(t *testing.T) *[]*fakeWatcher {
	t.Helper()
	var watchers []*fakeWatcher
	saved := newLearnWatcher
	newLearnWatcher = func(cfg learnwatch.WatcherConfig) learnWatcher {
		w := &fakeWatcher{cfg: cfg, stopped: make(chan struct{})}
		watchers = append(watchers, w)
		return w
	}
	t.Cleanup(func() { newLearnWatcher = saved })
	return &watchers
}

func TestWatcherStartsWithEngine(t *testing.T) {
	engines := withFakeEngines(t)
	watchers := withFakeWatchers(t)
	d := newLearningDaemon(t)
	d.syncLearner(learnedOutcome(antispam.LearningGate{Install: true, Publish: true}, testTarget))
	if len(*watchers) != 1 {
		t.Fatalf("%d watchers", len(*watchers))
	}
	w := (*watchers)[0]
	if w.cfg.Engine != (*engines)[0] || w.cfg.State == nil || w.cfg.Source == nil {
		t.Fatalf("watcher config %+v", w.cfg)
	}
	waitFor(t, func() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.running })
	if !w.cfg.CanDiscover() || !w.cfg.CanSubmit() {
		t.Fatal("open gate does not let the watcher work")
	}
	d.syncLearner(learnedOutcome(antispam.LearningGate{Install: true}, testTarget))
	if !w.cfg.CanDiscover() || w.cfg.CanSubmit() {
		t.Fatal("Publish=false must keep discovery and defer submissions")
	}
	d.syncLearner(learnedOutcome(antispam.LearningGate{}, testTarget))
	if w.cfg.CanDiscover() || w.cfg.CanSubmit() {
		t.Fatal("a closed gate still lets the watcher read")
	}
	if len(*watchers) != 1 {
		t.Fatal("a gate change started another watcher")
	}
}

func TestWatcherStopsOnDisable(t *testing.T) {
	withFakeEngines(t)
	watchers := withFakeWatchers(t)
	d := newLearningDaemon(t)
	d.syncLearner(learnedOutcome(antispam.LearningGate{Install: true, Publish: true}, testTarget))
	d.cfg.EmailProtection.Antispam.Learning.Enabled = false
	d.syncLearner(learnedOutcome(antispam.LearningGate{}, reconcile.LearnerTarget{}))
	w := (*watchers)[0]
	select {
	case <-w.stopped:
	default:
		t.Fatal("disable returned before the watcher stopped")
	}
	if w.cfg.CanDiscover() || w.cfg.CanSubmit() {
		t.Fatal("a stopped watcher's gate stayed open")
	}
}

func TestWatcherObserveNoReads(t *testing.T) {
	withFakeEngines(t)
	watchers := withFakeWatchers(t)
	d := newLearningDaemon(t)
	d.cfg.Mode = "observe"
	d.syncLearner(learnedOutcome(antispam.LearningGate{Install: true, Publish: true}, testTarget))
	if len(*watchers) != 0 {
		t.Fatal("observe mode started a watcher")
	}
	d.cfg.Mode = ""
	d.syncLearner(learnedOutcome(antispam.LearningGate{Install: true, Publish: true}, testTarget))
	d.cfg.Mode = "observe"
	d.syncLearner(learnedOutcome(antispam.LearningGate{Install: true, Publish: true}, testTarget))
	select {
	case <-(*watchers)[0].stopped:
	default:
		t.Fatal("observe mode left the watcher reading")
	}
}

// watchHome is one opted-in non-root account, served to the real watcher
// through the daemon's account source.
type watchHome struct {
	home string
	uid  int
}

func newWatchHome(t *testing.T) watchHome {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "tenant1")
	for _, d := range []string{"mail/.spam/cur", "mail/.spam/new"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".spamassassinenable"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	uid := os.Getuid()
	if uid == 0 {
		// The watcher correctly refuses root accounts; CI may run as root.
		uid = 1001
		if err := os.Chown(home, uid, uid); err != nil {
			t.Fatal(err)
		}
	}
	src, global := learnwatchSource, learnwatchGlobal
	t.Cleanup(func() { learnwatchSource, learnwatchGlobal = src, global })
	learnwatchSource = staticSource{users: []string{"tenant1"}, passwd: fmt.Sprintf("tenant1:x:%d:%d::%s:/bin/bash\n", uid, uid, home)}
	learnwatchGlobal = filepath.Join(root, "global_spamassassin_enable")
	return watchHome{home: home, uid: uid}
}

type staticSource struct {
	users  []string
	passwd string
}

func (s staticSource) CPanelUsers() ([]string, error) { return s.users, nil }
func (s staticSource) Passwd() ([]byte, error)        { return []byte(s.passwd), nil }

func (h watchHome) deliver(t *testing.T, name, body string) {
	t.Helper()
	path := filepath.Join(h.home, "mail/.spam/new", name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if h.uid != os.Getuid() {
		if err := os.Chown(path, h.uid, h.uid); err != nil {
			t.Fatal(err)
		}
	}
}

// startWatching starts the learner and waits for the watcher's first pass.
func startWatching(t *testing.T, d *Daemon) learnWatcher {
	t.Helper()
	d.syncLearner(learnedOutcome(antispam.LearningGate{Install: true, Publish: true}, testTarget))
	r := d.antispamLearner.Load()
	if r == nil || r.watcher == nil {
		t.Fatal("learner started without a watcher")
	}
	waitFor(t, func() bool { _, at := r.watcher.Last(); return !at.IsZero() })
	return r.watcher
}

// Last can publish just before Pass releases its busy guard. A manual
// pass must wait for that guard without counting Busy as completed work.
func watcherPass(t *testing.T, w learnWatcher) learnwatch.PassReport {
	t.Helper()
	var report learnwatch.PassReport
	waitFor(t, func() bool {
		report = w.Pass(context.Background())
		return !report.Busy
	})
	return report
}

func TestWatcherRestartResumesBaseline(t *testing.T) {
	engines := withFakeEngines(t)
	h := newWatchHome(t)
	h.deliver(t, "100.M1.host", "Subject: old\r\n\r\nbefore the baseline")
	d := newLearningDaemon(t)
	startWatching(t, d)
	d.stopLearner()
	h.deliver(t, "200.M2.host", "Subject: new\r\n\r\nafter the baseline")
	startWatching(t, d)
	e := (*engines)[1]
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.submits) != 1 || !strings.Contains(string(e.submits[0].Snapshot), "after the baseline") || e.submits[0].UID != h.uid {
		t.Fatalf("submits after restart: %d", len(e.submits))
	}
}

func TestWatcherSubmitsOutcomeMarksSeen(t *testing.T) {
	engines := withFakeEngines(t)
	h := newWatchHome(t)
	d := newLearningDaemon(t)
	w := startWatching(t, d)
	e := (*engines)[0]
	e.mu.Lock()
	e.respond = func(c learn.Candidate) (learn.Outcome, error) {
		switch body := string(c.Snapshot); {
		case strings.Contains(body, "duplicate"):
			return learn.Outcome{Duplicates: []uint64{2}}, nil
		case strings.Contains(body, "skip"):
			return learn.Outcome{Skips: []learn.Skip{{Reason: learn.SkipBelowJoin}}}, nil
		case strings.Contains(body, "deferred"):
			return learn.Outcome{Deferred: true}, nil
		}
		return learn.Outcome{Committed: []uint64{1}}, nil
	}
	e.mu.Unlock()
	for _, kind := range []string{"committed", "duplicate", "skip", "deferred"} {
		h.deliver(t, kind+".M1.host", "Subject: "+kind+"\r\n\r\n"+kind)
	}
	if r := watcherPass(t, w); r.Submitted != 3 {
		t.Fatalf("pass %+v", r)
	}
	state := learnwatch.NewState(store.Global(), nil)
	k := learnwatch.FolderKey{UID: h.uid, Folder: ".spam"}
	want := map[string]string{
		"committed": learnwatch.StatusSubmitted,
		"duplicate": learnwatch.StatusSubmitted,
		"skip":      learnwatch.StatusSubmitted,
		"deferred":  learnwatch.StatusPending,
	}
	if err := state.View(func(tx learnwatch.StateTx) error {
		for kind, status := range want {
			entry, ok, err := tx.Seen(k, kind+".M1.host")
			if err != nil || !ok || entry.Status != status {
				t.Errorf("%s: entry %+v, found %v, error %v", kind, entry, ok, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
