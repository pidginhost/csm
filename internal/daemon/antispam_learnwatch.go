package daemon

import (
	"context"
	"time"

	"github.com/pidginhost/csm/internal/antispam/learnwatch"
	"github.com/pidginhost/csm/internal/store"
)

type learnWatcher interface {
	Run(context.Context)
	Pass(context.Context) learnwatch.PassReport
	Last() (learnwatch.PassReport, time.Time)
}

// newLearnWatcher builds the Spam folder watcher; tests replace it.
var newLearnWatcher = func(cfg learnwatch.WatcherConfig) learnWatcher { return learnwatch.NewWatcher(cfg) }

// The account registry and global opt-in the watcher reads; tests point
// them at synthetic homes.
var (
	learnwatchSource learnwatch.Source = learnwatch.DefaultSource
	learnwatchGlobal                   = learnwatch.GlobalOptInPath
)

// newRunnerWatcher builds r's watcher. It lists folders only while r's gate
// allows installs and reads or submits reports only while it also allows
// publishing; stopping r cancels it with the engine.
func newRunnerWatcher(db *store.DB, r *learnerRunner) learnWatcher {
	return newLearnWatcher(learnwatch.WatcherConfig{
		Source:      learnwatchSource,
		GlobalPath:  learnwatchGlobal,
		State:       learnwatch.NewState(db, nil),
		Engine:      r.engine,
		CanDiscover: func() bool { return r.currentGate().Install },
		CanSubmit: func() bool {
			g := r.currentGate()
			return g.Install && g.Publish
		},
		OnPass: func(rep learnwatch.PassReport) {
			recordLearningPass(rep, time.Now())
			if st, err := r.engine.Stats(); err == nil {
				recordLearningStats(st)
			}
		},
	})
}
