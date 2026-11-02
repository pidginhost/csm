package daemon

import (
	"context"
	"slices"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/antispam/dovecot"
	"github.com/pidginhost/csm/internal/antispam/learnwatch"
	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/store"
)

type learnWatcher interface {
	Run(context.Context)
	Pass(context.Context) learnwatch.PassReport
	Last() (learnwatch.PassReport, time.Time)
}

// newLearnWatcher builds the Spam folder watcher; tests replace it.
var newLearnWatcher = func(cfg learnwatch.WatcherConfig) learnWatcher { return learnwatch.NewWatcher(cfg) }

// The account registry and global opt-in a cPanel watcher reads, and the
// Dovecot discovery a Postfix watcher reads; tests replace them.
var (
	learnwatchSource  learnwatch.Source        = learnwatch.DefaultSource
	learnwatchGlobal                           = learnwatch.GlobalOptInPath
	learnwatchDovecot learnwatch.DovecotSource = dovecot.Dovecot{}
)

// resetLearningWatcher cancels unsent reports on explicit disable, even
// when the daemon started with learning off. Shutdown and observe retain
// the watcher state. The caller holds antispamLearnerMu and has stopped it.
func (d *Daemon) resetLearningWatcher() bool {
	db := store.Global()
	if db == nil {
		return false
	}
	if err := db.ResetLearnWatch(); err != nil {
		csmlog.Warn("antispam learning cannot reset Spam folder baselines", "err", err)
		return false
	}
	d.antispamWatchReset = false
	return true
}

// watchConfig is what a runner's watcher reads reporters by: Dovecot with
// a reporter mode and exempt list on Postfix, else cPanel's accounts. The
// daemon compares it apart from the learner target; a change restarts the
// learner.
type watchConfig struct {
	postfix  bool
	reporter string
	exempt   []string
}

func (w watchConfig) equal(o watchConfig) bool {
	return w.postfix == o.postfix && w.reporter == o.reporter && slices.Equal(w.exempt, o.exempt)
}

// watchConfigFor is the watcher a pass on stack asks for under cfg. A pass
// that cannot tell the stack, as while postfix restarts, keeps cur's.
func watchConfigFor(stack antispam.MailStack, cfg *config.Config, cur *learnerRunner) watchConfig {
	switch {
	case stack == antispam.StackPostfix:
		as := cfg.EmailProtection.Antispam
		return watchConfig{postfix: true, reporter: as.Learning.Reporter, exempt: slices.Clone(as.Exempt)}
	case stack == antispam.StackNone && cur != nil:
		return cur.watch
	}
	return watchConfig{}
}

// newRunnerWatcher builds r's watcher. It lists folders only while r's gate
// allows installs and reads or submits reports only while it also allows
// publishing; stopping r cancels it with the engine.
func newRunnerWatcher(db *store.DB, r *learnerRunner) learnWatcher {
	cfg := learnwatch.WatcherConfig{
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
			} else {
				invalidateLearningStats()
			}
		},
	}
	if r.watch.postfix {
		cfg.Postfix = &learnwatch.Postfix{Dovecot: learnwatchDovecot, Reporter: r.watch.reporter, Exempt: r.watch.exempt}
	} else {
		cfg.Source, cfg.GlobalPath = learnwatchSource, learnwatchGlobal
	}
	return newLearnWatcher(cfg)
}
