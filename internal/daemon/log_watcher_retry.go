package daemon

import (
	"time"

	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/obs"
)

// Retry the whole candidate list: a fallback can appear before the preferred
// log when the web server starts after the daemon. spec names the handler and
// producer; its path is ignored.
func (d *Daemon) retryLogWatcherCandidates(paths []string, spec logWatchSpec) {
	defer d.wg.Done()
	ticker := time.NewTicker(logWatcherRetryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			for _, path := range paths {
				candidate := spec
				candidate.path = path
				w, err := newObservedLogWatcher(candidate, d.cfg, d.alertCh)
				if err != nil {
					continue
				}
				d.logWatchersMu.Lock()
				d.logWatchers = append(d.logWatchers, w)
				d.logWatchersMu.Unlock()
				d.wg.Add(1)
				obs.Go("logwatch-late", func() {
					defer d.wg.Done()
					w.Run(d.stopCh)
				})
				csmlog.Info("watching log (appeared after retry)", "path", path)
				if spec.name != "" {
					d.MarkWatcher(spec.name, true)
				}
				return
			}
		}
	}
}
