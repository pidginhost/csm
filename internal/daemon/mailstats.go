package daemon

import (
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/mailstats"
	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/store"
)

// mailStatsPersistInterval is how often the mail decision counter is saved.
// A clean shutdown saves once more after the log watchers stop. A var so
// tests can drive the periodic writer without waiting a minute.
var mailStatsPersistInterval = time.Minute

// recordMailStatsExim counts an Exim main log line for the Email Security
// page. Every Exim line comes through here, so a parser runs only for a line
// that holds its marker. The login count does not depend on the IP or infra
// filters, so it matches a grep of the log.
func (d *Daemon) recordMailStatsExim(line string, at time.Time) {
	if strings.Contains(line, " CSM-ANTISPAM ") {
		if s, ok := antispam.ParseScan(line); ok {
			d.mailStats.RecordScan(mailstats.LineTime(line, time.Local, at), s)
		}
	}
	if strings.Contains(line, " rejected ") {
		if r, ok := mailstats.ParseReject(line, time.Local, at); ok {
			d.mailStats.RecordReject(r)
		}
	}
	if strings.Contains(line, "authenticator failed") && strings.Contains(line, "dovecot") {
		d.mailStats.RecordLoginFailure(mailstats.LineTime(line, time.Local, at), false, 1)
	}
}

// recordMailStatsMail counts the password attempts of a failed Dovecot
// login, whatever the client address. A zero at means the source gave no
// observation time.
func (d *Daemon) recordMailStatsMail(line string, at time.Time) {
	if !strings.Contains(line, "(auth failed") || !isMailAuthLine(line) || dovecotLoginSucceeded(line) {
		return
	}
	if at.IsZero() {
		at = d.mailStatsNow()
	}
	d.mailStats.RecordLoginFailure(mailstats.LineTime(line, time.Local, at), true, dovecotFailedAttempts(line))
}

// restoreMailStats merges the stored counts into the counter before the log
// watchers start. Counting starts now, not when the counter was built, so
// the stop the load records ends here; a retried load keeps that end.
func (d *Daemon) restoreMailStats() {
	if sdb := store.Global(); sdb != nil {
		d.mailStats.SetStart(d.mailStatsNow())
		d.loadMailStats(sdb)
	}
}

// loadMailStats merges the stored counts once. Until a load succeeds the
// counter runs in memory only, since Flush writes nothing to the store
// before a load has merged; every save retries, and a load that already
// succeeded does nothing. Only the first failure and the recovery are
// logged.
func (d *Daemon) loadMailStats(sdb *store.DB) {
	err := d.mailStats.Load(sdb, d.mailStatsNow())
	switch {
	case err != nil && !d.mailStatsLoadFailing.Load():
		d.mailStatsLoadFailing.Store(true)
		csmlog.Warn("mail stats load failed, counting in memory until a retry succeeds", "err", err)
	case err == nil && d.mailStatsLoadFailing.Load():
		d.mailStatsLoadFailing.Store(false)
		csmlog.Info("mail stats load succeeded on retry")
	}
}

// persistMailStats saves the counter, loading the stored counts first if
// that has not succeeded yet. Without a state store it only prunes, so
// memory stays bounded.
func (d *Daemon) persistMailStats() {
	sdb := store.Global()
	if sdb == nil {
		d.mailStats.Prune(d.mailStatsNow())
		return
	}
	d.loadMailStats(sdb)
	if err := d.mailStats.Flush(sdb, d.mailStatsNow()); err != nil {
		csmlog.Warn("mail stats persistence failed", "err", err)
	}
}

// startMailStatsPersistence saves the counter periodically. It stops on
// d.stopCh without a final save; the shutdown path saves once more after
// every log watcher has exited.
func (d *Daemon) startMailStatsPersistence() {
	d.wg.Add(1)
	obs.Go("mail-stats-persist", func() {
		defer d.wg.Done()
		ticker := time.NewTicker(mailStatsPersistInterval)
		defer ticker.Stop()
		for {
			select {
			case <-d.stopCh:
				return
			case <-ticker.C:
				d.persistMailStats()
			}
		}
	})
}
