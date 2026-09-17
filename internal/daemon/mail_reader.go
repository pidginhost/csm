package daemon

import (
	"context"

	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/maillog"
	"github.com/pidginhost/csm/internal/obs"
)

func (d *Daemon) startMailLogReader(platformDefault string, handler LogLineHandler) {
	d.MarkWatcher("maillog", false)
	queue := maillog.NewQueue()
	d.registerQueueSource("mail", queue)
	ctx, cancel := context.WithCancel(context.Background())
	d.wg.Add(2)
	obs.Go("maillog-stop", func() {
		defer d.wg.Done()
		select {
		case <-d.stopCh:
		case <-ctx.Done():
		}
		cancel()
	})
	obs.Go("maillog-supervisor", func() {
		defer d.wg.Done()
		defer cancel()
		defer d.MarkWatcher("maillog", false)
		maillog.Supervise(ctx, func() (maillog.Reader, error) {
			return maillog.New(d.currentCfg().MailLogs, platformDefault, queue)
		}, func(err error) {
			if err != nil {
				csmlog.Warn("mail log source unavailable; retrying", "err", err)
				d.handleMailLogSourceGone(err)
			} else {
				d.handleMailLogSourceRestored()
			}
		}, func(line maillog.Line) bool {
			return d.dispatchMailLogLine(line, handler)
		})
	})
}
