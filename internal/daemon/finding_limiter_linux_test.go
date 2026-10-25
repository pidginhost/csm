//go:build linux

package daemon

import (
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/workerproc"
)

func TestParseFindingLimiterSharedAcrossWatcherReplacement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := &Daemon{alertCh: make(chan alert.Finding, 8)}
		d.reportIsolationUnavailable(errors.New("unit unavailable"))
		first := &SpoolWatcher{alertCh: d.alertCh, findings: &d.parseFindings}
		first.extractFailed("first", "", workerproc.ErrSpawn)
		replacement := &SpoolWatcher{alertCh: d.alertCh, findings: &d.parseFindings}
		replacement.extractFailed("replacement", "", workerproc.ErrSpawn)
		if fs := isolationFindings(d.alertCh); len(fs) != 1 || fs[0].Severity != alert.Critical {
			t.Fatalf("one outage delivered %+v, want one Critical", fs)
		}
		time.Sleep(isolationAlertInterval)
		replacement.extractFailed("next", "", workerproc.ErrSpawn)
		d.reportIsolationUnavailable(errors.New("unit still unavailable"))
		if fs := isolationFindings(d.alertCh); len(fs) != 1 || fs[0].Severity != alert.Critical {
			t.Fatalf("continuing outage delivered %+v, want one Critical", fs)
		}
	})
}
