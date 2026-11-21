package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
)

// A line read without its position, unframed or from a file of unknown
// identity, still names a log any local user can write, so it alerts but
// never blocks; another log's line names nothing.
func TestUnpositionedWatcherLinesKeepWritableProducer(t *testing.T) {
	const line = "Sep 10 10:00:00 host sshd[1]: Accepted password for root from 198.51.100.7 port 22 ssh2"
	now := time.Now()
	w := &LogWatcher{producer: checks.ProducerSSHLog}
	want := alert.Observation{Producer: string(checks.ProducerSSHLog)}
	if got := w.lineObservation(true, 0, line, now); got != want {
		t.Errorf("unknown file identity: %+v, want %+v", got, want)
	}
	w.fileID = logFileID{dev: 1, ino: 2, known: true}
	if got := w.lineObservation(false, 0, line, now); got != want {
		t.Errorf("unframed line: %+v, want %+v", got, want)
	}
	if got := (&LogWatcher{producer: checks.ProducerEximLog, fileID: w.fileID}).lineObservation(false, 0, line, now); got != (alert.Observation{}) {
		t.Errorf("unframed Exim line: %+v, want none", got)
	}
}
