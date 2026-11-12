package daemon

import (
	"fmt"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/platform"
)

const (
	// stalwartHealthTick is how often the Stalwart log health is judged.
	stalwartHealthTick = 5 * time.Minute
	// stalwartHealthSlots holds one hour of ticks.
	stalwartHealthSlots = 12
	// stalwartUnparsedMinLines is how many lines an hour must deliver, none
	// of them in Stalwart's layout, before CSM calls the layout changed.
	stalwartUnparsedMinLines = 50
	// stalwartStallAfter is how long a running Stalwart may leave its log
	// unchanged before CSM reports it. Scanners alone keep a public mail
	// server's log moving.
	stalwartStallAfter = 6 * time.Hour
	// stalwartUnattributedMin is how many SMTP sends an hour may go without
	// a login to name their sender before CSM reports it. Only sessions in
	// progress when CSM started, or a flood of logins evicting remembered
	// connections, leave a send unnamed.
	stalwartUnattributedMin = 20
)

// stalwartServiceActive reports whether Stalwart is running. var so tests
// can stand in for systemd.
var stalwartServiceActive = func() bool {
	return platform.ServiceActive("stalwart") || platform.ServiceActive("stalwart-mail")
}

// stalwartHealth is the last hour of line counts, touched only by the
// health ticker.
type stalwartHealth struct {
	lastRead, lastParsed, lastUnattributed int64
	read, parsed, unattributed             [stalwartHealthSlots]int64
	next                                   int
}

// health judges one tick. It reports a log whose last hour held many lines
// and none in Stalwart's layout (a layout change after an upgrade), a burst
// of SMTP sends with no login to name their sender, and a log that stopped
// growing while Stalwart runs.
func (s *stalwartState) health(now time.Time, serviceActive bool) []alert.Finding {
	h := &s.hourly
	read, parsed, unattributed := s.stats.read.Load(), s.stats.parsed.Load(), s.stats.unattributed.Load()
	h.read[h.next], h.parsed[h.next] = read-h.lastRead, parsed-h.lastParsed
	h.unattributed[h.next] = unattributed - h.lastUnattributed
	h.lastRead, h.lastParsed, h.lastUnattributed = read, parsed, unattributed
	h.next = (h.next + 1) % stalwartHealthSlots
	var hourRead, hourParsed, hourUnattributed int64
	for i := range h.read {
		hourRead += h.read[i]
		hourParsed += h.parsed[i]
		hourUnattributed += h.unattributed[i]
	}
	var out []alert.Finding
	if hourRead >= stalwartUnparsedMinLines && hourParsed == 0 {
		out = append(out, alert.Finding{
			Severity:  alert.Warning,
			Check:     "stalwart_log_degraded",
			Message:   fmt.Sprintf("Stalwart log: %d lines in the last hour, none in the expected format; Stalwart may have changed its log layout, so CSM sees no mail logins or sends", hourRead),
			DedupKey:  "stalwart_log_degraded:unparsed",
			Timestamp: now,
		})
	}
	if hourUnattributed >= stalwartUnattributedMin {
		out = append(out, alert.Finding{
			Severity:  alert.Warning,
			Check:     "stalwart_log_degraded",
			Message:   fmt.Sprintf("Stalwart log: %d authenticated SMTP sends in the last hour could not be tied to their login, so CSM cannot judge who sent them", hourUnattributed),
			DedupKey:  "stalwart_log_degraded:unattributed",
			Timestamp: now,
		})
	}
	if last := time.Unix(s.stats.lastLine.Load(), 0); serviceActive && now.Sub(last) >= stalwartStallAfter {
		out = append(out, alert.Finding{
			Severity:  alert.Warning,
			Check:     "stalwart_log_degraded",
			Message:   "Stalwart log has not grown for 6 hours while the stalwart service is running, so CSM sees no mail logins or sends",
			DedupKey:  "stalwart_log_degraded:stalled",
			Timestamp: now,
		})
	}
	return out
}
