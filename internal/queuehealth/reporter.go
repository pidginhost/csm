package queuehealth

import (
	"sort"
	"time"
)

// Event records a degradation, a bounded reminder or a recovery. Healthy
// startup produces no event, and one queue cannot suppress another's change.
type Event struct {
	Name      string
	Current   Status
	Recovered bool
}

// Reporter belongs to one health loop. Polling status does not consume its
// state or the trackers' counters, so API traffic cannot swallow an alert.
type Reporter struct {
	last map[string]time.Time
}

func (r *Reporter) Events(now time.Time, states map[string]Status) []Event {
	if r.last == nil {
		r.last = make(map[string]time.Time)
	}
	names := make([]string, 0, len(states))
	for name := range states {
		names = append(names, name)
	}
	sort.Strings(names)
	var events []Event
	for _, name := range names {
		s := states[name]
		previous, alerted := r.last[name]
		if s.Status == "degraded" {
			if !alerted || now.Sub(previous) >= 5*time.Minute {
				events = append(events, Event{Name: name, Current: s})
				r.last[name] = now
			}
		} else if alerted {
			events = append(events, Event{Name: name, Current: s, Recovered: true})
			delete(r.last, name)
		}
	}
	return events
}
