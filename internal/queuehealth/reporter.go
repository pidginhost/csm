package queuehealth

import (
	"sort"
	"time"
)

// reminderInterval bounds how often one queue can announce. It also bounds a
// flapping queue: a degradation that returns within the interval of the last
// announcement is carried in status but not notified again.
const reminderInterval = 5 * time.Minute

// Event records a degradation, a bounded reminder or a recovery. Healthy
// startup produces no event, and one queue cannot suppress another's change.
type Event struct {
	Name      string
	Current   Status
	Recovered bool
}

// incident is one queue's notification state. It outlives the degradation so a
// queue that recovers and degrades again stays inside the same bound.
type incident struct {
	announcedAt time.Time
	announced   bool
	degraded    bool
}

// Reporter belongs to one health loop. Polling status does not consume its
// state or the trackers' counters, so API traffic cannot swallow an alert.
type Reporter struct {
	last map[string]incident
}

func (r *Reporter) Events(now time.Time, states map[string]Status) []Event {
	if r.last == nil {
		r.last = make(map[string]incident)
	}
	names := make([]string, 0, len(states))
	for name := range states {
		names = append(names, name)
	}
	sort.Strings(names)
	var events []Event
	for _, name := range names {
		s := states[name]
		state := r.last[name]
		switch {
		case s.Advisory:
			// Best-effort work is visible in status and doctor only.
			continue
		case s.Status == "degraded":
			if state.announcedAt.IsZero() || now.Sub(state.announcedAt) >= reminderInterval {
				events = append(events, Event{Name: name, Current: s})
				state.announcedAt, state.announced = now, true
			} else if !state.degraded {
				// A degradation the bound suppressed must not announce a
				// recovery either, or the pair count is unchanged.
				state.announced = false
			}
			state.degraded = true
			r.last[name] = state
		case state.degraded:
			if state.announced {
				events = append(events, Event{Name: name, Current: s, Recovered: true})
				state.announced = false
			}
			state.degraded = false
			r.last[name] = state
		case !state.announcedAt.IsZero() && now.Sub(state.announcedAt) >= reminderInterval:
			delete(r.last, name)
		}
	}
	return events
}
