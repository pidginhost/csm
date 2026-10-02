package alert

import (
	"crypto/rand"
	"time"
)

// Observation names where a finding was read: the producer that read it,
// the stream (one generation of a log file, or a journal), the position of
// the triggering line in that stream, and when it was observed. Admission
// mints evidence from it; the zero value means the producer has none.
type Observation struct {
	Producer   string    `json:"producer"`
	Stream     string    `json:"stream"`
	Cursor     string    `json:"cursor"`
	ObservedAt time.Time `json:"observed_at"`
}

// NewObservationEpoch separates reader lifetimes without relying on a wall
// clock that can repeat after a restart.
func NewObservationEpoch() string { return rand.Text() }
