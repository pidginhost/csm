package alert

import "time"

// SprayConstituent is one address a subnet spray counted: when it was last
// seen in the window and the observation of the line that last named it.
type SprayConstituent struct {
	Address     string      `json:"address"`
	LastSeen    time.Time   `json:"last_seen"`
	Observation Observation `json:"observation"`
}
