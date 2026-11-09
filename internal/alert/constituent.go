package alert

import (
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// SprayConstituent is one address a subnet spray counted: when it was last
// seen in the window and the observation of the line that last named it.
type SprayConstituent struct {
	Address     string      `json:"address"`
	LastSeen    time.Time   `json:"last_seen"`
	Observation Observation `json:"observation"`
	// Attribution is how the tracker's parser read Address.
	Attribution admission.Attribution `json:"attribution,omitempty"`
}
