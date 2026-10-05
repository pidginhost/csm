//go:build !linux

package admissionowner

import (
	"errors"

	"github.com/pidginhost/csm/internal/admission"
)

// ReadClock has no boot identity off Linux, so the ledger admits nothing.
func ReadClock() (admission.ClockReading, error) {
	return admission.ClockReading{}, errors.New("the admission clock needs a Linux boot identity")
}
