package daemon

import (
	"errors"
	"testing"

	"github.com/pidginhost/csm/internal/emailav"
)

func TestShouldTempfailEmailDelivery(t *testing.T) {
	if shouldTempfailEmailDelivery(false, &emailav.ScanResult{AllEnginesDown: true}, nil) {
		t.Fatal("tempfail disabled should never deny")
	}
	if !shouldTempfailEmailDelivery(true, &emailav.ScanResult{AllEnginesDown: true}, nil) {
		t.Fatal("all engines down should deny in tempfail mode")
	}
	if !shouldTempfailEmailDelivery(true, &emailav.ScanResult{TimedOutEngines: []string{"clamav"}}, nil) {
		t.Fatal("timeout should deny in tempfail mode")
	}
	if !shouldTempfailEmailDelivery(true, &emailav.ScanResult{}, errors.New("quarantine failed")) {
		t.Fatal("quarantine failure should deny in tempfail mode")
	}
}
