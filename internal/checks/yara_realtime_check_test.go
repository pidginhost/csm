package checks

import "testing"

// An unregistered finding name is dropped from the list disabled_checks
// accepts, so an operator could not silence it. The realtime YARA failure
// needs the same classification the deep scan's coverage report carries.
func TestRealtimeYARAScanErrorIsRegistered(t *testing.T) {
	info, ok := LookupCheck("yara_realtime_scan_error")
	if !ok {
		t.Fatal("yara_realtime_scan_error is not in the check registry")
	}
	if info.Category != CategoryMalware {
		t.Errorf("category = %v, want CategoryMalware", info.Category)
	}
	if info.Correlation != CorrelationIgnored {
		t.Errorf("correlation = %v, want CorrelationIgnored", info.Correlation)
	}
}
