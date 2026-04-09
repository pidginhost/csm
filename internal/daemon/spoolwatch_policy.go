package daemon

import "github.com/pidginhost/csm/internal/emailav"

func shouldTempfailEmailDelivery(tempfail bool, result *emailav.ScanResult, quarantineErr error) bool {
	if !tempfail {
		return false
	}
	if quarantineErr != nil {
		return true
	}
	if result == nil {
		return false
	}
	return result.AllEnginesDown || len(result.TimedOutEngines) > 0
}
