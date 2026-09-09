package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/pidginhost/csm/internal/health"
)

// correlationAttributionCheck turns the daemon's attribution state into a
// doctor line. Checks whose findings sit in the active set without a hosting
// owner are named with their row counts, because those findings are reported
// but never counted by cross-account correlation. The cumulative history is
// shown either way so a producer that recovered is visible as recovered.
func correlationAttributionCheck(ca *health.CorrelationAttribution) DoctorCheck {
	check := DoctorCheck{Name: "correlation attribution", Status: "ok"}
	if ca == nil {
		check.Message = "no active set merged yet; nothing to judge"
		return check
	}
	total := 0
	for _, n := range ca.Cumulative {
		total += n
	}
	history := fmt.Sprintf("%d rows since start across %d merges", total, ca.ActiveSetUpdates)
	if len(ca.Current) == 0 {
		check.Message = "every eligible finding in the active set carries an owner; " + history + " were reported without one"
		return check
	}
	names := make([]string, 0, len(ca.Current))
	for name := range ca.Current {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, fmt.Sprintf("%s=%d", name, ca.Current[name]))
	}
	check.Status = "warn"
	check.Message = fmt.Sprintf("%d check(s) carry findings without a hosting owner in the active set: %s; %s",
		len(names), strings.Join(parts, ", "), history)
	check.Fix = "these findings are reported but not counted by cross-account correlation; the incidents documentation lists which producers cannot resolve an owner on this panel and the declared attribution gaps"
	return check
}
