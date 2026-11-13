package checks

import (
	"slices"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
)

// Central intel and incidents act on an address a local attack named. An
// outside reputation match is the same kind of opinion central intel is,
// and a destination is where this host connected, so neither may be the
// root those entries answer.
func TestCentralAndIncidentsWrapOnlyLocalAttacks(t *testing.T) {
	seen := map[admission.Entry]int{}
	for _, spec := range DerivedEntries() {
		switch spec.Entry {
		case admission.EntryCentral, admission.EntryIncident, admission.EntryIncidentSpray:
		default:
			continue
		}
		seen[spec.Entry]++
		for _, check := range []string{"pam_bruteforce", "wp_login_bruteforce", "mail_bruteforce"} {
			if !slices.Contains(spec.Checks, check) {
				t.Errorf("%s does not wrap local attack %s", spec.Entry, check)
			}
		}
		for _, check := range []string{"ip_reputation", "c2_connection"} {
			if slices.Contains(spec.Checks, check) {
				t.Errorf("%s wraps %s", spec.Entry, check)
			}
		}
		for _, check := range spec.Checks {
			if _, pol, ok := AdmissionPolicy(check); !ok || !pol.Family.LocalAttack() {
				t.Errorf("%s wraps %s, which is not local attack evidence", spec.Entry, check)
			}
		}
	}
	for _, entry := range []admission.Entry{admission.EntryCentral, admission.EntryIncident, admission.EntryIncidentSpray} {
		if seen[entry] != 1 {
			t.Errorf("entry %s appears %d times, want exactly once", entry, seen[entry])
		}
	}
}
