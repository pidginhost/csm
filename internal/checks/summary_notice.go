package checks

import (
	"strings"
	"sync"

	"github.com/pidginhost/csm/internal/alert"
)

var summaryChecks = sync.OnceValue(func() map[string]bool {
	names := make(map[string]bool)
	for _, c := range checkRegistry {
		if c.Summary {
			names[c.Name] = true
		}
	}
	return names
})

// IsSummaryNotice is the alert summary-notice policy: the finding's check is
// registered Summary. auto_block also reports queue, accounting and other
// response gaps as Warnings, which need a person, so only an applied block
// (Critical) or a dry-run verdict counts.
func IsSummaryNotice(f alert.Finding) bool {
	if !summaryChecks()[f.Check] {
		return false
	}
	if f.Check == "auto_block" {
		return f.Severity == alert.Critical || strings.Contains(f.Message, "[dry-run]")
	}
	return true
}
