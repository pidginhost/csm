package checks

import (
	"strings"
	"sync"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/firewall"
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
// (Critical), a dry-run verdict or the admission applied-responses summary
// counts. A block of an address in a Cloudflare allow range leaves its web
// ports open, so that notice needs a person too.
func IsSummaryNotice(f alert.Finding) bool {
	if !summaryChecks()[f.Check] {
		return false
	}
	if f.Check == "auto_block" {
		if strings.Contains(f.Details, firewall.CloudflareCoverageWarning) {
			return false
		}
		return f.Severity == alert.Critical || strings.Contains(f.Message, "[dry-run]") ||
			f.Message == admission.AppliedSummaryMessage
	}
	return true
}
