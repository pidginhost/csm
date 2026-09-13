package state

import "github.com/pidginhost/csm/internal/alert"

// ScanCoverage describes only units proved by a completed scan. Scope keys
// are scanner-issued identities, never file paths or parsed display text.
type ScanCoverage struct {
	PreservePaths   map[string]map[string]bool
	CompletedScopes map[string]map[string]bool
}

func (c *ScanCoverage) completed(f alert.Finding) bool {
	return c != nil && f.CoverageScope != "" && c.CompletedScopes[f.Check][f.CoverageScope]
}

// unexamined identifies retained state that must not be evicted to make room
// for new findings from a completed scope in the same scanner.
func (c *ScanCoverage) unexamined(f alert.Finding) bool {
	return c != nil && c.CompletedScopes[f.Check] != nil && !c.completed(f)
}
