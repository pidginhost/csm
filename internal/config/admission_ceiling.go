package config

import "github.com/pidginhost/csm/internal/admission"

// DefaultAdmissionCeiling is the admission ledger's hourly ceiling over
// every automatic source when max_blocks_per_hour is unset or zero (spec
// 5.6). The legacy hourly counter keeps DefaultMaxBlocksPerHour for the
// same key until routing through the ledger replaces it.
const DefaultAdmissionCeiling = 2000

// Where the admission ceiling came from.
const (
	CeilingDefault    = "default"
	CeilingConfigured = "configured"
	CeilingClamped    = "clamped"
)

// AdmissionCeiling is the hourly ceiling the admission ledger enforces:
// max_blocks_per_hour, its default when unset or zero, or the largest
// ceiling the ledger accepts when the setting exceeds it. The second
// result names which.
func (c *Config) AdmissionCeiling() (uint32, string) {
	v := c.AutoResponse.MaxBlocksPerHour
	switch {
	case v <= 0 || c.AutoResponse.MaxBlocksPerHourDefaulted:
		return DefaultAdmissionCeiling, CeilingDefault
	case v > admission.MaxCeiling:
		return admission.MaxCeiling, CeilingClamped
	}
	return uint32(v), CeilingConfigured // #nosec G115 -- 1..MaxCeiling here.
}
