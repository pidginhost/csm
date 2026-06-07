// Package guard glues the operator config to the pure forward-guard policy.
// It exists so internal/mailfwd/policy stays dependency-free of internal/config
// (policy is a low-level leaf; only this glue knows about both).
package guard

import (
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/mailfwd/policy"
)

// PolicyFromConfig projects the operator's forward-guard config onto the policy
// input. Only the fields the verdict needs are mapped; skip-list and retention
// are consumed by the adapter and quarantine, not by Verdict.
func PolicyFromConfig(fg config.ForwardGuardConfig) policy.Config {
	return policy.Config{
		Enabled: fg.Enabled,
		DryRun:  fg.DryRun,
		HoldSignals: policy.HoldSignals{
			BounceBackscatter: fg.HoldSignals.BounceBackscatter,
			SpamFlagged:       fg.HoldSignals.SpamFlagged,
			Malware:           fg.HoldSignals.Malware,
			BadSenderIP:       fg.HoldSignals.BadSenderIP,
			AuthFail:          fg.HoldSignals.AuthFail,
		},
	}
}
