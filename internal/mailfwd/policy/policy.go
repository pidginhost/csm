// Package policy is the single source of truth for the forward-guard hold
// decision: given the signals observed for a message, should the external
// forward copy be held? The same Verdict function feeds both the dry-run
// "would-hold" accounting and (in Phase 2) the generated MTA rule, so the two
// can never drift apart.
//
// The verdict is layered: any enabled signal that matches holds the message.
// Holding is conservative-by-omission -- a signal whose toggle is off, or a
// message with no matching signal, is never held.
package policy

// MessageMeta is the set of signals known about a single forwarded message.
// All fields default false (unknown == not flagged), so a partially-populated
// meta can only ever reduce the chance of a hold, never invent one.
type MessageMeta struct {
	NullSender  bool // envelope sender is <> (bounce/backscatter)
	SpamFlagged bool // SpamAssassin marked it spam
	MalwareHit  bool // ClamAV / YARA-X matched
	SenderIPBad bool // sender IP is in the CSM attack DB / reputation
	SPFFail     bool
	DKIMFail    bool
	DMARCFail   bool
}

// HoldSignals toggles which layered signals are allowed to hold a message.
// Each is individually switchable so operators can roll out one signal at a time.
type HoldSignals struct {
	BounceBackscatter bool
	SpamFlagged       bool
	Malware           bool
	BadSenderIP       bool
	AuthFail          bool
}

// Config is the forward-guard policy input. Enabled is the master switch; when
// off, Verdict never holds regardless of signals. DryRun does not affect the
// verdict itself -- it tells callers whether to enforce the hold or only
// account for it -- so it lives here for callers but is not read by Verdict.
type Config struct {
	Enabled     bool
	DryRun      bool
	HoldSignals HoldSignals
}

// Verdict reports whether a message's external-forward copy should be held and
// the matching reason codes (in a fixed, deterministic order). Reasons are
// stable identifiers safe to surface in the UI, log, and generated MTA rule.
func Verdict(meta MessageMeta, cfg Config) (hold bool, reasons []string) {
	if !cfg.Enabled {
		return false, nil
	}

	sig := cfg.HoldSignals
	// Fixed evaluation order -> deterministic reason slice (no map iteration).
	if sig.AuthFail && meta.SPFFail && meta.DKIMFail && meta.DMARCFail {
		reasons = append(reasons, "auth_fail")
	}
	if sig.BadSenderIP && meta.SenderIPBad {
		reasons = append(reasons, "bad_sender_ip")
	}
	if sig.BounceBackscatter && meta.NullSender {
		reasons = append(reasons, "bounce_backscatter")
	}
	if sig.Malware && meta.MalwareHit {
		reasons = append(reasons, "malware")
	}
	if sig.SpamFlagged && meta.SpamFlagged {
		reasons = append(reasons, "spam_flagged")
	}

	return len(reasons) > 0, reasons
}
