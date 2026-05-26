package firewall

// BlockOutcome reports what the firewall engine actually did in response
// to a BlockIPOutcome call. Auto-response callers consult it to decide
// whether to apply local side effects (state.IPs append, BlocksThisHour++,
// permanent threat-db insert, AUTO-BLOCK finding) - those should only fire
// when the kernel firewall was mutated.
//
// Returned values:
//
//   - BlockOutcomeLive: nftables was mutated. Caller should record the
//     block locally and emit the operator-facing Critical "AUTO-BLOCK"
//     finding.
//   - BlockOutcomeDryRun: auto_response.dry_run intercepted the call. No
//     kernel mutation occurred. Caller should NOT record a real block;
//     emit a Warning-level dry-run notice instead so operators can see
//     what would have been blocked without believing the block landed.
//   - BlockOutcomeAllowed: the verdict callback returned "allow", so CSM
//     intentionally did not block. Caller should NOT record a block and
//     should NOT emit an AUTO-BLOCK finding (the panel already knows it
//     downgraded the decision).
//   - BlockOutcomeNoop: the IP was already blocked, or a guard
//     (infra-IP, malformed IP, deny-limit) rejected the call. Caller
//     should treat the call as a no-op locally.
type BlockOutcome string

const (
	BlockOutcomeLive    BlockOutcome = "live"
	BlockOutcomeDryRun  BlockOutcome = "dry_run"
	BlockOutcomeAllowed BlockOutcome = "allowed"
	BlockOutcomeNoop    BlockOutcome = "noop"
)
