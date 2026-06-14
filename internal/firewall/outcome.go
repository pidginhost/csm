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
//   - BlockOutcomeAllowlisted: the IP is on a soft-allow list (operator
//     allowed_ips or a verified-bot range), so the auto-block path declined
//     to block it. The nftables input chain drops @blocked_ips before it
//     accepts @allowed_ips, so an allowlisted IP added to blocked_ips would
//     still be dropped; keeping it out of the set is the only safe fix.
//     Operator `firewall deny` uses BlockIPForce, which bypasses this gate,
//     so an explicit deny still wins. Caller should NOT record a block.
//   - BlockOutcomeNoop: the IP was already blocked, or a guard
//     (infra-IP, malformed IP, deny-limit) rejected the call. Caller
//     should treat the call as a no-op locally.
type BlockOutcome string

const (
	BlockOutcomeLive        BlockOutcome = "live"
	BlockOutcomeDryRun      BlockOutcome = "dry_run"
	BlockOutcomeAllowed     BlockOutcome = "allowed"
	BlockOutcomeAllowlisted BlockOutcome = "allowlisted"
	BlockOutcomeNoop        BlockOutcome = "noop"
)
