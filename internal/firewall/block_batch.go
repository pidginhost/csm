package firewall

import (
	"errors"
	"time"
)

// The block batch API compiles on every platform, so portable code can
// compose it; only Linux runs it.

// MaxBlockBatchMembers bounds one block batch, as the admission ledger
// bounds an execution batch (spec 5.5).
const MaxBlockBatchMembers = 64

// MaxBlockReasonBytes bounds the reason a batch member writes on its row.
const MaxBlockReasonBytes = 256

// BlockMember is one timed full-address block an admission attempt may
// apply: the attempt's ID, the canonical address, the reason written on
// its row and the absolute expiry its element never outlives.
type BlockMember struct {
	Action    string
	IP        string
	Reason    string
	ExpiresAt time.Time
}

// BlockRefusal says why a batch member cannot run; empty means it can.
type BlockRefusal string

const (
	// BlockRefusedInvalid: a malformed action ID, address, reason or
	// expiry, or an address not in canonical form.
	BlockRefusedInvalid BlockRefusal = "invalid"
	// BlockRefusedExpired: less than a millisecond of the block is left, or
	// a durable batch member too short to outlive its verification.
	BlockRefusedExpired BlockRefusal = "expired"
	// BlockRefusedUnsupported: the address family is not enabled.
	BlockRefusedUnsupported BlockRefusal = "unsupported"
	// BlockRefusedProtected: infra, the host's own address or one that is
	// never a packet's source.
	BlockRefusedProtected BlockRefusal = "protected"
	// BlockRefusedAllowed: an operator allow or a verified crawler.
	BlockRefusedAllowed BlockRefusal = "allowlisted"
	// BlockRefusedDuplicate: an earlier member names the same address or
	// action.
	BlockRefusedDuplicate BlockRefusal = "duplicate"
	// BlockRefusedExisting: a verified row and its kernel element already
	// block the address for at least the member's lifetime: an untimed
	// element for a permanent row, or one with the time a timed row has
	// left when that row ends no earlier than the member (spec 5.16).
	BlockRefusedExisting BlockRefusal = "existing_effect"
	// BlockRefusedPending: a row or a kernel element names the address
	// without proving an enforced block that covers the member: the row is
	// unverified, has no element or one with another lifetime, an element
	// has no row, or the proven block ends before the member. Recovery or
	// that block's end has to settle it first.
	BlockRefusedPending BlockRefusal = "pending_recovery"
	// BlockRefusedFull: no temporary deny slot is left.
	BlockRefusedFull BlockRefusal = "set_full"
)

// BlockEffect is what a batch did to one member.
type BlockEffect string

const (
	// BlockApplied: the kernel holds the member's element as encoded.
	BlockApplied BlockEffect = "applied"
	// BlockFailed: proven not applied; nothing of it is in the kernel.
	BlockFailed BlockEffect = "failed"
	// BlockUnknown: the element may or may not be in the kernel. Its row
	// stays, marked unverified.
	BlockUnknown BlockEffect = "unknown"
)

// BlockResult is one member's outcome: its effect, the check that refused
// it before the kernel batch, or the error behind a failed or unknown one.
// Existing names the block behind an existing-effect refusal.
type BlockResult struct {
	Effect   BlockEffect
	Refusal  BlockRefusal
	Existing ExistingBlock
	Err      error
}

// ExistingBlock names the block that already holds an address, so a member
// refused as an existing effect can link to it (spec 5.17): the admission
// action that wrote its row, or "eff_" and a digest of an operator or
// earlier row's identity, and when it ends (zero: permanent). The same row
// gets the same ID on every check and after a restart.
type ExistingBlock struct {
	ID        string
	ExpiresAt time.Time
}

// BlockAction names the row an admission attempt wrote: its action ID and
// address.
type BlockAction struct {
	Action, IP string
}

// BlockCheck is the batch check's answer for one member: its refusal and,
// for an existing effect, the block that holds the address.
type BlockCheck struct {
	Refusal  BlockRefusal
	Existing ExistingBlock
}

// ErrBlockBatchRejected marks a member that failed because the kernel
// rejected the whole transaction; a failure before the send does not carry
// it. A failed state restore carries ErrBlockBatchState instead. The owner
// retries rejected members one at a time (P9).
var ErrBlockBatchRejected = errors.New("kernel rejected the block batch")

// ErrBlockBatchState requires the owner to hold automatic execution while
// the engine's state safety changes lack a durable acknowledgement.
var ErrBlockBatchState = errors.New("firewall batch state is unproven")

// blockReadbackSlack covers the kernel's timeout granularity and the
// clock reads around the batch.
const blockReadbackSlack = time.Second

// CoversExpiry reports whether an effect ending at held lasts as long as
// one asked to end at wanted: a permanent effect, zero held, or one ending
// no earlier than wanted within the readback slack. A dry-run forecast
// judges its own blocks by it, so they cover exactly as real ones do.
func CoversExpiry(held, wanted time.Time) bool {
	return held.IsZero() || !held.Before(wanted.Add(-blockReadbackSlack))
}

// MaxShadowBlocks bounds the forecast addresses one admission snapshot
// counts: a dry-run forecast models at most this many active blocks.
const MaxShadowBlocks = 20000

// BlockAnswer is an admission snapshot's answer for one member, naming
// the member it answers.
type BlockAnswer struct {
	Action, IP string
	BlockCheck
}

// BlockAdmission is a read-only answer for one admission turn, from one
// snapshot of the state file and the kernel: each member's local checks
// and the temporary occupancy. No member takes a temporary slot and no
// repeated member is refused: the caller decides which members are ready
// and checks them with ReadyCapacity.
type BlockAdmission struct {
	// Answers holds one answer per member, in member order.
	Answers []BlockAnswer
	// Temporary is how many timed elements the blocked sets hold, both
	// address families together; Limit is the configured temporary limit,
	// zero for none.
	Temporary, Limit int
	// ShadowTemporary and ShadowPermanent count the forecast addresses the
	// sets already hold as a timed element and as an untimed one.
	ShadowTemporary, ShadowPermanent int
}

// Full reports whether the temporary set has no slot left for any member.
func (a BlockAdmission) Full() bool { return a.Limit > 0 && a.Temporary >= a.Limit }

// ReadyCapacity answers the members a turn is ready to run, in order, as a
// batch check answers its capacity: a member repeating an earlier one's
// address or action is a duplicate, and once the occupancy reaches the
// limit the rest find the set full. Only a member that passes takes a slot.
func (a BlockAdmission) ReadyCapacity(ready []BlockMember) []BlockRefusal {
	out := make([]BlockRefusal, len(ready))
	seenIP, seenAction := map[string]bool{}, map[string]bool{}
	temp := a.Temporary
	for i, m := range ready {
		switch {
		case seenIP[m.IP] || seenAction[m.Action]:
			out[i] = BlockRefusedDuplicate
		case a.Limit > 0 && temp >= a.Limit:
			out[i] = BlockRefusedFull
		default:
			temp++
			seenIP[m.IP], seenAction[m.Action] = true, true
		}
	}
	return out
}
