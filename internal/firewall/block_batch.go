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
	// BlockRefusedExpired: less than a millisecond of the block is left.
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
