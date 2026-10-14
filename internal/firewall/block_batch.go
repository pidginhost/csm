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
	// block the address: an untimed element for a permanent row, or one
	// with the time a timed row has left (spec 5.16).
	BlockRefusedExisting BlockRefusal = "existing_effect"
	// BlockRefusedPending: a row or a kernel element names the address
	// without proving an enforced block: the row is unverified, has no
	// element or one with another lifetime, or an element has no row.
	// Recovery has to settle it first.
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
type BlockResult struct {
	Effect  BlockEffect
	Refusal BlockRefusal
	Err     error
}

// ErrBlockBatchRejected marks a member that failed because the kernel
// rejected the whole transaction; a failure before the send does not carry
// it. A failed state restore carries ErrBlockBatchState instead. The owner
// retries rejected members one at a time (P9).
var ErrBlockBatchRejected = errors.New("kernel rejected the block batch")

// ErrBlockBatchState requires the owner to hold automatic execution while
// the engine's state safety changes lack a durable acknowledgement.
var ErrBlockBatchState = errors.New("firewall batch state is unproven")
