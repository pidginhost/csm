package firewall

import "errors"

var (
	// ErrStateUninitialized means no complete snapshot has been committed.
	ErrStateUninitialized = errors.New("firewall state is uninitialized")
	// ErrStateConflict requires re-reading state before constructing another change.
	ErrStateConflict = errors.New("firewall state revision conflict")
	// ErrStateCorrupt means stored state cannot safely be used or overwritten.
	ErrStateCorrupt = errors.New("firewall state is corrupt or unsupported")
)

// StateStore is the firewall-owned, lossless persistence contract. It does not
// activate the engine's storage cutover. No method filters, normalizes, merges,
// infers provenance, renews expiry, or touches the kernel.
//
// Read returns detached state and its revision, or only an error. Replace
// atomically replaces all four collections if the expected revision matches.
// Revision zero initializes a previously uninitialized snapshot. A successful
// replacement returns the new revision; an error returns zero. Callers must not
// mutate input slices during a call. Times retain their persisted instant and
// offset, not process-local monotonic clock or location metadata.
//
// Action admission must later share the private store transaction that replaces
// state; callers must not compose this operation with separate action writes.
type StateStore interface {
	ReadFirewallState() (FirewallState, uint64, error)
	ReplaceFirewallState(expectedRevision uint64, state FirewallState) (uint64, error)
}
