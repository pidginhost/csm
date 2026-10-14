//go:build linux

package firewall

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
)

func validBlockAction(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if c != '_' && c != '-' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func validBlockReason(reason string) bool {
	if len(reason) > MaxBlockReasonBytes || !utf8.ValidString(reason) {
		return false
	}
	for _, r := range reason {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// blockSnapshot is the one view a batch is checked against: the state
// file and the kernel's blocked sets. blocked and allowed key the checked
// rows by canonical address once, and live the kernel's elements, so each
// member check is a lookup.
type blockSnapshot struct {
	at      time.Time
	prior   FirewallState
	state   FirewallState
	blocked map[string]BlockedEntry
	allowed map[string]bool
	live    map[string]blockObservation
	elapsed time.Time
	temp    int
}

// proves reports whether row is an enforced block the kernel shows: a
// verified row whose element is untimed when the row is permanent, or has
// the time the row has left, within the readback slack, when it is timed.
type blockObservation struct {
	el            nftables.SetElement
	before, after time.Time
}

func (snap blockSnapshot) proves(row BlockedEntry, observed blockObservation, present bool) bool {
	el := observed.el
	switch {
	case row.Unverified || !present:
		return false
	case row.ExpiresAt.IsZero():
		return el.Timeout == 0 && el.Expires == 0
	}
	left := row.ExpiresAt.Sub(snap.at)
	if left <= 0 || el.Timeout <= 0 || el.Expires <= 0 {
		return false
	}
	// Netlink reports time left, not when in the dump it was sampled.
	// Bound that instant and age both bounds through the last set read.
	earliest := el.Expires - snap.elapsed.Sub(observed.before)
	latest := el.Expires - snap.elapsed.Sub(observed.after)
	return earliest > 0 && earliest-left <= blockReadbackSlack && latest-left >= -blockReadbackSlack
}

func (e *Engine) blockSnapshotLocked() (blockSnapshot, error) {
	if e.blockBatchStateErr != nil {
		return blockSnapshot{}, e.blockBatchStateErr
	}
	if e.lifecycle != nil {
		return blockSnapshot{}, errDurableBlockRows
	}
	if e.setBlocked == nil || (e.liveBlockedDump == nil && e.conn == nil) {
		return blockSnapshot{}, errors.New("blocked sets unavailable")
	}
	prior, ok := e.loadStateFileRawLocked()
	if !ok {
		return blockSnapshot{}, fmt.Errorf("%w: firewall state unavailable", ErrBlockBatchState)
	}
	e.overlayUnverifiedBlockActionsLocked(&prior)
	normalizeFirewallStateIPs(&prior)
	var conn *nftables.Conn
	if e.liveBlockedDump == nil {
		var err error
		conn, err = newLifecycleConn(e)
		if err != nil {
			return blockSnapshot{}, err
		}
	}
	now := e.expiryNow()
	at := e.leaseAtLocked(now)
	// Expired rows still own kernel cleanup, notably untimed subnet elements.
	// Only the check view is pruned; intent and restore retain the full image.
	state := copyFirewallState(prior)
	state.Blocked, _ = pruneBlocked(state.Blocked, at)
	state.BlockedNet, _ = pruneBlockedNet(state.BlockedNet, now)
	state.Allowed, _ = pruneAllowed(state.Allowed, now)
	snap := blockSnapshot{at: at, prior: prior, state: state, blocked: map[string]BlockedEntry{}, allowed: map[string]bool{}, live: map[string]blockObservation{}}
	for _, row := range state.Blocked {
		snap.blocked[stateIPKey(row.IP)] = row
	}
	for _, row := range state.Allowed {
		snap.allowed[stateIPKey(row.IP)] = true
	}
	for _, row := range state.PortAllowed {
		snap.allowed[stateIPKey(row.IP)] = true
	}
	tempByIP := blockedStateTempByIP(snap.state)
	for _, set := range []*nftables.Set{e.setBlocked, e.setBlocked6} {
		if set == nil || (set == e.setBlocked6 && !e.cfg.IPv6) {
			continue
		}
		e.leaseNowLocked()
		before := e.lease.at
		elements, err := e.blockSnapshotElementsLocked(conn, set)
		e.leaseNowLocked()
		after := e.lease.at
		if err != nil {
			return blockSnapshot{}, fmt.Errorf("listing blocked set %s: %w", set.Name, err)
		}
		var valid []nftables.SetElement
		for _, el := range elements {
			if ip, ok := blockSetIP(set, el.Key); ok {
				snap.live[ip] = blockObservation{el: el, before: before, after: after}
				valid = append(valid, el)
			}
		}
		_, temp := countLiveBlockElements(valid, tempByIP)
		snap.temp += temp
	}
	snap.at = e.leaseNowLocked()
	snap.elapsed = e.lease.at
	snap.state.Blocked, _ = pruneBlocked(snap.state.Blocked, snap.at)
	clear(snap.blocked)
	for _, row := range snap.state.Blocked {
		snap.blocked[stateIPKey(row.IP)] = row
	}
	return snap, nil
}

// Snapshot dumps use transient deadline sockets; the legacy connection
// may be lasting and has no bound on a reply.
func (e *Engine) blockSnapshotElementsLocked(conn *nftables.Conn, set *nftables.Set) ([]nftables.SetElement, error) {
	if e.liveBlockedDump != nil {
		return e.liveBlockedDump(set)
	}
	return conn.GetSetElements(set)
}

// verifiedRanges asks the verified-crawler callback outside the engine
// lock, as the automatic block path does.
func (e *Engine) verifiedRanges(members []BlockMember) []bool {
	out := make([]bool, len(members))
	for i, m := range members {
		if net.ParseIP(m.IP) != nil {
			out[i] = e.autoBlockVerifiedRange(m.IP)
		}
	}
	return out
}

// checkBlockMembersLocked answers every member against one snapshot. An
// invalid member is refused alone: it takes no slot and names nothing a
// later member could collide with.
func (e *Engine) checkBlockMembersLocked(members []BlockMember, verified []bool, snap blockSnapshot, now time.Time) []BlockRefusal {
	out := make([]BlockRefusal, len(members))
	seenIP, seenAction := map[string]bool{}, map[string]bool{}
	temp := snap.temp
	for i, m := range members {
		out[i] = e.blockRefusalLocked(m, verified[i], snap, now, seenIP, seenAction)
		if out[i] != "" {
			continue
		}
		if e.cfg.DenyTempIPLimit > 0 && temp >= e.cfg.DenyTempIPLimit {
			out[i] = BlockRefusedFull
			continue
		}
		temp++
		seenIP[m.IP], seenAction[m.Action] = true, true
	}
	return out
}

func (e *Engine) blockRefusalLocked(m BlockMember, verified bool, snap blockSnapshot, now time.Time, seenIP, seenAction map[string]bool) BlockRefusal {
	canon, err := canonicalFirewallIP(m.IP)
	if err != nil || canon != m.IP || !validBlockAction(m.Action) || !validBlockReason(m.Reason) || m.ExpiresAt.IsZero() {
		return BlockRefusedInvalid
	}
	if left := m.ExpiresAt.Sub(now); !now.Add(left).Equal(m.ExpiresAt) || m.ExpiresAt.UTC().Year() < 0 || m.ExpiresAt.UTC().Year() > 9999 {
		return BlockRefusedInvalid
	}
	if _, ok := blockTimeout(m.ExpiresAt, now); !ok {
		return BlockRefusedExpired
	}
	parsed := net.ParseIP(m.IP)
	if parsed.To4() == nil && (!e.cfg.IPv6 || e.setBlocked6 == nil) {
		return BlockRefusedUnsupported
	}
	if e.blockProtectionLocked(parsed, m.IP) != nil {
		return BlockRefusedProtected
	}
	key := stateIPKey(m.IP)
	if verified || snap.allowed[key] {
		return BlockRefusedAllowed
	}
	if seenIP[m.IP] || seenAction[m.Action] {
		return BlockRefusedDuplicate
	}
	el, live := snap.live[m.IP]
	row, held := snap.blocked[key]
	switch {
	case held && snap.proves(row, el, live):
		return BlockRefusedExisting
	case held || live:
		return BlockRefusedPending
	}
	return ""
}

// CheckBlockBatch answers, before anything is reserved, which members of a
// batch can run: each is checked on its own against one snapshot of the
// state file and the kernel, and only the members that fail are refused.
// An error refuses the whole call: an empty or oversized batch, durable
// state, or no snapshot.
func (e *Engine) CheckBlockBatch(members []BlockMember) ([]BlockRefusal, error) {
	if len(members) == 0 || len(members) > MaxBlockBatchMembers {
		return nil, fmt.Errorf("a block batch has 1 to %d members", MaxBlockBatchMembers)
	}
	verified := e.verifiedRanges(members)
	e.mu.Lock()
	defer e.mu.Unlock()
	snap, err := e.blockSnapshotLocked()
	if err != nil {
		return nil, err
	}
	return e.checkBlockMembersLocked(members, verified, snap, snap.at), nil
}

// blockReadbackSlack covers the kernel's timeout granularity and the
// clock reads around the batch.
const blockReadbackSlack = time.Second

// kernelRejected follows error provenance: a definitive reply proves the
// atomic transaction failed even if later acknowledgements were lost.
// A local receive error only says the reply could not be read.
func kernelRejected(err error) bool {
	if timed, ok := err.(interface{ Timeout() bool }); ok && timed.Timeout() {
		return false
	}
	switch cause := err.(type) {
	case *netlink.OpError:
		if cause.Op == "receive" {
			errno, ok := cause.Err.(syscall.Errno)
			return ok && kernelRejected(errno)
		}
		return cause.Op == "send-messages" && kernelRejected(cause.Err)
	case syscall.Errno:
		switch cause {
		case syscall.EINTR, syscall.EAGAIN, syscall.ENOBUFS, syscall.ETIMEDOUT:
			return false
		}
		return cause != 0
	case interface{ Unwrap() []error }:
		for _, child := range cause.Unwrap() {
			if kernelRejected(child) {
				return true
			}
		}
	case interface{ Unwrap() error }:
		return kernelRejected(cause.Unwrap())
	}
	return false
}

// A lasting connection dials before returning, so dial and socket-option
// errors are known before any send. The deadline covers send and readback.
func newBlockBatchConn(e *Engine, extra ...nftables.ConnOption) (*nftables.Conn, error) {
	if e.conn == nil {
		return nil, errors.New("firewall batch transport unavailable")
	}
	opts := []nftables.ConnOption{
		nftables.AsLasting(),
		nftables.WithNetNSFd(e.conn.NetNS),
		nftables.WithTestDial(e.conn.TestDial),
		nftables.WithSockOptions(applyNFTSocketBuffer),
	}
	if e.conn.TestDial == nil {
		opts = append(opts, nftables.WithSockOptions(applyLifecycleSocketDeadline))
	}
	opts = append(opts, extra...)
	return nftables.New(opts...)
}

// readbackMatches bounds time left between the encoded timeout and that
// timeout minus elapsed send/readback time and slack. The timeout itself
// must match independently of elapsed time, allowing kernel tick truncation.
// An older element with a longer timeout can have the same time left.
func readbackMatches(el nftables.SetElement, encoded, window time.Duration) bool {
	if el.Expires <= 0 || el.Expires > encoded || encoded-el.Expires > window {
		return false
	}
	return el.Timeout > 0 && el.Timeout <= encoded && encoded-el.Timeout <= blockReadbackSlack && el.Expires <= el.Timeout
}

func (e *Engine) readbackLocked(conn *nftables.Conn, set *nftables.Set) ([]nftables.SetElement, error) {
	if e.liveBlockedDump != nil {
		return e.liveBlockedDump(set)
	}
	return conn.GetSetElements(set)
}

// ApplyBlockBatch runs the members of one batch: it checks them again
// against the current state and kernel, writes every remaining row (with
// its action ID) in one state write, adds their elements in one netlink
// transaction on a fresh connection with a deadline, and reads the sets
// back. A member is applied only when the readback shows its element as
// encoded. A kernel rejection fails every member and restores the state;
// any other uncertainty leaves them unknown, their rows marked unverified.
// An error means nothing was written or sent.
func (e *Engine) ApplyBlockBatch(members []BlockMember) ([]BlockResult, error) {
	if len(members) == 0 || len(members) > MaxBlockBatchMembers {
		return nil, fmt.Errorf("a block batch has 1 to %d members", MaxBlockBatchMembers)
	}
	verified := e.verifiedRanges(members)
	e.mu.Lock()
	defer e.mu.Unlock()
	snap, err := e.blockSnapshotLocked()
	if err != nil {
		return nil, err
	}
	now := snap.at
	results := make([]BlockResult, len(members))
	defer func() {
		// Other members can spend a proved block's remaining lifetime.
		snap.at = e.leaseNowLocked()
		snap.elapsed = e.lease.at
		for i, result := range results {
			if result.Refusal != BlockRefusedExisting {
				continue
			}
			row := snap.blocked[stateIPKey(members[i].IP)]
			observed, present := snap.live[members[i].IP]
			if !snap.proves(row, observed, present) {
				results[i].Refusal = BlockRefusedPending
			}
		}
	}()
	next := copyFirewallState(snap.prior)
	encoded := make(map[int]time.Duration)
	var run []int
	var elems4, elems6 []nftables.SetElement
	for i, refusal := range e.checkBlockMembersLocked(members, verified, snap, now) {
		if refusal != "" {
			results[i] = BlockResult{Effect: BlockFailed, Refusal: refusal}
			continue
		}
		m := members[i]
		upsertBlockedEntryInState(&next, BlockedEntry{IP: m.IP, Reason: m.Reason, Source: SourceAutoResponse, BlockedAt: now, ExpiresAt: m.ExpiresAt.UTC(), ActionID: m.Action})
		run = append(run, i)
	}
	if len(run) == 0 {
		return results, nil
	}
	if persistErr := e.persistFirewallIntent(snap.prior, next); persistErr != nil {
		e.suppressFailedBlockActionsLocked(blockActions(members, run))
		e.blockBatchStateErr = errors.Join(ErrBlockBatchState, persistErr)
		for _, i := range run {
			results[i] = BlockResult{Effect: BlockFailed, Err: e.blockBatchStateErr}
		}
		return results, nil
	}

	conn, err := newBlockBatchConn(e)
	if err == nil {
		defer func() { _ = conn.CloseLasting() }()
		// State persistence can consume a member's remaining lifetime.
		// Refresh at one instant immediately before queueing the send.
		sendAt := e.leaseNowLocked()
		var ready []int
		for _, i := range run {
			m := members[i]
			timeout, ok := blockTimeout(m.ExpiresAt, sendAt)
			if !ok {
				results[i] = BlockResult{Effect: BlockFailed, Refusal: BlockRefusedExpired}
				e.suppressFailedBlockActionsLocked([]string{m.Action})
				removeBlockedIPFromState(&next, m.IP)
				continue
			}
			encoded[i] = timeout
			parsed := net.ParseIP(m.IP)
			if ip4 := parsed.To4(); ip4 != nil {
				elems4 = append(elems4, nftables.SetElement{Key: ip4, Timeout: timeout})
			} else {
				elems6 = append(elems6, nftables.SetElement{Key: parsed.To16(), Timeout: timeout})
			}
			ready = append(ready, i)
		}
		run = ready
		if len(run) == 0 {
			return results, nil
		}
	}
	if err == nil && len(elems4) > 0 {
		err = conn.SetAddElements(e.setBlocked, elems4)
	}
	if err == nil && len(elems6) > 0 {
		err = conn.SetAddElements(e.setBlocked6, elems6)
	}
	sent := err == nil
	start := time.Now()
	if sent {
		err = conn.Flush()
	}
	if err != nil && (!sent || kernelRejected(err)) {
		if restoreErr := e.saveState(&snap.prior); restoreErr != nil {
			e.suppressFailedBlockActionsLocked(blockActions(members, run))
			e.blockBatchStateErr = errors.Join(ErrBlockBatchState, restoreErr)
			err = errors.Join(err, fmt.Errorf("state restore failed: %w", e.blockBatchStateErr))
		} else if sent {
			err = errors.Join(ErrBlockBatchRejected, err)
		}
		for _, i := range run {
			results[i] = BlockResult{Effect: BlockFailed, Err: err}
		}
		return results, nil
	}

	var found map[string]nftables.SetElement
	if err == nil {
		found, err = e.readbackBatchLocked(conn, len(elems4) > 0, len(elems6) > 0)
	}
	window := time.Since(start) + blockReadbackSlack
	var unknown []int
	for _, i := range run {
		m := members[i]
		if el, ok := found[m.IP]; ok && readbackMatches(el, encoded[i], window) {
			results[i] = BlockResult{Effect: BlockApplied}
			e.legacyFileAuditLocked("block", m.IP, m.Reason, SourceAutoResponse, encoded[i])
			continue
		}
		results[i] = BlockResult{Effect: BlockUnknown, Err: err}
		unknown = append(unknown, i)
	}
	if len(unknown) > 0 {
		if markErr := e.flagUnknownRowsLocked(members, unknown, next); markErr != nil {
			for _, i := range unknown {
				results[i].Err = errors.Join(results[i].Err, markErr)
			}
		}
	}
	return results, nil
}

func (e *Engine) readbackBatchLocked(conn *nftables.Conn, v4, v6 bool) (map[string]nftables.SetElement, error) {
	found := map[string]nftables.SetElement{}
	var readErr error
	for _, read := range []struct {
		set  *nftables.Set
		used bool
	}{{e.setBlocked, v4}, {e.setBlocked6, v6}} {
		if !read.used {
			continue
		}
		elements, err := e.readbackLocked(conn, read.set)
		if err != nil {
			readErr = errors.Join(readErr, fmt.Errorf("reading back blocked set %s: %w", read.set.Name, err))
			continue
		}
		for _, el := range elements {
			if ip, ok := blockSetIP(read.set, el.Key); ok {
				found[ip] = el
			}
		}
	}
	return found, readErr
}

// flagUnknownRowsLocked persists unknown marks; failed persistence keeps
// live suppression and exposes the shared state-integrity hold.
func (e *Engine) flagUnknownRowsLocked(members []BlockMember, unknown []int, next FirewallState) error {
	flag := make(map[string]bool, len(unknown))
	for _, i := range unknown {
		flag[members[i].Action] = true
	}
	for i, row := range next.Blocked {
		if flag[row.ActionID] {
			next.Blocked[i].Unverified = true
		}
	}
	e.rememberUnverifiedBlockActionsLocked(next)
	if err := e.saveState(&next); err != nil {
		e.blockBatchStateErr = errors.Join(ErrBlockBatchState, err)
		return e.blockBatchStateErr
	}
	return nil
}

func blockActions(members []BlockMember, indices []int) []string {
	out := make([]string, 0, len(indices))
	for _, i := range indices {
		out = append(out, members[i].Action)
	}
	return out
}

// A mapped key in an IPv6 set cannot enforce an IPv4 packet.
func blockSetIP(set *nftables.Set, key []byte) (string, bool) {
	if len(key) != int(set.KeyType.Bytes) || (len(key) == net.IPv6len && net.IP(key).To4() != nil) {
		return "", false
	}
	return setElementIPString(key)
}

// ProbeBlockState proves the current snapshot without sending an action.
func (e *Engine) ProbeBlockState() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, err := e.blockSnapshotLocked()
	return err
}
