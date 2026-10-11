//go:build linux

package firewall

import (
	"errors"
	"fmt"
	"net"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/nftables"
)

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
	// BlockRefusedExisting: a state row or a kernel element already names
	// the address.
	BlockRefusedExisting BlockRefusal = "existing_effect"
	// BlockRefusedFull: no temporary deny slot is left.
	BlockRefusedFull BlockRefusal = "set_full"
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
// file and the kernel's blocked sets.
type blockSnapshot struct {
	at    time.Time
	state FirewallState
	live  map[string]bool
	temp  int
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
	var conn *nftables.Conn
	if e.liveBlockedDump == nil {
		var err error
		conn, err = newLifecycleConn(e)
		if err != nil {
			return blockSnapshot{}, err
		}
	}
	at := e.expiryNow()
	snap := blockSnapshot{at: at, state: e.loadStateFileAtLocked(at), live: map[string]bool{}}
	tempByIP := blockedStateTempByIP(snap.state)
	for _, set := range []*nftables.Set{e.setBlocked, e.setBlocked6} {
		if set == nil || (set == e.setBlocked6 && !e.cfg.IPv6) {
			continue
		}
		elements, err := e.blockSnapshotElementsLocked(conn, set)
		if err != nil {
			return blockSnapshot{}, fmt.Errorf("listing blocked set %s: %w", set.Name, err)
		}
		var valid []nftables.SetElement
		for _, el := range elements {
			if ip, ok := blockSetIP(set, el.Key); ok {
				snap.live[ip] = true
				valid = append(valid, el)
			}
		}
		_, temp := countLiveBlockElements(valid, tempByIP)
		snap.temp += temp
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
	if verified || blockSnapshotAllows(snap.state, m.IP) {
		return BlockRefusedAllowed
	}
	if seenIP[m.IP] || seenAction[m.Action] {
		return BlockRefusedDuplicate
	}
	if firewallStateHasBlocked(snap.state, m.IP) || snap.live[m.IP] {
		return BlockRefusedExisting
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

func blockSnapshotAllows(state FirewallState, ip string) bool {
	for _, row := range state.Allowed {
		if sameIPString(row.IP, ip) {
			return true
		}
	}
	for _, row := range state.PortAllowed {
		if sameIPString(row.IP, ip) {
			return true
		}
	}
	return false
}

// A mapped key in an IPv6 set cannot enforce an IPv4 packet.
func blockSetIP(set *nftables.Set, key []byte) (string, bool) {
	if len(key) != int(set.KeyType.Bytes) || (len(key) == net.IPv6len && net.IP(key).To4() != nil) {
		return "", false
	}
	return setElementIPString(key)
}
