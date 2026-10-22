//go:build linux

package firewall

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"time"
	"unicode/utf8"
)

// BlockBatchResult is what a durable block batch did: the action it ran or
// replayed, and, in call order, why each member was left out (empty when the
// member ran). A replayed batch reports no refusals.
type BlockBatchResult struct {
	Action   FirewallAction
	Refusals []BlockRefusal
}

// BlockBatchRequest runs automatic temporary blocks as one durable batch
// (spec 5.5). Each member is checked on its own against one committed
// snapshot and refused members are left out; the rest share one admission,
// one kernel transaction and one outcome. A lone valid member runs as an
// ordinary one-request action under its own ID. A repeated call naming a
// stored batch observes it and never plans it again. Nothing evicts for a
// batch: a full temporary set refuses the member.
func (e *Engine) BlockBatchRequest(header ActionRequest, members []ActionRequest, budget *ScanAdmission) (BlockBatchResult, error) {
	if !validBlockBatchHeader(header) || len(members) == 0 || len(members) > MaxActionMembers {
		return BlockBatchResult{}, errors.New("invalid firewall block batch")
	}
	if e.autoResponseDryRunEnabled() {
		return BlockBatchResult{}, ErrActionDryRun
	}
	members = slices.Clone(members)
	// The verified-range callback runs outside the engine lock, as it does
	// for a single automatic block.
	verified := make([]bool, len(members))
	for i := range members {
		if canonical, err := canonicalFirewallIP(members[i].Target); err == nil {
			members[i].Target = canonical
			verified[i] = e.autoBlockVerifiedRange(canonical)
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.lifecycle == nil {
		return BlockBatchResult{}, errors.New("firewall lifecycle unavailable")
	}
	if replayed, result, err := e.replayBlockBatchLocked(header, members); replayed || err != nil {
		return result, err
	}
	if replayed, result, err := e.replayBlockSingleLocked(header, members); replayed || err != nil {
		return result, err
	}
	if err := e.lifecycleReadyLocked(); err != nil {
		return BlockBatchResult{}, err
	}
	prior, _, err := e.readCommittedStateLocked()
	if err != nil {
		return BlockBatchResult{}, err
	}
	at := e.leaseNowLocked()
	result := BlockBatchResult{Refusals: e.checkBlockBatchLocked(header, members, verified, prior, at)}
	next := copyFirewallState(prior)
	var ran []ActionMember
	for i, m := range members {
		if result.Refusals[i] != "" {
			continue
		}
		ran = append(ran, ActionMember{Request: m, Budget: budget})
		next.Blocked = append(next.Blocked, BlockedEntry{IP: m.Target, Reason: m.Reason, Source: InferProvenance("block", m.Reason), BlockedAt: at, ExpiresAt: at.Add(m.TTL), ActionID: m.ID})
	}
	if len(ran) == 0 {
		return result, nil
	}
	// The new deadlines may use a forward-ratcheted lease, as a single
	// block's does: save its clock before the intent.
	if leaseErr := e.saveLeaseLocked(); leaseErr != nil {
		return result, fmt.Errorf("saving block lease: %w", leaseErr)
	}
	plan := FirewallAction{Request: header, Members: ran, After: next, CreatedAt: at}
	if len(ran) == 1 {
		// A lone member writes the record a single block writes.
		next.Blocked[len(next.Blocked)-1].ActionID = ""
		plan = FirewallAction{Request: ran[0].Request, Budget: budget, After: next, CreatedAt: at}
	}
	result.Action, err = e.runDurablePlanLocked(plan)
	return result, durableActionOutcome(result.Action, err)
}

// validBlockBatchHeader holds a batch header to plan 1.5d-1's shape: an
// automatic block with no target, link, lifetime or charge of its own.
func validBlockBatchHeader(h ActionRequest) bool {
	return validBlockAction(h.ID) && h.Operation == "block" && h.Automatic && h.Actor != "" && h.Source != "" && utf8.ValidString(h.Actor) && utf8.ValidString(h.ActorDetail) && utf8.ValidString(h.Source) &&
		h.Target == "" && h.Reason == "" && h.FindingID == "" && h.IncidentID == "" && h.UndoOf == "" && h.TTL == 0
}

// replayBlockBatchLocked observes a batch already stored under the header's
// ID. The call must name that batch's members, in order, among its own.
func (e *Engine) replayBlockBatchLocked(header ActionRequest, members []ActionRequest) (bool, BlockBatchResult, error) {
	stored, err := e.lifecycle.Store.ReadFirewallAction(header.ID)
	if errors.Is(err, ErrActionMissing) {
		return false, BlockBatchResult{}, nil
	}
	if err != nil {
		return true, BlockBatchResult{}, err
	}
	next := 0
	for _, m := range members {
		if next < len(stored.Members) && stored.Members[next].Request == m {
			next++
		}
	}
	if stored.Request != header || len(stored.Members) < 2 || next != len(stored.Members) {
		return true, BlockBatchResult{}, ErrStateConflict
	}
	a, executeErr := e.lifecycle.Execute(stored, engineActionKernel{e})
	current, _, readErr := e.readCommittedStateLocked()
	if readErr == nil {
		e.installCommittedCache(current)
	}
	return true, BlockBatchResult{Action: a}, errors.Join(durableActionOutcome(a, executeErr), readErr)
}

// replayBlockSingleLocked handles the single-request shape whose header was
// never stored. The known member is immutable; other IDs do not become
// part of the stored action merely because policy now permits them. Group
// occurrences before reading so each ID is decoded once without retaining
// every stored action's snapshots. A later occurrence may be the exact request.
func (e *Engine) replayBlockSingleLocked(header ActionRequest, members []ActionRequest) (bool, BlockBatchResult, error) {
	var stored FirewallAction
	found, known := false, false
	occurrences := make(map[string][]ActionRequest, len(members))
	for _, m := range members {
		occurrences[m.ID] = append(occurrences[m.ID], m)
	}
	for _, m := range members {
		candidates, unread := occurrences[m.ID]
		if !unread {
			continue
		}
		delete(occurrences, m.ID)
		a, err := e.lifecycle.Store.ReadFirewallAction(m.ID)
		if errors.Is(err, ErrActionMissing) {
			continue
		}
		if err != nil {
			return true, BlockBatchResult{}, err
		}
		known = true
		matched := false
		for _, candidate := range candidates {
			if !validBlockBatchMember(header, candidate) || !a.IsRequest(candidate) {
				continue
			}
			matched = true
			break
		}
		if !matched {
			continue
		}
		if found && stored.Request.ID != a.Request.ID {
			return true, BlockBatchResult{}, ErrStateConflict
		}
		stored, found = a, true
	}
	if !found {
		if known {
			return true, BlockBatchResult{}, ErrStateConflict
		}
		return false, BlockBatchResult{}, nil
	}
	a, executeErr := e.lifecycle.Execute(stored, engineActionKernel{e})
	current, _, readErr := e.readCommittedStateLocked()
	if readErr == nil {
		e.installCommittedCache(current)
	}
	return true, BlockBatchResult{Action: a}, errors.Join(durableActionOutcome(a, executeErr), readErr)
}

// checkBlockBatchLocked answers every member against the committed snapshot.
// A refused member takes no slot and names nothing a later member collides
// with.
func (e *Engine) checkBlockBatchLocked(header ActionRequest, members []ActionRequest, verified []bool, prior FirewallState, at time.Time) []BlockRefusal {
	rows := make(map[string]BlockedEntry, len(prior.Blocked))
	temp := 0
	for _, row := range prior.Blocked {
		// Expiry cannot settle an unverified row; its owner must.
		if row.Unverified || row.ExpiresAt.IsZero() || row.ExpiresAt.After(at) {
			rows[stateIPKey(row.IP)] = row
		}
		if !row.Unverified && row.ExpiresAt.After(at) {
			temp++
		}
	}
	out := make([]BlockRefusal, len(members))
	seenIP, seenID := map[string]bool{}, map[string]bool{header.ID: true}
	for i, m := range members {
		out[i] = e.blockBatchRefusalLocked(header, m, verified[i], rows, at, seenIP, seenID)
		if out[i] != "" {
			continue
		}
		if e.cfg.DenyTempIPLimit > 0 && temp >= e.cfg.DenyTempIPLimit {
			out[i] = BlockRefusedFull
			continue
		}
		temp++
		seenIP[m.Target], seenID[m.ID] = true, true
	}
	return out
}

func validBlockBatchMember(header, m ActionRequest) bool {
	parsed := net.ParseIP(m.Target)
	if parsed == nil || !validBlockAction(m.ID) || !validBlockReason(m.Reason) || !utf8.ValidString(m.FindingID) || !utf8.ValidString(m.IncidentID) ||
		m.Operation != "block" || !m.Automatic || m.TTL <= 0 || m.UndoOf != "" || m.Actor != header.Actor || m.ActorDetail != header.ActorDetail || m.Source != header.Source {
		return false
	}
	return true
}

func (e *Engine) blockBatchRefusalLocked(header, m ActionRequest, verified bool, rows map[string]BlockedEntry, at time.Time, seenIP, seenID map[string]bool) BlockRefusal {
	parsed := net.ParseIP(m.Target)
	if !validBlockBatchMember(header, m) {
		return BlockRefusedInvalid
	}
	if _, ok := blockTimeout(at.Add(m.TTL), at); !ok {
		return BlockRefusedExpired
	}
	if parsed.To4() == nil && (!e.cfg.IPv6 || e.setBlocked6 == nil) {
		return BlockRefusedUnsupported
	}
	if e.blockProtectionLocked(parsed, m.Target) != nil {
		return BlockRefusedProtected
	}
	if verified || e.operatorSoftAllowedLocked(m.Target) {
		return BlockRefusedAllowed
	}
	if seenIP[m.Target] || seenID[m.ID] {
		return BlockRefusedDuplicate
	}
	if row, held := rows[m.Target]; held {
		if !row.Unverified && CoversExpiry(row.ExpiresAt, at.Add(m.TTL)) {
			return BlockRefusedExisting
		}
		return BlockRefusedPending
	}
	return ""
}
