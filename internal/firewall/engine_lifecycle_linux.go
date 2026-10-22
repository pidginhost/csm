//go:build linux

package firewall

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"time"

	"github.com/google/nftables"
	"github.com/pidginhost/csm/internal/actionlog"
)

// AttachLifecycle is a construction-time injection, not a migration. The owner
// must already have initialized the complete store and own the daemon lock.
func (e *Engine) AttachLifecycle(l *Lifecycle) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if l == nil || l.Store == nil || e.lifecycle != nil {
		return errors.New("invalid firewall lifecycle attachment")
	}
	state, revision, err := l.Store.ReadFirewallState()
	if err != nil {
		return err
	}
	if l.Audit == nil {
		l.Audit = writeFirewallActionAudit
	}
	e.lifecycle = l
	e.stateRevision = revision
	e.installCommittedCache(state)
	return nil
}

// writeFirewallActionAudit records one event per member and one evict_temp
// event per row a member removed to make room. Several events go in one
// durable write, each with the action's outcome and version.
func writeFirewallActionAudit(a FirewallAction) error {
	var records []actionlog.Record
	for _, m := range a.ActionMembers() {
		records = append(records, firewallAuditRecord(a, m.Request))
		for _, v := range removedVictims(a, m) {
			r := firewallAuditRecord(a, m.Request)
			r.Action, r.Target, r.Reason = "evict_temp", v.IP, evictTempReason
			records = append(records, r)
		}
	}
	if len(records) == 1 {
		return actionlog.WriteDurable(records[0])
	}
	return actionlog.WriteDurableBatch(records)
}

func firewallAuditRecord(a FirewallAction, req ActionRequest) actionlog.Record {
	return actionlog.Record{ActionID: req.ID, ActionVersion: a.AuditVersion, IncidentID: req.IncidentID, UndoOf: req.UndoOf, Timestamp: a.UpdatedAt, Op: firewallAuditOperation(req), Action: req.Operation, Actor: actionlog.Actor(req.Actor), ActorDetail: req.ActorDetail, FindingID: req.FindingID, Target: req.Target, Reason: req.Reason, Result: actionlog.Result(a.Phase), Error: a.Detail}
}
func (e *Engine) lifecycleEnabled() bool { e.mu.Lock(); defer e.mu.Unlock(); return e.lifecycle != nil }
func (e *Engine) installCommittedCache(state FirewallState) {
	e.installCommittedCacheAtLocked(state, e.expiryNow())
}

func (e *Engine) installCommittedCacheAtLocked(state FirewallState, now time.Time) {
	state = copyFirewallState(state)
	e.overlayUnverifiedBlockActionsLocked(&state)
	e.stateCache = &state
	e.applyExpiryAtLocked(now)
	e.rebuildIndexLocked()
}
func (e *Engine) lifecycleReadyLocked() error {
	if e.lifecycle == nil {
		return nil
	}
	pending, err := e.lifecycle.Store.PendingFirewallActions()
	if err != nil {
		return err
	}
	if len(pending) > 0 {
		return fmt.Errorf("%w: %s", ErrActionUnknown, pending[0].Request.ID)
	}
	state, _, err := e.readCommittedStateLocked()
	if err != nil {
		return err
	}
	e.installCommittedCache(state)
	return nil
}
func (e *Engine) RecoverActions() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.lifecycle == nil {
		return errors.New("firewall lifecycle unavailable")
	}
	recoverErr := e.lifecycle.Recover(engineActionKernel{e})
	state, _, readErr := e.readCommittedStateLocked()
	if readErr == nil {
		e.installCommittedCache(state)
	}
	return errors.Join(recoverErr, readErr)
}

// PendingActions reports the actions recovery could not settle. While any
// exists the engine refuses new mutations, so this is what an operator needs
// to see before deciding anything.
func (e *Engine) PendingActions() ([]FirewallAction, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.lifecycle == nil {
		return nil, errors.New("firewall lifecycle unavailable")
	}
	return e.lifecycle.Store.PendingFirewallActions()
}

// ResolveAction records an outcome an operator established by hand for an
// action the kernel cannot prove. The committed cache follows the outcome,
// whether it came from the operator or from the kernel proving it after all.
func (e *Engine) ResolveAction(id, outcome, detail string) (FirewallAction, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.lifecycle == nil {
		return FirewallAction{}, errors.New("firewall lifecycle unavailable")
	}
	a, err := e.lifecycle.Resolve(id, outcome, detail, engineActionKernel{e})
	state, _, readErr := e.readCommittedStateLocked()
	if readErr == nil {
		e.installCommittedCache(state)
	}
	return a, errors.Join(durableActionOutcome(a, err), readErr)
}

func (e *Engine) UndoAction(req ActionRequest) (FirewallAction, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.lifecycle == nil {
		return FirewallAction{}, errors.New("firewall lifecycle unavailable")
	}
	a, err := e.lifecycle.Undo(req, engineActionKernel{e})
	err = durableActionOutcome(a, err)
	if a.Phase == "verified" {
		current, _, readErr := e.readCommittedStateLocked()
		if readErr != nil {
			return a, errors.Join(err, readErr)
		}
		e.installCommittedCache(current)
	}
	return a, err
}
func (e *Engine) runDurableLocked(req ActionRequest, budget *ScanAdmission, next FirewallState) error {
	_, err := e.runDurablePlanLocked(FirewallAction{Request: req, After: next, Budget: budget})
	return err
}

// runDurablePlanLocked admits and executes a plan the caller made from the
// committed snapshot it last read. Its request, members, budget and After
// state are the caller's; Before, revision and kernel evidence are read here.
// Only an admitted attempt's error speaks for its durable outcome; a refusal
// before admission keeps the caller's refusal record.
func (e *Engine) runDurablePlanLocked(plan FirewallAction) (FirewallAction, error) {
	if e.stateReadErr != nil {
		return FirewallAction{}, e.stateReadErr
	}
	expectedRevision := e.stateRevision
	if err := e.lifecycleReadyLocked(); err != nil {
		return FirewallAction{}, err
	}
	prior, revision, err := e.readCommittedStateLocked()
	if err != nil {
		return FirewallAction{}, err
	}
	if revision != expectedRevision {
		return FirewallAction{}, fmt.Errorf("%w: planning snapshot changed", ErrStateConflict)
	}
	if plan.Request.ID == "" {
		plan.Request.ID = rand.Text()
	}
	plan.Request = normalizeActionRequest(plan.Request)
	if len(plan.Members) == 1 {
		// A one-member manifest repeats its header exactly.
		plan.Members[0].Request = plan.Request
	}
	plan.Before, plan.Revision = prior, revision
	at := plan.CreatedAt
	if at.IsZero() {
		at = e.expiryNow()
	}
	if prepareErr := e.prepareActionKernelAt(&plan, at); prepareErr != nil {
		return FirewallAction{}, prepareErr
	}
	a, err := e.lifecycle.Execute(plan, engineActionKernel{e})
	if a.Phase == "verified" {
		e.installCommittedCache(a.After)
	}
	return a, durableActionOutcome(a, err)
}

func stateFingerprint(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return "csm:" + hex.EncodeToString(sum[:])
}
func (e *Engine) actionSet(name string) *nftables.Set {
	for _, set := range []*nftables.Set{e.setBlocked, e.setBlocked6, e.setAllowed, e.setAllowed6, e.setBlockedNet, e.setBlockedNet6} {
		if set != nil && set.Name == name {
			return set
		}
	}
	return nil
}
func actionSetNames(ipv6 bool) []string {
	names := []string{"blocked_ips", "allowed_ips", "blocked_nets"}
	if ipv6 {
		names = append(names, "blocked_ips6", "allowed_ips6", "blocked_nets6")
	}
	return names
}
func desiredActionSets(state FirewallState, ipv6 bool, now time.Time) map[string][]ActionElement {
	out := make(map[string][]ActionElement)
	for _, name := range actionSetNames(ipv6) {
		out[name] = nil
	}
	for _, b := range state.Blocked {
		if b.Unverified || (!b.ExpiresAt.IsZero() && !b.ExpiresAt.After(now)) {
			continue
		}
		name, key, ok := blockedSetKey(b.IP, ipv6)
		if !ok {
			continue
		}
		out[name] = append(out[name], ActionElement{Key: key, Comment: stateFingerprint(b), ExpiresAt: b.ExpiresAt})
	}
	allowed := make(map[string][]AllowedEntry)
	for _, a := range state.Allowed {
		if a.ExpiresAt.IsZero() || a.ExpiresAt.After(now) {
			allowed[a.IP] = append(allowed[a.IP], a)
		}
	}
	for address, rows := range allowed {
		ip := net.ParseIP(address)
		if ip == nil {
			continue
		}
		name := "allowed_ips"
		key := ip.To4()
		if key == nil {
			if !ipv6 {
				continue
			}
			name += "6"
			key = ip.To16()
		}
		out[name] = append(out[name], ActionElement{Key: key, Comment: stateFingerprint(rows)})
	}
	var activeSubnets []SubnetEntry
	for _, entry := range state.BlockedNet {
		if entry.ExpiresAt.IsZero() || entry.ExpiresAt.After(now) {
			activeSubnets = append(activeSubnets, entry)
		}
	}
	v4, v6 := subnetIntervalElements(activeSubnets, ipv6, now)
	for i, elems := range [][]nftables.SetElement{v4, v6} {
		name := "blocked_nets"
		if i == 1 {
			name += "6"
		}
		for _, elem := range elems {
			comment := ""
			// Interval-end sentinels cannot carry element userdata. The start
			// marker identifies the complete union, including source expiry.
			if !elem.IntervalEnd {
				comment = stateFingerprint(activeSubnets)
			}
			out[name] = append(out[name], ActionElement{Key: elem.Key, End: elem.IntervalEnd, Comment: comment})
		}
	}
	return out
}

// blockedSetKey names the blocked set and element key for an address.
func blockedSetKey(address string, ipv6 bool) (string, []byte, bool) {
	ip := net.ParseIP(address)
	if ip == nil {
		return "", nil, false
	}
	if key := ip.To4(); key != nil {
		return "blocked_ips", key, true
	}
	if !ipv6 {
		return "", nil, false
	}
	return "blocked_ips6", ip.To16(), true
}

func (e *Engine) prepareActionKernel(a *FirewallAction) error {
	return e.prepareActionKernelAt(a, e.expiryNow())
}

// prepareActionKernelAt keeps a planner's chosen instant for all its evidence.
func (e *Engine) prepareActionKernelAt(a *FirewallAction, now time.Time) error {
	a.CreatedAt = now
	desired := desiredActionSets(a.After, e.setBlocked6 != nil, now)
	expected := desiredActionSets(a.Before, e.setBlocked6 != nil, now)
	unpruned := desiredActionSets(a.Before, e.setBlocked6 != nil, time.Time{})
	conn, connErr := newLifecycleConn(e)
	if connErr != nil {
		return connErr
	}
	names := requiredActionSets(*a)
	a.KernelBefore = nil
	a.KernelAfter = nil
	for _, name := range names {
		at := e.leaseNowLocked()
		actual, readErr := readActionSet(conn, name)
		if readErr != nil {
			return readErr
		}
		elems := actual.elements
		if !actual.exists && e.actionSet(name) != nil {
			return fmt.Errorf("%w: set %s disappeared", ErrActionUnknown, name)
		}
		if !matchActionElements(expected[name], elems, at) && !matchActionElements(unpruned[name], elems, at) {
			return fmt.Errorf("%w: live set %s differs from committed state", ErrActionUnknown, name)
		}
		before := ActionSet{Name: name, Exists: actual.exists}
		now := e.leaseNowLocked()
		for _, elem := range elems {
			entry := ActionElement{Key: bytes.Clone(elem.Key), End: elem.IntervalEnd, Comment: elem.Comment}
			if elem.Timeout > 0 {
				entry.ExpiresAt = now.Add(elem.Expires)
				for _, known := range expected[name] {
					if bytes.Equal(known.Key, entry.Key) && known.Comment == entry.Comment {
						entry.ExpiresAt = known.ExpiresAt
						break
					}
				}
			}
			before.Elements = append(before.Elements, entry)
		}
		a.KernelBefore = append(a.KernelBefore, before)
		a.KernelAfter = append(a.KernelAfter, ActionSet{Name: name, Exists: actual.exists, Elements: desired[name]})
	}
	return nil
}

type engineActionKernel struct{ e *Engine }

func (k engineActionKernel) ApplyFirewallAction(a FirewallAction) error {
	if a.Request.Operation == "apply" {
		conn, err := newLifecycleConn(k.e)
		if err != nil {
			return err
		}
		priorConn := k.e.conn
		k.e.conn = conn
		defer func() { k.e.conn = priorConn }()
		return k.e.applyRulesetLocked(a.Ruleset.Marker)
	}
	if err := k.applyActionSets(a, true); err != nil {
		if len(a.Members) > 1 || !isNftNotFound(err) {
			return err
		}
		// The kernel expires timed elements on its own, so a delete can name an
		// element that is already gone. That batch changed nothing, so rewrite
		// the complete set instead of reporting an uncertain outcome.
		return k.applyActionSets(a, false)
	}
	return nil
}

// applyActionSets writes the intended effect of one action. A whole-set rewrite
// costs one message per retained element, which on a busy host is most of the
// work a single block does, so unchanged elements are left alone where the set
// allows it.
func (k engineActionKernel) applyActionSets(a FirewallAction, delta bool) error {
	conn, connErr := newLifecycleConn(k.e)
	if connErr != nil {
		return connErr
	}
	now := k.e.leaseNowLocked()
	for i, state := range a.KernelAfter {
		if !state.Exists {
			continue
		}
		set := k.e.actionSet(state.Name)
		if set == nil {
			return fmt.Errorf("firewall recovery set unavailable: %s", state.Name)
		}
		if !delta || i >= len(a.KernelBefore) || !deltaApplicable(a.KernelBefore[i], state) {
			conn.FlushSet(set)
			if err := addElementsChunked(conn, set, actionElements(state.Elements, now)); err != nil {
				return err
			}
			continue
		}
		add, remove := actionElementDelta(a.KernelBefore[i], state, now)
		// Each element list has a uint16 netlink attribute length. Bound
		// deletion messages too, while keeping all chunks in one transaction.
		for offset := 0; offset < len(remove); offset += 1000 {
			end := min(offset+1000, len(remove))
			if err := conn.SetDeleteElements(set, remove[offset:end]); err != nil {
				return err
			}
		}
		if err := addElementsChunked(conn, set, add); err != nil {
			return err
		}
	}
	return conn.Flush()
}

// deltaApplicable reports whether a set can be changed element by element.
// Interval sets carry paired start and end markers whose union changes shape
// when any member changes, so those are always rewritten whole.
func deltaApplicable(before, after ActionSet) bool {
	if !before.Exists || before.Name != after.Name {
		return false
	}
	for _, set := range []ActionSet{before, after} {
		for _, elem := range set.Elements {
			if elem.End {
				return false
			}
		}
	}
	return true
}

func actionElementKey(elem ActionElement) string {
	return fmt.Sprintf("%x/%t", elem.Key, elem.End)
}

// actionElementDelta returns the elements to add and to remove so the live set
// matches the intended effect. An element whose comment or expiry changed is
// removed and re-added in the same batch, which nftables applies atomically.
func actionElementDelta(before, after ActionSet, now time.Time) (add, remove []nftables.SetElement) {
	live := make(map[string]ActionElement, len(before.Elements))
	for _, elem := range before.Elements {
		live[actionElementKey(elem)] = elem
	}
	intended := make(map[string]ActionElement, len(after.Elements))
	var additions []ActionElement
	for _, entry := range after.Elements {
		key := actionElementKey(entry)
		prior, held := live[key]
		// Millisecond encoding must not make an unchanged absolute expiry
		// look like a replacement on every later mutation.
		unchanged := held && prior.Comment == entry.Comment && prior.ExpiresAt.Equal(entry.ExpiresAt)
		if !entry.ExpiresAt.IsZero() {
			if _, ok := blockTimeout(entry.ExpiresAt, now); !ok {
				// The kernel expires an unchanged element on its own. A delete
				// naming one it already dropped fails the whole transaction.
				if unchanged {
					intended[key] = entry
				}
				continue
			}
		}
		intended[key] = entry
		if unchanged {
			continue
		}
		if held {
			remove = append(remove, nftables.SetElement{Key: prior.Key, IntervalEnd: prior.End})
		}
		additions = append(additions, entry)
	}
	for _, elem := range before.Elements {
		if _, wanted := intended[actionElementKey(elem)]; wanted {
			continue
		}
		remove = append(remove, nftables.SetElement{Key: elem.Key, IntervalEnd: elem.End})
	}
	return actionElements(additions, now), remove
}
func actionElements(entries []ActionElement, now time.Time) []nftables.SetElement {
	var out []nftables.SetElement
	for _, entry := range entries {
		timeout := time.Duration(0)
		if !entry.ExpiresAt.IsZero() {
			var ok bool
			if timeout, ok = blockTimeout(entry.ExpiresAt, now); !ok {
				continue
			}
		}
		out = append(out, nftables.SetElement{Key: entry.Key, IntervalEnd: entry.End, Comment: entry.Comment, Timeout: timeout})
	}
	return out
}
func matchActionElements(expected []ActionElement, actual []nftables.SetElement, at time.Time) bool {
	remaining := make(map[string]ActionElement)
	for _, entry := range expected {
		if !entry.ExpiresAt.IsZero() && !entry.ExpiresAt.After(at) {
			continue
		}
		remaining[fmt.Sprintf("%x/%t", entry.Key, entry.End)] = entry
	}
	for _, elem := range actual {
		key := fmt.Sprintf("%x/%t", elem.Key, elem.IntervalEnd)
		want, ok := remaining[key]
		if !ok || want.Comment != elem.Comment {
			return false
		}
		if want.ExpiresAt.IsZero() {
			if elem.Timeout != 0 {
				return false
			}
		} else {
			if elem.Timeout <= 0 {
				return false
			}
			delta := at.Add(elem.Expires).Sub(want.ExpiresAt)
			if delta > 2*time.Second || delta < -2*time.Second {
				return false
			}
		}
		delete(remaining, key)
	}
	return len(remaining) == 0
}
func (k engineActionKernel) ObserveFirewallAction(a FirewallAction) (ActionObservation, error) {
	if err := k.ValidateEvidence(a); err != nil {
		return ActionObservation{}, err
	}
	var generation uint32
	if a.Request.Operation == "apply" {
		var genErr error
		generation, genErr = k.e.actionGeneration()
		if genErr != nil {
			return ActionObservation{}, genErr
		}
	}
	result := ActionObservation{Before: true, After: true}
	for i, before := range a.KernelBefore {
		after := a.KernelAfter[i]
		if before.Name != after.Name {
			return ActionObservation{}, errors.New("mismatched firewall kernel evidence")
		}
		conn, connErr := newLifecycleConn(k.e)
		if connErr != nil {
			return ActionObservation{}, connErr
		}
		started := time.Now()
		at := k.e.leaseNowLocked()
		actual, err := readActionSet(conn, before.Name)
		if err != nil {
			return ActionObservation{}, err
		}
		elems := actual.elements
		if actual.exists != before.Exists {
			result.Before = false
		}
		if actual.exists != after.Exists {
			result.After = false
		}
		if time.Since(started) > 2*time.Second {
			return ActionObservation{}, errors.New("firewall verification took too long")
		}
		result.Before = result.Before && matchActionElements(before.Elements, elems, at)
		result.After = result.After && matchActionElements(after.Elements, elems, at)
	}
	if len(a.Members) > 1 {
		at := k.e.leaseNowLocked()
		for _, m := range a.Members {
			for _, row := range a.After.Blocked {
				// A row can outlive the journal entry that reserved its ID.
				if row.ActionID != m.Request.ID || row.IP != m.Request.Target || !row.ExpiresAt.After(a.CreatedAt) {
					continue
				}
				if _, live := blockTimeout(row.ExpiresAt, at); !live {
					// Absence cannot distinguish a missed effect from an expired one.
					return ActionObservation{}, nil
				}
			}
		}
	}
	if a.Request.Operation == "apply" {
		rules, err := k.e.rulesetEvidenceMatches(a, generation)
		if err != nil {
			return ActionObservation{}, err
		}
		result.Before = result.Before && rules.Before
		result.After = result.After && rules.After
	}
	return result, nil
}

// BlockIPRequest carries durable request identity and source-specific admission
// policy through the existing automatic and manual safety gates.
func (e *Engine) BlockIPRequest(req ActionRequest, budget *ScanAdmission) (BlockOutcome, error) {
	canonical, err := canonicalFirewallIP(req.Target)
	if err != nil {
		recordBlockOutcome(req.Target, req.Reason, req.TTL, BlockOutcomeNoop, err, !req.Automatic, req.FindingID)
		return BlockOutcomeNoop, err
	}
	req.Target = canonical
	req.Operation = "block"
	req = normalizeActionRequest(req)
	e.mu.Lock()
	if found, replayErr := e.replayActionLocked(req); found || replayErr != nil {
		e.mu.Unlock()
		return BlockOutcomeNoop, replayErr
	}
	readyErr := e.lifecycleReadyLocked()
	e.mu.Unlock()
	if readyErr != nil {
		return BlockOutcomeNoop, readyErr
	}
	if req.Automatic {
		return e.blockIPOutcomeRequest(req, budget)
	}
	outcome, err := e.blockIPLockedRequest(req.Target, req.Reason, req.TTL, false, false, req, budget)
	if e.shouldLegacyOutcome(err) {
		recordBlockOutcome(req.Target, req.Reason, req.TTL, outcome, err, true, req.FindingID)
	}
	return outcome, err
}

func firewallAuditOperation(req ActionRequest) string {
	if req.Automatic {
		return "respond.block_ip"
	}
	return "operate.manual_firewall"
}
func (e *Engine) DurableActionsEnabled() bool { return e.lifecycleEnabled() }
func (e *Engine) FirewallScanBudget(window string) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.lifecycle == nil {
		return 0, errors.New("durable firewall budget unavailable")
	}
	return e.lifecycle.Store.ReadFirewallScanBudget(window)
}

type liveActionSet struct {
	exists   bool
	elements []nftables.SetElement
}

func readActionSet(conn *nftables.Conn, name string) (liveActionSet, error) {
	set, err := conn.GetSetByName(&nftables.Table{Name: "csm", Family: nftables.TableFamilyINet}, name)
	if err != nil {
		if isNftNotFound(err) {
			return liveActionSet{}, nil
		}
		return liveActionSet{}, err
	}
	elems, err := conn.GetSetElements(set)
	return liveActionSet{exists: true, elements: elems}, err
}
func (e *Engine) applyDurableLocked() error {
	state, revision, err := e.readCommittedStateLocked()
	if err != nil {
		return err
	}
	req := ActionRequest{ID: rand.Text(), Operation: "apply", Target: "csm", Actor: string(actionlog.DefaultActor()), Source: SourceSystem}
	plan := FirewallAction{Request: req, Before: state, After: state, Revision: revision, CreatedAt: time.Now()}
	if evidenceErr := e.prepareRulesetEvidence(&plan); evidenceErr != nil {
		return evidenceErr
	}
	plan.CreatedAt = e.expiryNow()
	desired := desiredActionSets(state, e.cfg.IPv6, plan.CreatedAt)
	conn, err := newLifecycleConn(e)
	if err != nil {
		return err
	}
	for _, name := range actionSetNames(true) {
		actual, readErr := readActionSet(conn, name)
		if readErr != nil {
			return readErr
		}
		before := ActionSet{Name: name, Exists: actual.exists}
		now := e.leaseNowLocked()
		for _, elem := range actual.elements {
			entry := ActionElement{Key: bytes.Clone(elem.Key), End: elem.IntervalEnd, Comment: elem.Comment}
			if elem.Timeout > 0 {
				entry.ExpiresAt = now.Add(elem.Expires)
			}
			before.Elements = append(before.Elements, entry)
		}
		elements, exists := desired[name]
		plan.KernelBefore = append(plan.KernelBefore, before)
		plan.KernelAfter = append(plan.KernelAfter, ActionSet{Name: name, Exists: exists, Elements: elements})
	}
	generation, genErr := e.actionGeneration()
	if genErr != nil {
		return genErr
	}
	if generation != plan.Ruleset.Generation {
		return fmt.Errorf("%w: ruleset changed during planning", ErrActionUnknown)
	}
	a, executeErr := e.lifecycle.Execute(plan, engineActionKernel{e})
	return durableActionOutcome(a, executeErr)
}

func requiredActionSets(a FirewallAction) []string {
	if a.Request.Operation == "apply" {
		return actionSetNames(true)
	}
	// A removal must prove the target set even when committed state already
	// omits it. Otherwise an untracked live element is reported as removed.
	blocked := a.Request.Operation == "unblock" || a.Request.Operation == "flush"
	allowed := a.Request.Operation == "remove_allow"
	subnets := a.Request.Operation == "unblock_subnet"
	var names []string
	if blocked || !reflect.DeepEqual(a.Before.Blocked, a.After.Blocked) {
		names = append(names, "blocked_ips", "blocked_ips6")
	}
	if allowed || !reflect.DeepEqual(a.Before.Allowed, a.After.Allowed) {
		names = append(names, "allowed_ips", "allowed_ips6")
	}
	if subnets || !reflect.DeepEqual(a.Before.BlockedNet, a.After.BlockedNet) {
		names = append(names, "blocked_nets", "blocked_nets6")
	}
	return names
}
func (k engineActionKernel) ValidateEvidence(a FirewallAction) error {
	names := requiredActionSets(a)
	if len(names) != len(a.KernelBefore) || len(names) != len(a.KernelAfter) {
		return errors.New("incomplete firewall kernel evidence")
	}
	expected := desiredActionSets(a.After, true, a.CreatedAt)
	for i, name := range names {
		before, after := a.KernelBefore[i], a.KernelAfter[i]
		if before.Name != name || after.Name != name {
			return errors.New("mismatched firewall kernel evidence")
		}
		if !strings.HasSuffix(name, "6") && !after.Exists {
			return errors.New("missing IPv4 firewall set")
		}
		for _, set := range []ActionSet{before, after} {
			if !set.Exists && len(set.Elements) != 0 {
				return errors.New("absent set has elements")
			}
			keys := make(map[string]bool)
			for _, elem := range set.Elements {
				size := 4
				if strings.HasSuffix(name, "6") {
					size = 16
				}
				key := fmt.Sprintf("%x/%t", elem.Key, elem.End)
				if len(elem.Key) != size || keys[key] {
					return errors.New("invalid or duplicate firewall element")
				}
				keys[key] = true
			}
		}
		if after.Exists && !sameActionElements(after.Elements, expected[name]) {
			return errors.New("kernel evidence differs from intended effect")
		}
	}
	return validateBatchMemberEvidence(a)
}

// validateBatchMemberEvidence requires every member of a batch to add its own
// element: before the batch the kernel held nothing for its address, and
// after it the element carries the fingerprint of that member's row. Retained
// rows from an older use of an ID are not evidence for the current member.
func validateBatchMemberEvidence(a FirewallAction) error {
	if len(a.Members) < 2 {
		return nil
	}
	targets := make(map[string]string, len(a.Members))
	for _, m := range a.Members {
		targets[m.Request.ID] = m.Request.Target
	}
	rows := make(map[string]BlockedEntry, len(a.Members))
	for _, row := range a.After.Blocked {
		if target, member := targets[row.ActionID]; member && row.IP == target && row.ExpiresAt.After(a.CreatedAt) {
			rows[row.ActionID] = row
		}
	}
	sets := make(map[string][2]ActionSet, len(a.KernelBefore))
	for i, before := range a.KernelBefore {
		sets[before.Name] = [2]ActionSet{before, a.KernelAfter[i]}
	}
	for _, m := range a.Members {
		row, ok := rows[m.Request.ID]
		if !ok {
			return errors.New("batch member has no row")
		}
		name, key, ok := blockedSetKey(row.IP, true)
		evidence, held := sets[name]
		if !ok || !held {
			return errors.New("batch member has no kernel evidence")
		}
		for _, elem := range evidence[0].Elements {
			if bytes.Equal(elem.Key, key) {
				return errors.New("batch member already held before the batch")
			}
		}
		added := false
		for _, elem := range evidence[1].Elements {
			added = added || bytes.Equal(elem.Key, key) && elem.Comment == stateFingerprint(row)
		}
		if !added {
			return errors.New("batch member element missing after the batch")
		}
	}
	return nil
}
func sameActionElements(a, b []ActionElement) bool {
	if len(a) != len(b) {
		return false
	}
	entries := make(map[string]ActionElement, len(a))
	for _, entry := range a {
		entries[fmt.Sprintf("%x/%t", entry.Key, entry.End)] = entry
	}
	for _, entry := range b {
		prior, ok := entries[fmt.Sprintf("%x/%t", entry.Key, entry.End)]
		if !ok || prior.Comment != entry.Comment || !prior.ExpiresAt.Equal(entry.ExpiresAt) {
			return false
		}
	}
	return true
}
func (k engineActionKernel) PrepareFirewallUndo(plan *FirewallAction) error {
	at := k.e.leaseNowLocked()
	plan.After = withoutExpiredRows(plan.After, at)
	return k.e.prepareActionKernelAt(plan, at)
}

// The caller holds e.mu. Durable paths deliver their versioned journal event.
func (e *Engine) legacyActionAuditLocked(action, target, reason, source string, ttl time.Duration) {
	if e.lifecycle == nil {
		AppendAudit(e.statePath, action, target, reason, source, ttl)
	}
}
func (e *Engine) legacyFileAuditLocked(action, target, reason, source string, ttl time.Duration) {
	if e.lifecycle == nil {
		appendAudit(e.statePath, action, target, reason, source, ttl)
	}
}

// Failure defers run after the engine lock is released. Cleanup loops already
// hold that lock and use their durable outcome instead.
func (e *Engine) legacyFirewallFailure(action, target, reason, source string, ttl time.Duration, err error) {
	if e.shouldLegacyOutcome(err) {
		recordFirewallFailure(action, target, reason, source, ttl, err)
	}
}

func normalizeActionRequest(req ActionRequest) ActionRequest {
	if req.Source == "" {
		req.Source = InferProvenance(req.Operation, req.Reason)
	}
	if req.Actor == "" {
		_, actor := firewallActionOp(req.Operation, req.Source)
		req.Actor = string(actor)
	}
	return req
}

// A retry observes the original plan and refreshes current committed state.
// Historical After must never overwrite cache state from a later action.
func (e *Engine) replayActionLocked(req ActionRequest) (bool, error) {
	if e.lifecycle == nil || req.ID == "" {
		return false, nil
	}
	previous, err := e.lifecycle.Store.ReadFirewallAction(req.ID)
	if errors.Is(err, ErrActionMissing) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !previous.IsRequest(req) {
		return true, ErrStateConflict
	}
	result, executeErr := e.lifecycle.Execute(previous, engineActionKernel{e})
	if executeErr != nil && result.Phase != "verified" {
		return true, durableActionOutcome(result, executeErr)
	}
	current, _, err := e.readCommittedStateLocked()
	if err == nil {
		e.installCommittedCache(current)
	}
	return true, errors.Join(durableActionOutcome(result, executeErr), err)
}

func (e *Engine) savePortPolicyLocked(state *FirewallState, req ActionRequest) error {
	if e.lifecycle != nil {
		return e.runDurableLocked(req, nil, *state)
	}
	return e.saveState(state)
}

// An admitted action owns its versioned outcome; rejected attempts retain the
// existing best-effort refusal record at their public operation boundary.
type durableAttemptError struct{ error }

func (err *durableAttemptError) Unwrap() error { return err.error }
func durableActionOutcome(a FirewallAction, err error) error {
	if err == nil {
		return nil
	}
	if a.Phase == "verified" {
		return &durableAttemptError{errors.Join(ErrActionAuditPending, err)}
	}
	if a.Request.ID != "" || errors.Is(err, ErrActionUnknown) || errors.Is(err, ErrStateCommitUncertain) {
		return &durableAttemptError{err}
	}
	return err
}
func (e *Engine) shouldLegacyOutcome(err error) bool {
	if !e.lifecycleEnabled() {
		return true
	}
	var admitted *durableAttemptError
	return err != nil && !errors.As(err, &admitted)
}

// Pin mutation plans to the snapshot they read. A later successful read must
// not silently attach an older After state to a newer committed revision.
func (e *Engine) readCommittedStateLocked() (FirewallState, uint64, error) {
	state, revision, err := e.lifecycle.Store.ReadFirewallState()
	e.stateReadErr = err
	if err == nil {
		e.stateRevision = revision
	}
	return state, revision, err
}
