package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pidginhost/csm/internal/firewall"
	bolt "go.etcd.io/bbolt"
)

const firewallActionsBucket = "fw:actions"
const firewallBudgetBucket = "fw:scan_budget"
const firewallAuditBucket = "fw:action_audit"
const firewallActionIndexBucket = "fw:action_index"
const firewallBudgetIndexBucket = "fw:budget_index"

// A batch of several members indexes each member ID to its batch, and the
// batch to its members so retention can release them without decoding the
// record. A one-member action needs neither: its only ID is its key.
const firewallMemberIndexBucket = "fw:member_index"
const firewallBatchMembersBucket = "fw:batch_members"
const firewallScanWindowLayout = "2006-01-02T15"

// An action with a manifest is stored as version 2. One without stays version
// 1, the only format earlier builds read, so its encoding never changes.
const firewallManifestVersion = 2

var _ firewall.ActionStore = (*DB)(nil)

// ErrFirewallActionMissing distinguishes an unknown request from a damaged
// journal. Neither is permission to execute an unrecorded mutation.
var ErrFirewallActionMissing = firewall.ErrActionMissing

func firewallActionPending(phase string) bool {
	return phase == "planned" || phase == "executing" || phase == "applied" || phase == "unknown"
}

// firewallActionOutstanding reports whether a still holds the pending
// interlock: a pending phase that recovery has not retired.
func firewallActionOutstanding(a firewall.FirewallAction) bool {
	return firewallActionPending(a.Phase) && !a.Retired
}

func validateFirewallAdmission(a firewall.FirewallAction) error {
	if a.Request.ID == "" || len(a.Request.ID) > 128 || a.Request.Operation == "" || a.Request.Actor == "" || a.CreatedAt.IsZero() || a.Revision == 0 || a.Retired && a.Phase != "unknown" {
		return errors.New("invalid firewall action admission")
	}
	for _, value := range []string{a.Request.ID, a.Request.Operation, a.Request.Target, a.Request.Reason, a.Request.Actor, a.Request.ActorDetail, a.Request.Source, a.Request.FindingID, a.Request.IncidentID, a.Request.UndoOf, a.Detail} {
		if !utf8.ValidString(value) {
			return errors.New("firewall action contains invalid Unicode")
		}
	}
	for _, at := range []time.Time{a.CreatedAt, a.UpdatedAt} {
		_, offset := at.Zone()
		if offset%60 != 0 {
			return errors.New("firewall action time cannot round-trip")
		}
	}
	if err := validateFirewallBudget(a.Request.Source, a.Budget); err != nil {
		return err
	}
	return validateFirewallManifest(a)
}

func validateFirewallBudget(source string, budget *firewall.ScanAdmission) error {
	if budget == nil {
		return nil
	}
	if source != "scan" || budget.Limit <= 0 {
		return errors.New("invalid firewall scan admission")
	}
	if _, err := time.Parse(firewallScanWindowLayout, budget.Window); err != nil {
		return errors.New("invalid firewall scan window")
	}
	return nil
}

var errInvalidFirewallManifest = errors.New("invalid firewall batch manifest")

// A manifest names each member once. One member repeats its header and
// charge. A larger batch holds automatic temporary blocks under a header that
// carries no target, link or charge of its own. Only a block removes rows.
func validateFirewallManifest(a firewall.FirewallAction) error {
	if a.Members == nil {
		return nil
	}
	if len(a.Members) == 0 || len(a.Members) > firewall.MaxActionMembers {
		return errInvalidFirewallManifest
	}
	header := a.Request
	if len(a.Members) == 1 {
		if a.Members[0].Request != header || !sameFirewallBudget(a.Members[0].Budget, a.Budget) {
			return errInvalidFirewallManifest
		}
	} else if header.Operation != "block" || !header.Automatic || header.Target != "" || header.Reason != "" || header.FindingID != "" || header.IncidentID != "" || header.UndoOf != "" || header.TTL != 0 || a.Budget != nil {
		return errInvalidFirewallManifest
	}
	ids, targets, victims := map[string]bool{header.ID: true}, map[string]bool{}, map[string]bool{}
	limits := map[string]int{}
	for i, m := range a.Members {
		r := m.Request
		if i > 0 || len(a.Members) > 1 {
			if r.ID == "" || len(r.ID) > 128 || ids[r.ID] || r.Operation != "block" || !r.Automatic || r.TTL <= 0 || !canonicalFirewallAddress(r.Target) || targets[r.Target] || r.UndoOf != "" || r.Actor != header.Actor || r.ActorDetail != header.ActorDetail || r.Source != header.Source {
				return errInvalidFirewallManifest
			}
			for _, value := range []string{r.ID, r.Target, r.Reason, r.FindingID, r.IncidentID} {
				if !utf8.ValidString(value) {
					return errInvalidFirewallManifest
				}
			}
		}
		// A one-member target may be any spelling; victims compare by address.
		ids[r.ID], targets[canonicalFirewallTarget(r.Target)] = true, true
		if err := validateFirewallBudget(r.Source, m.Budget); err != nil {
			return err
		}
		if m.Budget != nil {
			if limit, seen := limits[m.Budget.Window]; seen && limit != m.Budget.Limit {
				return errInvalidFirewallManifest
			}
			limits[m.Budget.Window] = m.Budget.Limit
		}
		if len(m.Victims) > 0 && r.Operation != "block" {
			return errInvalidFirewallManifest
		}
		for _, v := range m.Victims {
			if !canonicalFirewallAddress(v.IP) || v.ExpiresAt.IsZero() || victims[v.IP] || !validFirewallRowEncoding(v) {
				return errInvalidFirewallManifest
			}
			victims[v.IP] = true
		}
	}
	for ip := range victims {
		if targets[ip] {
			return errInvalidFirewallManifest
		}
	}
	if len(a.Members) > 1 {
		return validateFirewallBatchStates(a)
	}
	return validateFirewallVictims(a)
}

// canonicalFirewallAddress accepts one address in its only spelling, so no
// two members or victims can name the same address differently.
func canonicalFirewallAddress(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	return err == nil && addr.Zone() == "" && addr.Unmap().String() == ip
}

func sameFirewallBudget(a, b *firewall.ScanAdmission) bool {
	return a == b || a != nil && b != nil && *a == *b
}

// Journal envelopes detect valid-JSON corruption before recovery or typed undo
// interprets historical evidence. Checksums cover the exact stored payload.
type firewallJournalEnvelope struct {
	Version uint64          `json:"version"`
	Payload json.RawMessage `json:"payload"`
	SHA256  string          `json:"sha256"`
}

func encodeFirewallJournal(value any) ([]byte, error) {
	return encodeFirewallJournalVersion(value, 1)
}

func encodeFirewallJournalVersion(value any, version uint64) ([]byte, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	return json.Marshal(firewallJournalEnvelope{Version: version, Payload: payload, SHA256: fmt.Sprintf("%x", digest)})
}

func encodeFirewallActionRecord(a firewall.FirewallAction) ([]byte, error) {
	if a.Members == nil {
		return encodeFirewallJournal(a)
	}
	return encodeFirewallJournalVersion(a, firewallManifestVersion)
}

func decodeFirewallJournal(raw []byte) ([]byte, error) {
	payload, _, err := decodeFirewallJournalVersion(raw, 1)
	if err != nil {
		return nil, err
	}
	if !validFirewallJSONText(raw) {
		return nil, firewall.ErrStateCorrupt
	}
	return payload, nil
}

// Only the version belongs to every schema. Newer records may change any
// other field, including its type or text encoding.
func decodeFirewallVersion(raw []byte, newest uint64) (uint64, error) {
	var header struct {
		Version uint64 `json:"version"`
	}
	if json.Unmarshal(raw, &header) != nil || header.Version == 0 {
		return 0, firewall.ErrStateCorrupt
	}
	if header.Version > newest {
		return 0, firewall.ErrStateUnsupported
	}
	return header.Version, nil
}

// Text validation belongs to the reader, after any nested version checks:
// a supported audit envelope can contain an unsupported action envelope.
func decodeFirewallJournalVersion(raw []byte, newest uint64) ([]byte, uint64, error) {
	version, err := decodeFirewallVersion(raw, newest)
	if err != nil {
		return nil, 0, err
	}
	var envelope firewallJournalEnvelope
	if json.Unmarshal(raw, &envelope) != nil || !bytes.HasPrefix(bytes.TrimSpace(envelope.Payload), []byte("{")) {
		return nil, 0, firewall.ErrStateCorrupt
	}
	digest := sha256.Sum256(envelope.Payload)
	if envelope.SHA256 != fmt.Sprintf("%x", digest) {
		return nil, 0, firewall.ErrStateCorrupt
	}
	return envelope.Payload, version, nil
}

func decodeFirewallAction(raw []byte) (firewall.FirewallAction, error) {
	var a firewall.FirewallAction
	if len(raw) == 0 {
		return a, ErrFirewallActionMissing
	}
	payload, version, err := decodeFirewallJournalVersion(raw, firewallManifestVersion)
	if err != nil {
		return firewall.FirewallAction{}, err
	}
	if !validFirewallJSONText(raw) {
		return firewall.FirewallAction{}, firewall.ErrStateCorrupt
	}
	raw = payload
	var evidence struct {
		Before  json.RawMessage `json:"before"`
		After   json.RawMessage `json:"after"`
		Members json.RawMessage `json:"members"`
	}
	if json.Unmarshal(raw, &evidence) != nil || !bytes.HasPrefix(bytes.TrimSpace(evidence.Before), []byte("{")) || !bytes.HasPrefix(bytes.TrimSpace(evidence.After), []byte("{")) {
		return firewall.FirewallAction{}, firewall.ErrStateCorrupt
	}
	if json.Unmarshal(raw, &a) != nil || validateFirewallAdmission(a) != nil || a.UpdatedAt.IsZero() || a.AuditVersion == 0 || a.AuditAck > a.AuditVersion {
		return firewall.FirewallAction{}, firewall.ErrStateCorrupt
	}
	// Version 1 never carries a manifest and version 2 always does, so a
	// record is never read as a different batch than the one written.
	if (version == 1) != (evidence.Members == nil) || version == firewallManifestVersion && len(a.Members) == 0 {
		return firewall.FirewallAction{}, firewall.ErrStateCorrupt
	}
	if !firewallActionPending(a.Phase) && a.Phase != "verified" && a.Phase != "failed" {
		return firewall.FirewallAction{}, firewall.ErrStateCorrupt
	}
	if _, _, err := encodeFirewallSnapshot(a.Before); err != nil {
		return firewall.FirewallAction{}, fmt.Errorf("%w: action before state: %v", firewall.ErrStateCorrupt, err)
	}
	if _, _, err := encodeFirewallSnapshot(a.After); err != nil {
		return firewall.FirewallAction{}, fmt.Errorf("%w: action after state: %v", firewall.ErrStateCorrupt, err)
	}
	return a, nil
}

func readFirewallAction(tx *bolt.Tx, id string) (firewall.FirewallAction, error) {
	b := tx.Bucket([]byte(firewallActionsBucket))
	if b == nil {
		return firewall.FirewallAction{}, ErrFirewallActionMissing
	}
	a, err := decodeFirewallAction(b.Get([]byte(id)))
	if err == nil && a.Request.ID != id {
		return firewall.FirewallAction{}, firewall.ErrStateCorrupt
	}
	return a, err
}

func writeFirewallAction(tx *bolt.Tx, a firewall.FirewallAction) (int, error) {
	raw, err := encodeFirewallActionRecord(a)
	if err != nil {
		return 0, err
	}
	b, err := tx.CreateBucketIfNotExists([]byte(firewallActionsBucket))
	if err != nil {
		return 0, err
	}
	return len(raw), b.Put([]byte(a.Request.ID), raw)
}

// Only outstanding work is indexed. Retained history is validated when read for
// inspection or undo, so admission does not decode every historical snapshot.
type firewallAuditReference struct {
	ID      string `json:"id"`
	Version uint64 `json:"version"`
}

type firewallJournalIndex struct {
	Initialized bool                     `json:"initialized"`
	PendingID   string                   `json:"pending_id"`
	Audit       []firewallAuditReference `json:"audit"`
}

func readFirewallJournalIndex(tx *bolt.Tx) (firewallJournalIndex, error) {
	var index firewallJournalIndex
	b := tx.Bucket([]byte(firewallActionIndexBucket))
	if b == nil {
		for _, name := range []string{firewallActionsBucket, firewallAuditBucket, firewallBudgetBucket, firewallBudgetIndexBucket, firewallActionHistoryBucket, firewallMemberIndexBucket, firewallBatchMembersBucket} {
			if tx.Bucket([]byte(name)) != nil {
				return index, firewall.ErrStateCorrupt
			}
		}
		return index, nil
	}
	payload, err := decodeFirewallJournal(b.Get([]byte("index")))
	if err != nil {
		return index, err
	}
	var required struct {
		PendingID *string         `json:"pending_id"`
		Audit     json.RawMessage `json:"audit"`
	}
	if json.Unmarshal(payload, &required) != nil || required.PendingID == nil || !bytes.HasPrefix(bytes.TrimSpace(required.Audit), []byte("[")) {
		return firewallJournalIndex{}, firewall.ErrStateCorrupt
	}
	if json.Unmarshal(payload, &index) != nil || !index.Initialized || tx.Bucket([]byte(firewallActionsBucket)) == nil {
		return firewallJournalIndex{}, firewall.ErrStateCorrupt
	}
	seen := make(map[firewallAuditReference]bool, len(index.Audit))
	for _, ref := range index.Audit {
		if ref.ID == "" || ref.Version == 0 || seen[ref] {
			return firewallJournalIndex{}, firewall.ErrStateCorrupt
		}
		seen[ref] = true
	}
	return index, nil
}

func writeFirewallJournalIndex(tx *bolt.Tx, index firewallJournalIndex) error {
	index.Initialized = true
	if index.Audit == nil {
		index.Audit = []firewallAuditReference{}
	}
	raw, err := encodeFirewallJournal(index)
	if err != nil {
		return err
	}
	b, err := tx.CreateBucketIfNotExists([]byte(firewallActionIndexBucket))
	if err != nil {
		return err
	}
	return b.Put([]byte("index"), raw)
}

func indexedPendingFirewallAction(tx *bolt.Tx, index firewallJournalIndex) (firewall.FirewallAction, error) {
	if index.PendingID == "" {
		return firewall.FirewallAction{}, nil
	}
	a, err := readFirewallAction(tx, index.PendingID)
	if errors.Is(err, firewall.ErrStateUnsupported) {
		return firewall.FirewallAction{}, err
	}
	if err != nil || !firewallActionOutstanding(a) {
		return firewall.FirewallAction{}, firewall.ErrStateCorrupt
	}
	return a, nil
}

func refusePendingFirewallActions(tx *bolt.Tx) error {
	index, err := readFirewallJournalIndex(tx)
	if err != nil {
		return err
	}
	a, err := indexedPendingFirewallAction(tx, index)
	if err != nil {
		return err
	}
	if a.Request.ID != "" {
		return fmt.Errorf("%w: action %s requires recovery", firewall.ErrStateConflict, a.Request.ID)
	}
	return nil
}

type firewallScanBudget struct {
	Window string `json:"window"`
	Count  *int   `json:"count"`
}

// Keep the inventory separate from pending action metadata: recovery need not
// decode previously used budget windows. Missing charged counters are corruption.
type firewallBudgetInventory struct {
	Initialized bool     `json:"initialized"`
	Windows     []string `json:"windows"`
	// PrunedThrough prevents discarded charges from reopening after a clock
	// correction. Omitted in journals written before budget retention.
	PrunedThrough string `json:"pruned_through,omitempty"`
}

func readFirewallBudgetInventory(tx *bolt.Tx) (firewallBudgetInventory, error) {
	var inventory firewallBudgetInventory
	b := tx.Bucket([]byte(firewallBudgetIndexBucket))
	if b == nil {
		for _, name := range []string{firewallActionsBucket, firewallAuditBucket, firewallBudgetBucket, firewallActionIndexBucket, firewallActionHistoryBucket, firewallMemberIndexBucket, firewallBatchMembersBucket} {
			if tx.Bucket([]byte(name)) != nil {
				return inventory, firewall.ErrStateCorrupt
			}
		}
		return inventory, nil
	}
	payload, err := decodeFirewallJournal(b.Get([]byte("index")))
	if err != nil {
		return inventory, err
	}
	if json.Unmarshal(payload, &inventory) != nil || !inventory.Initialized || inventory.Windows == nil {
		return firewallBudgetInventory{}, firewall.ErrStateCorrupt
	}
	if inventory.PrunedThrough != "" {
		if _, err := time.Parse(firewallScanWindowLayout, inventory.PrunedThrough); err != nil {
			return firewallBudgetInventory{}, firewall.ErrStateCorrupt
		}
	}
	for i, window := range inventory.Windows {
		if window <= inventory.PrunedThrough {
			return firewallBudgetInventory{}, firewall.ErrStateCorrupt
		}
		if _, err := time.Parse(firewallScanWindowLayout, window); err != nil {
			return firewallBudgetInventory{}, firewall.ErrStateCorrupt
		}
		if i > 0 && inventory.Windows[i-1] >= window {
			return firewallBudgetInventory{}, firewall.ErrStateCorrupt
		}
	}
	return inventory, nil
}

func writeFirewallBudgetInventory(tx *bolt.Tx, inventory firewallBudgetInventory) error {
	inventory.Initialized = true
	if inventory.Windows == nil {
		inventory.Windows = []string{}
	}
	raw, err := encodeFirewallJournal(inventory)
	if err != nil {
		return err
	}
	b, err := tx.CreateBucketIfNotExists([]byte(firewallBudgetIndexBucket))
	if err != nil {
		return err
	}
	return b.Put([]byte("index"), raw)
}

func readFirewallScanBudget(tx *bolt.Tx, window string) (int, error) {
	inventory, err := readFirewallBudgetInventory(tx)
	if err != nil {
		return 0, err
	}
	return readFirewallScanBudgetCount(tx, window, inventory)
}

func readFirewallScanBudgetCount(tx *bolt.Tx, window string, inventory firewallBudgetInventory) (int, error) {
	_, known := slices.BinarySearch(inventory.Windows, window)
	b := tx.Bucket([]byte(firewallBudgetBucket))
	if b == nil && len(inventory.Windows) > 0 {
		return 0, firewall.ErrStateCorrupt
	}
	if b != nil && b.Bucket([]byte(window)) != nil {
		return 0, firewall.ErrStateCorrupt
	}
	if b == nil || b.Get([]byte(window)) == nil {
		if known {
			return 0, firewall.ErrStateCorrupt
		}
		return 0, nil
	}
	if !known {
		return 0, firewall.ErrStateCorrupt
	}
	payload, err := decodeFirewallJournal(b.Get([]byte(window)))
	if err != nil {
		return 0, err
	}
	var budget firewallScanBudget
	if json.Unmarshal(payload, &budget) != nil || budget.Window != window || budget.Count == nil || *budget.Count <= 0 {
		return 0, firewall.ErrStateCorrupt
	}
	if _, err := time.Parse(firewallScanWindowLayout, budget.Window); err != nil {
		return 0, firewall.ErrStateCorrupt
	}
	return *budget.Count, nil
}

// chargeFirewallScanBudget charges count units to one hourly window, or
// refuses the whole batch when they do not fit under its limit.
func chargeFirewallScanBudget(tx *bolt.Tx, window string, limit, count int) error {
	inventory, err := readFirewallBudgetInventory(tx)
	if err != nil {
		return err
	}
	if window <= inventory.PrunedThrough {
		return firewall.ErrScanBudget
	}
	charged, err := readFirewallScanBudgetCount(tx, window, inventory)
	if err != nil {
		return err
	}
	if count > limit-charged {
		return firewall.ErrScanBudget
	}
	b, err := tx.CreateBucketIfNotExists([]byte(firewallBudgetBucket))
	if err != nil {
		return err
	}
	charged += count
	raw, err := encodeFirewallJournal(firewallScanBudget{Window: window, Count: &charged})
	if err != nil {
		return err
	}
	if err := b.Put([]byte(window), raw); err != nil {
		return err
	}
	if position, known := slices.BinarySearch(inventory.Windows, window); !known {
		inventory.Windows = slices.Insert(inventory.Windows, position, window)
		if err := writeFirewallBudgetInventory(tx, inventory); err != nil {
			return err
		}
		if _, err := pruneFirewallScanBudgetWindows(tx, inventory); err != nil {
			return err
		}
	}
	return nil
}

type firewallScanBudgetCharge struct {
	window string
	limit  int
	count  int
}

// firewallBatchCharges counts the charged members per window, in window order.
func firewallBatchCharges(a firewall.FirewallAction) []firewallScanBudgetCharge {
	var charges []firewallScanBudgetCharge
	for _, m := range a.ActionMembers() {
		if m.Budget == nil {
			continue
		}
		i := slices.IndexFunc(charges, func(c firewallScanBudgetCharge) bool { return c.window == m.Budget.Window })
		if i < 0 {
			charges = append(charges, firewallScanBudgetCharge{window: m.Budget.Window, limit: m.Budget.Limit})
			i = len(charges) - 1
		}
		charges[i].count++
	}
	slices.SortFunc(charges, func(x, y firewallScanBudgetCharge) int { return strings.Compare(x.window, y.window) })
	return charges
}

type firewallMemberIndexEntry struct {
	Batch string `json:"batch"`
}

type firewallBatchMembers struct {
	Members []string `json:"members"`
}

// firewallBatchMemberIDs returns the member IDs a batch indexes: none for one
// member, whose ID is the batch's own.
func firewallBatchMemberIDs(a firewall.FirewallAction) []string {
	if len(a.Members) < 2 {
		return nil
	}
	ids := make([]string, len(a.Members))
	for i, m := range a.Members {
		ids[i] = m.Request.ID
	}
	return ids
}

// refuseReusedFirewallIDs keeps every ID in exactly one batch: no admitted
// batch may name the new header or a new member, in any role.
func refuseReusedFirewallIDs(tx *bolt.Tx, a firewall.FirewallAction) error {
	index := tx.Bucket([]byte(firewallMemberIndexBucket))
	actions := tx.Bucket([]byte(firewallActionsBucket))
	for i, id := range append([]string{a.Request.ID}, firewallBatchMemberIDs(a)...) {
		if index != nil && index.Bucket([]byte(id)) != nil || actions != nil && actions.Bucket([]byte(id)) != nil {
			return firewall.ErrStateCorrupt
		}
		if index != nil && index.Get([]byte(id)) != nil || i > 0 && actions != nil && actions.Get([]byte(id)) != nil {
			return fmt.Errorf("%w: member ID reused", firewall.ErrStateConflict)
		}
	}
	return nil
}

func indexFirewallBatchMembers(tx *bolt.Tx, a firewall.FirewallAction) error {
	ids := firewallBatchMemberIDs(a)
	if ids == nil {
		return nil
	}
	index, err := tx.CreateBucketIfNotExists([]byte(firewallMemberIndexBucket))
	if err != nil {
		return err
	}
	entry, err := encodeFirewallJournal(firewallMemberIndexEntry{Batch: a.Request.ID})
	if err != nil {
		return err
	}
	for _, id := range ids {
		if putErr := index.Put([]byte(id), entry); putErr != nil {
			return putErr
		}
	}
	batches, err := tx.CreateBucketIfNotExists([]byte(firewallBatchMembersBucket))
	if err != nil {
		return err
	}
	raw, err := encodeFirewallJournal(firewallBatchMembers{Members: ids})
	if err != nil {
		return err
	}
	return batches.Put([]byte(a.Request.ID), raw)
}

// releaseFirewallBatchMembers deletes a removed batch's member index. Every
// entry must still name that batch: anything else is damage, not permission
// to free an ID another batch holds.
func releaseFirewallBatchMembers(tx *bolt.Tx, id string) error {
	batches := tx.Bucket([]byte(firewallBatchMembersBucket))
	if batches != nil && batches.Bucket([]byte(id)) != nil {
		return firewall.ErrStateCorrupt
	}
	if batches == nil || batches.Get([]byte(id)) == nil {
		return nil
	}
	payload, err := decodeFirewallJournal(batches.Get([]byte(id)))
	if err != nil {
		return err
	}
	var list firewallBatchMembers
	if json.Unmarshal(payload, &list) != nil || len(list.Members) < 2 {
		return firewall.ErrStateCorrupt
	}
	index := tx.Bucket([]byte(firewallMemberIndexBucket))
	for _, member := range list.Members {
		if index == nil {
			return firewall.ErrStateCorrupt
		}
		entryRaw, err := decodeFirewallJournal(index.Get([]byte(member)))
		if errors.Is(err, firewall.ErrStateUnsupported) {
			return err
		}
		var entry firewallMemberIndexEntry
		if err != nil || json.Unmarshal(entryRaw, &entry) != nil || entry.Batch != id {
			return firewall.ErrStateCorrupt
		}
		if err := index.Delete([]byte(member)); err != nil {
			return err
		}
	}
	return batches.Delete([]byte(id))
}

func (db *DB) ReadFirewallScanBudget(window string) (int, error) {
	var count int
	err := db.bolt.View(func(tx *bolt.Tx) error {
		var err error
		count, err = readFirewallScanBudget(tx, window)
		return err
	})
	return count, err
}

// AdmitFirewallAction commits the recovery evidence and accepted scan charge
// together. The complete committed state stays at Before until verification.
func (db *DB) AdmitFirewallAction(in firewall.FirewallAction) (result firewall.FirewallAction, fresh bool, err error) {
	defer func() { recordFirewallWriteError(err) }()
	if validationErr := validateFirewallAdmission(in); validationErr != nil {
		return result, false, validationErr
	}
	if _, _, err = encodeFirewallSnapshot(in.Before); err != nil {
		return result, false, err
	}
	if _, _, err = encodeFirewallSnapshot(in.After); err != nil {
		return result, false, err
	}
	before, err := json.Marshal(in.Before)
	if err != nil {
		return result, false, err
	}
	err = db.updateFirewallSnapshot(1, func(tx *bolt.Tx) error {
		index, indexErr := readFirewallJournalIndex(tx)
		if indexErr != nil {
			return indexErr
		}
		pending, pendingErr := indexedPendingFirewallAction(tx, index)
		if pendingErr != nil {
			return pendingErr
		}
		existing, readErr := readFirewallAction(tx, in.Request.ID)
		if readErr == nil {
			if !existing.SameManifest(in) {
				return fmt.Errorf("%w: request ID reused", firewall.ErrStateConflict)
			}
			result = existing
			return nil
		}
		if !errors.Is(readErr, ErrFirewallActionMissing) {
			return readErr
		}
		if reuseErr := refuseReusedFirewallIDs(tx, in); reuseErr != nil {
			return reuseErr
		}
		if pending.Request.ID != "" {
			return fmt.Errorf("%w: action %s requires recovery", firewall.ErrStateConflict, pending.Request.ID)
		}
		meta, txErr := readFirewallSnapshotMeta(tx)
		if txErr != nil {
			return txErr
		}
		if meta.Revision != in.Revision {
			return firewall.ErrStateConflict
		}
		rows, txErr := readFirewallSnapshotRows(tx, meta)
		if txErr != nil {
			return txErr
		}
		state, txErr := decodeFirewallSnapshot(rows, meta)
		if txErr != nil {
			return txErr
		}
		current, txErr := json.Marshal(state)
		if txErr != nil {
			return txErr
		}
		if !bytes.Equal(current, before) {
			return fmt.Errorf("%w: action before state differs", firewall.ErrStateConflict)
		}
		if !index.Initialized {
			if inventoryErr := writeFirewallBudgetInventory(tx, firewallBudgetInventory{}); inventoryErr != nil {
				return inventoryErr
			}
		}
		for _, charge := range firewallBatchCharges(in) {
			if chargeErr := chargeFirewallScanBudget(tx, charge.window, charge.limit, charge.count); chargeErr != nil {
				return chargeErr
			}
		}
		in.Phase = "planned"
		in.UpdatedAt = in.CreatedAt
		in.Detail = ""
		in.AuditVersion, in.AuditAck = 1, 0
		if _, writeErr := writeFirewallAction(tx, in); writeErr != nil {
			return writeErr
		}
		if indexErr := indexFirewallBatchMembers(tx, in); indexErr != nil {
			return indexErr
		}
		index.PendingID = in.Request.ID
		if writeErr := writeFirewallJournalIndex(tx, index); writeErr != nil {
			return writeErr
		}
		// Decode to detach every slice from caller-owned input.
		result, txErr = readFirewallAction(tx, in.Request.ID)
		fresh = txErr == nil
		return txErr
	})
	if err != nil {
		return firewall.FirewallAction{}, false, err
	}
	return result, fresh, nil
}

func (db *DB) ReadFirewallAction(id string) (firewall.FirewallAction, error) {
	var a firewall.FirewallAction
	err := db.bolt.View(func(tx *bolt.Tx) error {
		var err error
		a, err = readFirewallAction(tx, id)
		return err
	})
	if err != nil {
		return firewall.FirewallAction{}, err
	}
	return a, nil
}

// ReadFirewallBatchMember returns the batch that indexes member id. An ID no
// batch indexes is missing; an entry naming a batch that does not list the
// member is damage.
func (db *DB) ReadFirewallBatchMember(id string) (firewall.FirewallAction, error) {
	var a firewall.FirewallAction
	err := db.bolt.View(func(tx *bolt.Tx) error {
		index := tx.Bucket([]byte(firewallMemberIndexBucket))
		if index != nil && index.Bucket([]byte(id)) != nil {
			return firewall.ErrStateCorrupt
		}
		if index == nil || index.Get([]byte(id)) == nil {
			return ErrFirewallActionMissing
		}
		payload, err := decodeFirewallJournal(index.Get([]byte(id)))
		if err != nil {
			return err
		}
		var entry firewallMemberIndexEntry
		if json.Unmarshal(payload, &entry) != nil {
			return firewall.ErrStateCorrupt
		}
		a, err = readFirewallAction(tx, entry.Batch)
		if errors.Is(err, ErrFirewallActionMissing) || err == nil && !slices.Contains(firewallBatchMemberIDs(a), id) {
			return firewall.ErrStateCorrupt
		}
		return err
	})
	if err != nil {
		return firewall.FirewallAction{}, err
	}
	return a, nil
}

func (db *DB) PendingFirewallActions() ([]firewall.FirewallAction, error) {
	var pending []firewall.FirewallAction
	err := db.bolt.View(func(tx *bolt.Tx) error {
		index, err := readFirewallJournalIndex(tx)
		if err != nil {
			return err
		}
		a, err := indexedPendingFirewallAction(tx, index)
		if err != nil {
			return err
		}
		if a.Request.ID != "" {
			pending = append(pending, a)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return pending, nil
}

func firewallAuditPhase(phase string) bool {
	return phase == "unknown" || phase == "verified" || phase == "failed"
}

// Each outcome event keeps its original payload. Acknowledgement changes only
// the envelope; retaining it permits exact, idempotent acknowledgements.
type firewallAuditEvent struct {
	Action       json.RawMessage `json:"action"`
	Acknowledged bool            `json:"acknowledged"`
}

func firewallAuditKey(id string, version uint64) []byte {
	return []byte(fmt.Sprintf("%s\x00%020d", id, version))
}

func decodeFirewallAuditEvent(key, raw []byte) (firewallAuditEvent, firewall.FirewallAction, error) {
	var event firewallAuditEvent
	payload, _, err := decodeFirewallJournalVersion(raw, 1)
	if err != nil {
		return event, firewall.FirewallAction{}, err
	}
	if json.Unmarshal(payload, &event) != nil {
		return event, firewall.FirewallAction{}, firewall.ErrStateCorrupt
	}
	a, err := decodeFirewallAction(event.Action)
	if errors.Is(err, firewall.ErrStateUnsupported) {
		return event, firewall.FirewallAction{}, err
	}
	if err != nil || !validFirewallJSONText(raw) || !firewallAuditPhase(a.Phase) || !bytes.Equal(key, firewallAuditKey(a.Request.ID, a.AuditVersion)) {
		return event, firewall.FirewallAction{}, firewall.ErrStateCorrupt
	}
	return event, a, nil
}

func writeFirewallAuditEvent(tx *bolt.Tx, a firewall.FirewallAction) error {
	if !firewallAuditPhase(a.Phase) {
		return nil
	}
	action, err := encodeFirewallActionRecord(a)
	if err != nil {
		return err
	}
	raw, err := encodeFirewallJournal(firewallAuditEvent{Action: action})
	if err != nil {
		return err
	}
	b, err := tx.CreateBucketIfNotExists([]byte(firewallAuditBucket))
	if err != nil {
		return err
	}
	key := firewallAuditKey(a.Request.ID, a.AuditVersion)
	if b.Get(key) != nil || b.Bucket(key) != nil {
		return firewall.ErrStateConflict
	}
	return b.Put(key, raw)
}

func (db *DB) FirewallAuditPending() ([]firewall.FirewallAction, error) {
	var pending []firewall.FirewallAction
	err := db.bolt.View(func(tx *bolt.Tx) error {
		index, err := readFirewallJournalIndex(tx)
		if err != nil {
			return err
		}
		b := tx.Bucket([]byte(firewallAuditBucket))
		for _, ref := range index.Audit {
			if b == nil {
				return firewall.ErrStateCorrupt
			}
			key := firewallAuditKey(ref.ID, ref.Version)
			event, a, decodeErr := decodeFirewallAuditEvent(key, b.Get(key))
			if errors.Is(decodeErr, firewall.ErrStateUnsupported) {
				return decodeErr
			}
			if decodeErr != nil || event.Acknowledged {
				return firewall.ErrStateCorrupt
			}
			current, readErr := readFirewallAction(tx, ref.ID)
			if errors.Is(readErr, firewall.ErrStateUnsupported) {
				return readErr
			}
			if readErr != nil || !current.SameManifest(a) || a.AuditVersion > current.AuditVersion {
				return firewall.ErrStateCorrupt
			}
			pending = append(pending, a)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return pending, nil
}

func validFirewallActionTransition(from, to string) bool {
	if !firewallActionPending(from) {
		return false
	}
	switch to {
	case "executing":
		return from == "planned"
	case "applied":
		return from == "executing"
	case "unknown", "verified", "failed":
		return true
	}
	return false
}

func validateFirewallActionBase(tx *bolt.Tx, a firewall.FirewallAction) error {
	meta, err := readFirewallSnapshotMeta(tx)
	if err != nil {
		return err
	}
	if meta.Revision != a.Revision {
		return firewall.ErrStateConflict
	}
	rows, err := readFirewallSnapshotRows(tx, meta)
	if err != nil {
		return err
	}
	state, err := decodeFirewallSnapshot(rows, meta)
	if err != nil {
		return err
	}
	current, err := json.Marshal(state)
	if err != nil {
		return err
	}
	before, err := json.Marshal(a.Before)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, before) {
		return fmt.Errorf("%w: action before evidence differs from committed state", firewall.ErrStateCorrupt)
	}
	return nil
}

func (db *DB) TransitionFirewallAction(id, phase, detail string, at time.Time) (result firewall.FirewallAction, resultErr error) {
	defer func() { recordFirewallWriteError(resultErr) }()
	resultErr = db.updateFirewallSnapshot(1, func(tx *bolt.Tx) error {
		index, indexErr := readFirewallJournalIndex(tx)
		if indexErr != nil {
			return indexErr
		}
		a, err := readFirewallAction(tx, id)
		if err != nil {
			return err
		}
		if firewallActionOutstanding(a) {
			if index.PendingID != id {
				return firewall.ErrStateCorrupt
			}
			if baseErr := validateFirewallActionBase(tx, a); baseErr != nil {
				return baseErr
			}
		}
		if a.Retired {
			return fmt.Errorf("%w: retired action cannot transition", firewall.ErrStateConflict)
		}
		if a.Phase == phase && a.Detail == detail {
			result = a
			return nil
		}
		if !validFirewallActionTransition(a.Phase, phase) || at.IsZero() || a.AuditVersion == math.MaxUint64 {
			return fmt.Errorf("%w: invalid action transition", firewall.ErrStateConflict)
		}
		if phase == "verified" || phase == "failed" {
			state := a.Before
			if phase == "verified" {
				state = a.After
			}
			if publishErr := publishFirewallState(tx, a, state); publishErr != nil {
				return publishErr
			}
		}
		a.Phase, a.Detail, a.UpdatedAt = phase, detail, at
		result, err = commitFirewallTransition(tx, index, a)
		return err
	})
	if resultErr != nil {
		return firewall.FirewallAction{}, resultErr
	}
	return result, nil
}

// publishFirewallState commits state as the revision after a's own.
func publishFirewallState(tx *bolt.Tx, a firewall.FirewallAction, state firewall.FirewallState) error {
	meta, rows, err := encodeFirewallSnapshot(state)
	if err != nil {
		return err
	}
	if a.Revision == math.MaxUint64 {
		return firewall.ErrStateConflict
	}
	meta.Revision = a.Revision + 1
	raw, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return replaceFirewallSnapshot(tx, a.Revision, meta, rows, raw)
}

// commitFirewallTransition writes a's next version and its audit event, and
// once a no longer holds the pending interlock frees it and indexes a as
// retained history.
func commitFirewallTransition(tx *bolt.Tx, index firewallJournalIndex, a firewall.FirewallAction) (firewall.FirewallAction, error) {
	if err := validateFirewallAdmission(a); err != nil {
		return firewall.FirewallAction{}, err
	}
	a.AuditVersion++
	size, err := writeFirewallAction(tx, a)
	if err != nil {
		return firewall.FirewallAction{}, err
	}
	if err := writeFirewallAuditEvent(tx, a); err != nil {
		return firewall.FirewallAction{}, err
	}
	settled := !firewallActionOutstanding(a)
	if settled {
		index.PendingID = ""
	}
	if firewallAuditPhase(a.Phase) {
		index.Audit = append(index.Audit, firewallAuditReference{ID: a.Request.ID, Version: a.AuditVersion})
	}
	if err := writeFirewallJournalIndex(tx, index); err != nil {
		return firewall.FirewallAction{}, err
	}
	if settled {
		if err := recordFirewallActionHistory(tx, a, size); err != nil {
			return firewall.FirewallAction{}, err
		}
		if err := pruneFirewallActionHistory(tx, index); err != nil {
			return firewall.FirewallAction{}, err
		}
	}
	return a, nil
}

// RetireFirewallAction retires the uncertainty of an unknown block action
// once nothing it may have applied can remain (spec 5.4, design D7). The
// caller has proved that the kernel holds the retired state at at; the store
// checks that every effect has expired by then and that the unknown
// outcome's audit was delivered, so the event follows the outcome. In one
// transaction it commits the rows Before and After agree on as the next
// revision, frees the pending interlock and records the event. The outcome
// stays unknown and its charges stay spent. On an action already retired
// it changes nothing.
func (db *DB) RetireFirewallAction(id string, at time.Time) (result firewall.FirewallAction, resultErr error) {
	defer func() { recordFirewallWriteError(resultErr) }()
	resultErr = db.updateFirewallSnapshot(1, func(tx *bolt.Tx) error {
		index, err := readFirewallJournalIndex(tx)
		if err != nil {
			return err
		}
		a, err := readFirewallAction(tx, id)
		if err != nil {
			return err
		}
		if a.Retired {
			result = a
			return nil
		}
		if a.Phase != "unknown" {
			return fmt.Errorf("%w: action %s is not an unknown outcome", firewall.ErrStateConflict, id)
		}
		if index.PendingID != id {
			return firewall.ErrStateCorrupt
		}
		if baseErr := validateFirewallActionBase(tx, a); baseErr != nil {
			return baseErr
		}
		if slices.ContainsFunc(index.Audit, func(ref firewallAuditReference) bool { return ref.ID == id }) {
			return fmt.Errorf("%w: action %s outcome audit pending", firewall.ErrStateConflict, id)
		}
		if a.AuditAck != a.AuditVersion {
			return fmt.Errorf("%w: action %s outcome audit acknowledgement missing", firewall.ErrStateCorrupt, id)
		}
		state, ok := firewall.RetiredActionState(a, at)
		if !ok || a.AuditVersion == math.MaxUint64 {
			return fmt.Errorf("%w: action %s has an effect that can still be live", firewall.ErrStateConflict, id)
		}
		if publishErr := publishFirewallState(tx, a, state); publishErr != nil {
			return publishErr
		}
		a.Retired, a.UpdatedAt = true, at
		result, err = commitFirewallTransition(tx, index, a)
		return err
	})
	if resultErr != nil {
		return firewall.FirewallAction{}, resultErr
	}
	return result, nil
}

func (db *DB) AcknowledgeFirewallAudit(id string, version uint64) (err error) {
	defer func() { recordFirewallWriteError(err) }()
	return db.updateFirewallSnapshot(1, func(tx *bolt.Tx) error {
		index, indexErr := readFirewallJournalIndex(tx)
		if indexErr != nil {
			return indexErr
		}
		position := -1
		for i, ref := range index.Audit {
			if ref.ID == id && ref.Version == version {
				position = i
				break
			}
		}
		a, err := readFirewallAction(tx, id)
		if err != nil {
			return err
		}
		if version == 0 || version > a.AuditVersion {
			return firewall.ErrStateConflict
		}
		b := tx.Bucket([]byte(firewallAuditBucket))
		key := firewallAuditKey(id, version)
		if b == nil || b.Get(key) == nil {
			if position >= 0 {
				return firewall.ErrStateCorrupt
			}
			return firewall.ErrStateConflict
		}
		event, eventAction, err := decodeFirewallAuditEvent(key, b.Get(key))
		if err != nil {
			return err
		}
		if !eventAction.SameManifest(a) {
			return firewall.ErrStateCorrupt
		}
		if event.Acknowledged {
			if position >= 0 {
				return firewall.ErrStateCorrupt
			}
			return nil
		}
		if position < 0 {
			return firewall.ErrStateCorrupt
		}
		event.Acknowledged = true
		raw, err := encodeFirewallJournal(event)
		if err != nil {
			return err
		}
		if err := b.Put(key, raw); err != nil {
			return err
		}
		a.AuditAck = max(a.AuditAck, version)
		size, writeErr := writeFirewallAction(tx, a)
		if writeErr != nil {
			return writeErr
		}
		if err := updateFirewallActionHistorySize(tx, a, size); err != nil {
			return err
		}
		index.Audit = append(index.Audit[:position], index.Audit[position+1:]...)
		if err := writeFirewallJournalIndex(tx, index); err != nil {
			return err
		}
		return pruneFirewallActionHistory(tx, index)
	})
}
