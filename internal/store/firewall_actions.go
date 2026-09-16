package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
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
const firewallScanWindowLayout = "2006-01-02T15"

var _ firewall.ActionStore = (*DB)(nil)

// ErrFirewallActionMissing distinguishes an unknown request from a damaged
// journal. Neither is permission to execute an unrecorded mutation.
var ErrFirewallActionMissing = firewall.ErrActionMissing

func firewallActionPending(phase string) bool {
	return phase == "planned" || phase == "executing" || phase == "applied" || phase == "unknown"
}

func validateFirewallAdmission(a firewall.FirewallAction) error {
	if a.Request.ID == "" || len(a.Request.ID) > 128 || a.Request.Operation == "" || a.Request.Actor == "" || a.CreatedAt.IsZero() || a.Revision == 0 {
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
	if a.Budget != nil {
		if a.Request.Source != "scan" || a.Budget.Limit <= 0 {
			return errors.New("invalid firewall scan admission")
		}
		if _, err := time.Parse(firewallScanWindowLayout, a.Budget.Window); err != nil {
			return errors.New("invalid firewall scan window")
		}
	}
	return nil
}

// Journal envelopes detect valid-JSON corruption before recovery or typed undo
// interprets historical evidence. Checksums cover the exact stored payload.
type firewallJournalEnvelope struct {
	Version uint64          `json:"version"`
	Payload json.RawMessage `json:"payload"`
	SHA256  string          `json:"sha256"`
}

func encodeFirewallJournal(value any) ([]byte, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	return json.Marshal(firewallJournalEnvelope{Version: 1, Payload: payload, SHA256: fmt.Sprintf("%x", digest)})
}

func decodeFirewallJournal(raw []byte) ([]byte, error) {
	var envelope firewallJournalEnvelope
	if !validFirewallJSONText(raw) || json.Unmarshal(raw, &envelope) != nil || envelope.Version != 1 || !bytes.HasPrefix(bytes.TrimSpace(envelope.Payload), []byte("{")) {
		return nil, firewall.ErrStateCorrupt
	}
	digest := sha256.Sum256(envelope.Payload)
	if envelope.SHA256 != fmt.Sprintf("%x", digest) {
		return nil, firewall.ErrStateCorrupt
	}
	return envelope.Payload, nil
}

func decodeFirewallAction(raw []byte) (firewall.FirewallAction, error) {
	var a firewall.FirewallAction
	if len(raw) == 0 {
		return a, ErrFirewallActionMissing
	}
	var err error
	raw, err = decodeFirewallJournal(raw)
	if err != nil {
		return firewall.FirewallAction{}, err
	}
	var evidence struct {
		Before json.RawMessage `json:"before"`
		After  json.RawMessage `json:"after"`
	}
	if json.Unmarshal(raw, &evidence) != nil || !bytes.HasPrefix(bytes.TrimSpace(evidence.Before), []byte("{")) || !bytes.HasPrefix(bytes.TrimSpace(evidence.After), []byte("{")) {
		return firewall.FirewallAction{}, firewall.ErrStateCorrupt
	}
	if !validFirewallJSONText(raw) || json.Unmarshal(raw, &a) != nil || validateFirewallAdmission(a) != nil || a.UpdatedAt.IsZero() || a.AuditVersion == 0 || a.AuditAck > a.AuditVersion {
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
	raw, err := encodeFirewallJournal(a)
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
		for _, name := range []string{firewallActionsBucket, firewallAuditBucket, firewallBudgetBucket, firewallBudgetIndexBucket, firewallActionHistoryBucket} {
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
	if err != nil || !firewallActionPending(a.Phase) {
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
}

func readFirewallBudgetInventory(tx *bolt.Tx) (firewallBudgetInventory, error) {
	var inventory firewallBudgetInventory
	b := tx.Bucket([]byte(firewallBudgetIndexBucket))
	if b == nil {
		for _, name := range []string{firewallActionsBucket, firewallAuditBucket, firewallBudgetBucket, firewallActionIndexBucket, firewallActionHistoryBucket} {
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
	for i, window := range inventory.Windows {
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
			if existing.Request != in.Request {
				return fmt.Errorf("%w: request ID reused", firewall.ErrStateConflict)
			}
			result = existing
			return nil
		}
		if !errors.Is(readErr, ErrFirewallActionMissing) {
			return readErr
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
		if in.Budget != nil {
			inventory, inventoryErr := readFirewallBudgetInventory(tx)
			if inventoryErr != nil {
				return inventoryErr
			}
			count, budgetErr := readFirewallScanBudgetCount(tx, in.Budget.Window, inventory)
			if budgetErr != nil {
				return budgetErr
			}
			if count >= in.Budget.Limit {
				return firewall.ErrScanBudget
			}
			b, createErr := tx.CreateBucketIfNotExists([]byte(firewallBudgetBucket))
			if createErr != nil {
				return createErr
			}
			count++
			budgetRaw, encodeErr := encodeFirewallJournal(firewallScanBudget{Window: in.Budget.Window, Count: &count})
			if encodeErr != nil {
				return encodeErr
			}
			if putErr := b.Put([]byte(in.Budget.Window), budgetRaw); putErr != nil {
				return putErr
			}
			if position, known := slices.BinarySearch(inventory.Windows, in.Budget.Window); !known {
				inventory.Windows = slices.Insert(inventory.Windows, position, in.Budget.Window)
				if inventoryErr := writeFirewallBudgetInventory(tx, inventory); inventoryErr != nil {
					return inventoryErr
				}
				if _, pruneErr := pruneFirewallScanBudgetWindows(tx, inventory); pruneErr != nil {
					return pruneErr
				}
			}
		}
		in.Phase = "planned"
		in.UpdatedAt = in.CreatedAt
		in.Detail = ""
		in.AuditVersion, in.AuditAck = 1, 0
		if _, writeErr := writeFirewallAction(tx, in); writeErr != nil {
			return writeErr
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
	var err error
	raw, err = decodeFirewallJournal(raw)
	if err != nil {
		return event, firewall.FirewallAction{}, err
	}
	if !validFirewallJSONText(raw) || json.Unmarshal(raw, &event) != nil {
		return event, firewall.FirewallAction{}, firewall.ErrStateCorrupt
	}
	a, err := decodeFirewallAction(event.Action)
	if err != nil || !firewallAuditPhase(a.Phase) || !bytes.Equal(key, firewallAuditKey(a.Request.ID, a.AuditVersion)) {
		return event, firewall.FirewallAction{}, firewall.ErrStateCorrupt
	}
	return event, a, nil
}

func writeFirewallAuditEvent(tx *bolt.Tx, a firewall.FirewallAction) error {
	if !firewallAuditPhase(a.Phase) {
		return nil
	}
	action, err := encodeFirewallJournal(a)
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
			if decodeErr != nil || event.Acknowledged {
				return firewall.ErrStateCorrupt
			}
			current, readErr := readFirewallAction(tx, ref.ID)
			if readErr != nil || current.Request != a.Request || a.AuditVersion > current.AuditVersion {
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
		if firewallActionPending(a.Phase) {
			if index.PendingID != id {
				return firewall.ErrStateCorrupt
			}
			if err := validateFirewallActionBase(tx, a); err != nil {
				return err
			}
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
			if err := replaceFirewallSnapshot(tx, a.Revision, meta, rows, raw); err != nil {
				return err
			}
		}
		a.Phase, a.Detail, a.UpdatedAt = phase, detail, at
		if err := validateFirewallAdmission(a); err != nil {
			return err
		}
		a.AuditVersion++
		size, writeErr := writeFirewallAction(tx, a)
		if writeErr != nil {
			return writeErr
		}
		if err := writeFirewallAuditEvent(tx, a); err != nil {
			return err
		}
		if !firewallActionPending(a.Phase) {
			index.PendingID = ""
		}
		if firewallAuditPhase(a.Phase) {
			index.Audit = append(index.Audit, firewallAuditReference{ID: id, Version: a.AuditVersion})
		}
		if err := writeFirewallJournalIndex(tx, index); err != nil {
			return err
		}
		if !firewallActionPending(a.Phase) {
			if err := recordFirewallActionHistory(tx, a, size); err != nil {
				return err
			}
			if err := pruneFirewallActionHistory(tx, index); err != nil {
				return err
			}
		}
		result = a
		return nil
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
		if eventAction.Request != a.Request {
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
