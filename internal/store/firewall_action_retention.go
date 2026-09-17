package store

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
	bolt "go.etcd.io/bbolt"
)

// Terminal actions are indexed by outcome time so retention reads an ordered
// list without decoding the evidence each record carries.
const firewallActionHistoryBucket = "fw:action_history"

type firewallActionRetentionCaps struct {
	// Actions and Bytes bound the retained outcome history. Bytes matters
	// because one record keeps two complete states plus kernel evidence, so a
	// host with a large blocked set writes far more per action than a small one.
	Actions int
	Bytes   uint64
	// BudgetWindows bounds the hourly scan counters. Only the current window is
	// ever read, and the inventory is validated on every admission.
	BudgetWindows int
}

// Retention sweeps are opt-in, so on a default install these caps are the only
// bound on journal growth. They apply on the write path, not on a timer.
var firewallActionRetention = firewallActionRetentionCaps{Actions: 1000, Bytes: 64 << 20, BudgetWindows: 48}

func firewallActionHistoryKey(at time.Time, id string) []byte {
	nanoseconds := at.UnixNano()
	if nanoseconds < 0 {
		nanoseconds = 0
	}
	return []byte(fmt.Sprintf("%020d\x00%s", nanoseconds, id))
}

func firewallActionHistoryID(key []byte) (string, bool) {
	separator := bytes.IndexByte(key, 0)
	if separator < 0 || separator+1 >= len(key) {
		return "", false
	}
	return string(key[separator+1:]), true
}

type firewallActionHistoryEntry struct {
	key  []byte
	id   string
	size uint64
}

// readFirewallActionHistory returns retained outcomes oldest first. A history
// key without its action record is corruption: both are written in one
// transaction, so recovery must not silently accept a half-deleted record.
func readFirewallActionHistory(tx *bolt.Tx) ([]firewallActionHistoryEntry, uint64, error) {
	b := tx.Bucket([]byte(firewallActionHistoryBucket))
	if b == nil {
		return nil, 0, nil
	}
	actions := tx.Bucket([]byte(firewallActionsBucket))
	var entries []firewallActionHistoryEntry
	var total uint64
	cursor := b.Cursor()
	for key, raw := cursor.First(); key != nil; key, raw = cursor.Next() {
		id, ok := firewallActionHistoryID(key)
		if !ok || len(raw) != 8 {
			return nil, 0, fmt.Errorf("%w: firewall action history entry", firewall.ErrStateCorrupt)
		}
		if actions == nil || actions.Get([]byte(id)) == nil {
			return nil, 0, fmt.Errorf("%w: firewall action history without record", firewall.ErrStateCorrupt)
		}
		// The index stores the action row size. Audit rows are counted live
		// so existing indexes also include every retained evidence copy.
		size := binary.BigEndian.Uint64(raw) + firewallActionAuditSize(tx, id)
		total += size
		entries = append(entries, firewallActionHistoryEntry{key: bytes.Clone(key), id: id, size: size})
	}
	return entries, total, nil
}

// Older journals predate the outcome index. Build it atomically before the
// first retention operation, including undelivered outcomes for later pruning.
func initializeFirewallActionHistory(tx *bolt.Tx) error {
	if tx.Bucket([]byte(firewallActionHistoryBucket)) != nil {
		return nil
	}
	actions := tx.Bucket([]byte(firewallActionsBucket))
	if actions == nil {
		return nil
	}
	if _, err := tx.CreateBucketIfNotExists([]byte(firewallActionHistoryBucket)); err != nil {
		return err
	}
	return actions.ForEach(func(key, raw []byte) error {
		a, err := readFirewallAction(tx, string(key))
		if err != nil {
			return err
		}
		if firewallActionPending(a.Phase) {
			return nil
		}
		return recordFirewallActionHistory(tx, a, len(raw))
	})
}

// Audit keys have a fixed-width version suffix. A prefix alone also matches
// other valid request IDs containing NUL, so match the complete key length.
func firewallActionAuditSize(tx *bolt.Tx, id string) uint64 {
	var size uint64
	if b := tx.Bucket([]byte(firewallAuditBucket)); b != nil {
		prefix := append([]byte(id), 0)
		cursor := b.Cursor()
		for key, raw := cursor.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix); key, raw = cursor.Next() {
			if len(key) == len(prefix)+20 {
				size += uint64(len(raw))
			}
		}
	}
	return size
}

func recordFirewallActionHistory(tx *bolt.Tx, a firewall.FirewallAction, size int) error {
	if err := initializeFirewallActionHistory(tx); err != nil {
		return err
	}
	b := tx.Bucket([]byte(firewallActionHistoryBucket))
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(size)) // #nosec G115 -- a stored record length is never negative.
	return b.Put(firewallActionHistoryKey(a.UpdatedAt, a.Request.ID), encoded[:])
}

// updateFirewallActionHistorySize keeps byte accounting honest after an
// acknowledgement rewrites a retained record.
func updateFirewallActionHistorySize(tx *bolt.Tx, a firewall.FirewallAction, size int) error {
	if err := initializeFirewallActionHistory(tx); err != nil {
		return err
	}
	b := tx.Bucket([]byte(firewallActionHistoryBucket))
	if b == nil {
		return nil
	}
	key := firewallActionHistoryKey(a.UpdatedAt, a.Request.ID)
	if b.Get(key) == nil {
		return nil
	}
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(size)) // #nosec G115 -- a stored record length is never negative.
	return b.Put(key, encoded[:])
}

func undeliveredFirewallAuditIDs(index firewallJournalIndex) map[string]bool {
	undelivered := make(map[string]bool, len(index.Audit))
	for _, ref := range index.Audit {
		undelivered[ref.ID] = true
	}
	return undelivered
}

// deleteFirewallAction removes one retained outcome with every event that
// refers to it. Undelivered outcomes are never passed here.
func deleteFirewallAction(tx *bolt.Tx, entry firewallActionHistoryEntry) error {
	if b := tx.Bucket([]byte(firewallAuditBucket)); b != nil {
		prefix := append([]byte(entry.id), 0)
		// Collect first: acknowledgement rewrites an audit leaf in this
		// transaction, and a bbolt cursor that deletes and then steps with
		// Next skips keys in a bucket already written by the transaction.
		var keys [][]byte
		cursor := b.Cursor()
		for key, _ := cursor.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix); key, _ = cursor.Next() {
			if len(key) == len(prefix)+20 {
				keys = append(keys, append([]byte(nil), key...))
			}
		}
		for _, key := range keys {
			if err := b.Delete(key); err != nil {
				return err
			}
		}
	}
	if b := tx.Bucket([]byte(firewallActionsBucket)); b != nil {
		if err := b.Delete([]byte(entry.id)); err != nil {
			return err
		}
	}
	return tx.Bucket([]byte(firewallActionHistoryBucket)).Delete(entry.key)
}

// pruneFirewallActionHistory enforces the retained-outcome caps inside the
// transaction that recorded the newest outcome. The newest record and any
// record with undelivered audit are kept whatever the caps say.
func pruneFirewallActionHistory(tx *bolt.Tx, index firewallJournalIndex) error {
	if err := initializeFirewallActionHistory(tx); err != nil {
		return err
	}
	entries, total, err := readFirewallActionHistory(tx)
	if err != nil {
		return err
	}
	undelivered := undeliveredFirewallAuditIDs(index)
	count := len(entries)
	for _, entry := range entries[:max(len(entries)-1, 0)] {
		if count <= firewallActionRetention.Actions && total <= firewallActionRetention.Bytes {
			return nil
		}
		if undelivered[entry.id] {
			continue
		}
		if err := deleteFirewallAction(tx, entry); err != nil {
			return err
		}
		count--
		total -= entry.size
	}
	return nil
}

// SweepFirewallActionsOlderThan deletes proven outcomes whose audit has been
// delivered and whose result is older than cutoff. Pending actions and
// undelivered outcomes are retained regardless of age: recovery still needs
// them. Deleting an outcome ends the undo window for that action.
func (db *DB) SweepFirewallActionsOlderThan(cutoff time.Time) (int, error) {
	var deleted int
	err := boltUpdate(db.bolt, func(tx *bolt.Tx) error {
		deleted = 0
		index, err := readFirewallJournalIndex(tx)
		if err != nil {
			return err
		}
		if initErr := initializeFirewallActionHistory(tx); initErr != nil {
			return initErr
		}
		entries, _, err := readFirewallActionHistory(tx)
		if err != nil {
			return err
		}
		undelivered := undeliveredFirewallAuditIDs(index)
		boundary := firewallActionHistoryKey(cutoff, "")
		for _, entry := range entries {
			if bytes.Compare(entry.key, boundary) >= 0 {
				break
			}
			if undelivered[entry.id] {
				continue
			}
			if err := deleteFirewallAction(tx, entry); err != nil {
				return err
			}
			deleted++
		}
		return sweepFirewallScanBudget(tx, cutoff)
	})
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

// sweepFirewallScanBudget drops hourly counters the admission path can no
// longer charge. The inventory and its rows are updated together so a missing
// counter keeps meaning corruption.
func sweepFirewallScanBudget(tx *bolt.Tx, cutoff time.Time) error {
	inventory, err := readFirewallBudgetInventory(tx)
	if err != nil {
		return err
	}
	boundary := cutoff.UTC().Format(firewallScanWindowLayout)
	keep := inventory.Windows[:0:0]
	for _, window := range inventory.Windows {
		if window >= boundary {
			keep = append(keep, window)
			continue
		}
		if err := deleteFirewallScanBudgetWindow(tx, window); err != nil {
			return err
		}
		inventory.PrunedThrough = max(inventory.PrunedThrough, window)
	}
	if len(keep) == len(inventory.Windows) {
		return nil
	}
	inventory.Windows = keep
	return writeFirewallBudgetInventory(tx, inventory)
}

func deleteFirewallScanBudgetWindow(tx *bolt.Tx, window string) error {
	b := tx.Bucket([]byte(firewallBudgetBucket))
	if b == nil {
		return nil
	}
	return b.Delete([]byte(window))
}

// pruneFirewallScanBudgetWindows keeps the newest windows only. The current
// window may move backwards after a clock correction. Keep a durable boundary
// so admission refuses discarded windows instead of resetting their charges.
func pruneFirewallScanBudgetWindows(tx *bolt.Tx, inventory firewallBudgetInventory) (firewallBudgetInventory, error) {
	if len(inventory.Windows) <= firewallActionRetention.BudgetWindows {
		return inventory, nil
	}
	excess := len(inventory.Windows) - firewallActionRetention.BudgetWindows
	for _, window := range inventory.Windows[:excess] {
		if err := deleteFirewallScanBudgetWindow(tx, window); err != nil {
			return inventory, err
		}
	}
	inventory.PrunedThrough = max(inventory.PrunedThrough, inventory.Windows[excess-1])
	inventory.Windows = append(inventory.Windows[:0:0], inventory.Windows[excess:]...)
	return inventory, writeFirewallBudgetInventory(tx, inventory)
}
