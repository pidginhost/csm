package store

import (
	"errors"
	"fmt"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/metrics"
	bolt "go.etcd.io/bbolt"
)

// These collectors have no labels: paths, addresses and caller identities never
// allocate time series. They cover only the new firewall snapshot contract.
var (
	firewallWriteWait        = metrics.NewHistogram("csm_storage_firewall_write_wait_seconds", "Firewall writer lock wait.", []float64{.001, .01, .1, 1, 10})
	firewallWriteTransaction = metrics.NewHistogram("csm_storage_firewall_write_transaction_seconds", "Firewall write transaction through commit or rollback, excluding writer wait.", []float64{.001, .01, .1, 1, 10})
	firewallReadDuration     = metrics.NewHistogram("csm_storage_firewall_read_seconds", "Firewall snapshot read including copying and decoding.", []float64{.001, .01, .1, 1, 10})
	firewallBatchRows        = metrics.NewHistogram("csm_storage_firewall_batch_rows", "Rows in attempted firewall snapshot transactions.", []float64{0, 100, 1000, 10000, 100000})
	firewallPendingWrites    = metrics.NewGauge("csm_storage_firewall_pending_writes", "Firewall writes waiting or executing.")
	firewallWriteFailures    = metrics.NewCounter("csm_storage_firewall_write_failures_total", "Firewall replacements returning errors, including admission refusals.")
	firewallReadFailures     = metrics.NewCounter("csm_storage_firewall_read_failures_total", "Firewall reads returning errors.")
	firewallCommitFailures   = metrics.NewCounter("csm_storage_firewall_commit_failures_total", "Firewall transactions accepted by the callback without a confirmed commit.")
	firewallConflicts        = metrics.NewCounter("csm_storage_firewall_conflicts_total", "Firewall replacements refused due to revision conflicts.")
)

func init() {
	metrics.MustRegister("csm_storage_firewall_write_wait_seconds", firewallWriteWait)
	metrics.MustRegister("csm_storage_firewall_write_transaction_seconds", firewallWriteTransaction)
	metrics.MustRegister("csm_storage_firewall_read_seconds", firewallReadDuration)
	metrics.MustRegister("csm_storage_firewall_batch_rows", firewallBatchRows)
	metrics.MustRegister("csm_storage_firewall_pending_writes", firewallPendingWrites)
	metrics.MustRegister("csm_storage_firewall_write_failures_total", firewallWriteFailures)
	metrics.MustRegister("csm_storage_firewall_read_failures_total", firewallReadFailures)
	metrics.MustRegister("csm_storage_firewall_commit_failures_total", firewallCommitFailures)
	metrics.MustRegister("csm_storage_firewall_conflicts_total", firewallConflicts)
}

func recordFirewallWriteError(err error) {
	if err != nil {
		firewallWriteFailures.Inc()
	}
	if errors.Is(err, firewall.ErrStateConflict) {
		firewallConflicts.Inc()
	}
}

func (db *DB) updateFirewallSnapshot(rowCount int, fn func(*bolt.Tx) error) error {
	firewallBatchRows.Observe(float64(rowCount))
	firewallPendingWrites.Inc()
	defer firewallPendingWrites.Dec()
	waiting := time.Now()
	var acquired time.Time
	accepted := false
	err := boltUpdate(db.bolt, func(tx *bolt.Tx) error {
		acquired = time.Now()
		firewallWriteWait.Observe(acquired.Sub(waiting).Seconds())
		callbackErr := fn(tx)
		accepted = callbackErr == nil
		return callbackErr
	})
	if acquired.IsZero() {
		// Begin failed: elapsed time belongs to acquisition, not a transaction.
		firewallWriteWait.Observe(time.Since(waiting).Seconds())
	} else {
		firewallWriteTransaction.Observe(time.Since(acquired).Seconds())
	}
	if err != nil && accepted {
		firewallCommitFailures.Inc()
		// bbolt can return a sync error after publishing its new metadata.
		// An accepted callback plus an error is not proof of rollback.
		return fmt.Errorf("%w: %w", firewall.ErrStateCommitUncertain, err)
	}
	return err
}
