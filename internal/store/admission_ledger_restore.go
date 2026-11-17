package store

import (
	"fmt"
	"os"
	"runtime/debug"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// CheckLedgerRestore returns ErrLedgerBehind when putting the database at
// archive, or the firewall state saved beside it, in place of the database
// at target would move a ledger that started live back: the archive's
// ledger never started live or its clock is behind. An older ledger would
// spend an hour's charges again and run the live start a second time from
// stale blocks. A target whose ledger never started live is never refused,
// so recovery onto a fresh host keeps working. A target this binary cannot
// read is not refused either: restoring over it is the repair. An archive
// ledger it cannot read counts as behind. Neither file needs a ledger.
func CheckLedgerRestore(archive, target string) error {
	if live, at, err := readLedgerPosition(target, true); err == nil && live {
		return checkArchiveLedger(archive, at)
	}
	return nil
}

func checkArchiveLedger(archive string, targetClock time.Time) error {
	live, clock, err := readLedgerPosition(archive, false)
	switch {
	case err != nil:
		return fmt.Errorf("%w: it cannot be read (%v); use --force to restore it anyway", ErrLedgerBehind, err)
	case !live:
		return fmt.Errorf("%w: it never started live; use --force to restore it anyway", ErrLedgerBehind)
	case clock.Before(targetClock):
		return fmt.Errorf("%w: its clock reads %s, this host's %s; use --force to restore it anyway",
			ErrLedgerBehind, clock.Format(time.RFC3339Nano), targetClock.Format(time.RFC3339Nano))
	}
	return nil
}

// readLedgerPosition reads, without a ledger handle, whether the database
// at path holds a ledger that started live and its admission clock. A
// missing file or one without a current ledger has not started.
func readLedgerPosition(path string, allowLeakedPages bool) (live bool, at time.Time, err error) {
	// bbolt reports a damaged page by panicking. A database that cannot be
	// read is an answer here, not a crash: restoring over it is the repair.
	defer func() {
		if r := recover(); r != nil {
			live, at, err = false, time.Time{}, fmt.Errorf("reading the ledger database: %v", r)
		}
	}()
	// Check the file type and page structure before opening bbolt. A pipe
	// blocks before the lock timeout and page cycles never finish.
	err = verifyStoppedDatabase(path, allowLeakedPages)
	if os.IsNotExist(err) {
		return false, time.Time{}, nil
	}
	if err != nil {
		return false, time.Time{}, err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		return false, time.Time{}, err
	}
	defer func() { _ = db.Close() }()
	// Truncated mapped pages raise memory faults rather than bbolt panics.
	// Limit fault recovery to this goroutine's read and restore its setting.
	defer debug.SetPanicOnFault(debug.SetPanicOnFault(true))
	var clock admission.Clock
	err = db.View(func(tx *bolt.Tx) error {
		if current, currentErr := currentLedger(tx); !current {
			return currentErr
		}
		if tx.Bucket([]byte(admissionQueueStateBucket)) == nil {
			return admission.ErrCorruptRecord
		}
		if _, featuresErr := loadFeatures(tx); featuresErr != nil {
			return featuresErr
		}
		var viewErr error
		if _, live, viewErr = loadLiveStart(tx); viewErr != nil {
			return viewErr
		}
		clock, viewErr = loadLedgerClock(tx.Bucket([]byte(admissionMetaBucket)))
		return viewErr
	})
	return live, clock.Now(), err
}
