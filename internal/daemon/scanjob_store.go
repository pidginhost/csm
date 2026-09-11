package daemon

import (
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

type scanJobStore interface {
	PutScanJob(store.ScanJobRecord) error
	GetScanJob(string) (store.ScanJobRecord, bool, error)
	ListScanJobs() ([]store.ScanJobRecord, error)
	AppendScanJobFindings(string, int, []alert.Finding) error
	ListScanJobFindings(string, int, int) ([]alert.Finding, int, error)
	PruneScanJobs(int, int) (int, error)
}

// Only worker operations advance the job clock. Status polling through the
// manager's store must not conceal stalled worker persistence.
type scanJobWorkStore struct {
	scanJobStore
	work *scanJobWork
}

func (req scanJobRequest) trackedStore(db scanJobStore) scanJobWorkStore {
	return scanJobWorkStore{scanJobStore: db, work: req.work}
}

func (db scanJobWorkStore) PutScanJob(rec store.ScanJobRecord) error {
	db.work.progressed()
	err := db.scanJobStore.PutScanJob(rec)
	if err != nil {
		db.work.fail()
	}
	db.work.progressed()
	return err
}

func (db scanJobWorkStore) GetScanJob(id string) (store.ScanJobRecord, bool, error) {
	db.work.progressed()
	rec, ok, err := db.scanJobStore.GetScanJob(id)
	if err != nil || !ok {
		db.work.fail()
	}
	db.work.progressed()
	return rec, ok, err
}

func (db scanJobWorkStore) AppendScanJobFindings(id string, seq int, findings []alert.Finding) error {
	db.work.progressed()
	err := db.scanJobStore.AppendScanJobFindings(id, seq, findings)
	if err != nil {
		db.work.fail()
	}
	db.work.progressed()
	return err
}

func (db scanJobWorkStore) PruneScanJobs(keep, maxFindings int) (int, error) {
	db.work.progressed()
	n, err := db.scanJobStore.PruneScanJobs(keep, maxFindings)
	if err != nil {
		db.work.fail()
	}
	db.work.progressed()
	return n, err
}
