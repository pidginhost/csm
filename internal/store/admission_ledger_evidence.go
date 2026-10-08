package store

import (
	"slices"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// loadStoredEvidence loads a published record as it was stored, without
// judging it against current policy.
func loadStoredEvidence(tx *bolt.Tx, id admission.EvidenceID) (admission.Evidence, error) {
	if _, err := admission.ParseEvidenceID(string(id)); err != nil {
		return admission.Evidence{}, err
	}
	raw := tx.Bucket([]byte(admissionEvidenceBucket)).Get([]byte(id))
	if raw == nil {
		return admission.Evidence{}, admission.ErrEvidenceUnpublished
	}
	e, err := admission.UnmarshalEvidence(raw)
	if err != nil {
		return admission.Evidence{}, corruptRecord(err)
	}
	if e.ID() != id {
		return admission.Evidence{}, admission.ErrCorruptRecord
	}
	return e, nil
}

func loadEvidence(tx *bolt.Tx, reg *admission.Registry, id admission.EvidenceID) (admission.Evidence, error) {
	e, err := loadStoredEvidence(tx, id)
	if err != nil {
		return e, err
	}
	// Revalidate on every use: a policy change applies to evidence minted
	// before it.
	if err := reg.Validate(e); err != nil {
		return admission.Evidence{}, err
	}
	return e, nil
}

// PublishEvidence stores an immutable record. The same record again changes
// nothing; a different record under the same ID is refused and the stored
// original is kept.
func (l *AdmissionLedger) PublishEvidence(e admission.Evidence) (bool, error) {
	if err := l.reg.Validate(e); err != nil {
		return false, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	published := false
	err := l.update("publish", func(tx *bolt.Tx) error {
		q, txErr := l.openQueue(tx, l.now)
		if txErr != nil {
			return txErr
		}
		if published, txErr = publishTx(q, l.reg, e); txErr != nil {
			return txErr
		}
		return q.flush()
	})
	if err != nil {
		return false, err
	}
	return published, nil
}

// publishTx stores e unless the same record is already there. A new record
// takes a loose position until a candidate names it.
func publishTx(q *queueTx, reg *admission.Registry, e admission.Evidence) (bool, error) {
	if err := reg.Validate(e); err != nil {
		return false, err
	}
	data, err := e.MarshalBinary()
	if err != nil {
		return false, err
	}
	id := []byte(e.ID())
	b := q.tx.Bucket([]byte(admissionEvidenceBucket))
	if raw := b.Get(id); raw != nil {
		old, decodeErr := admission.UnmarshalEvidence(raw)
		if decodeErr != nil {
			return false, corruptRecord(decodeErr)
		}
		if old.ID() != e.ID() {
			return false, admission.ErrCorruptRecord
		}
		if _, err = loadRefs(q.tx, e.ID()); err != nil {
			return false, err
		}
		if !old.Equal(e) {
			return false, old.Conflict(e)
		}
		return false, nil
	}
	// A surviving reference or report belongs to missing evidence, not to
	// a new publication. Recreating it would lose its recorded ownership.
	for _, name := range []string{admissionRefsBucket, admissionReportsBucket} {
		owned := q.tx.Bucket([]byte(name))
		if owned.Get(id) != nil || owned.Bucket(id) != nil {
			return false, admission.ErrCorruptRecord
		}
	}
	if err = b.Put(id, data); err != nil {
		return false, err
	}
	return true, q.loosen(e.ID())
}

// LoadEvidence loads a published record and revalidates it.
func (l *AdmissionLedger) LoadEvidence(id admission.EvidenceID) (admission.Evidence, error) {
	var e admission.Evidence
	err := l.db.bolt.View(func(tx *bolt.Tx) error {
		var err error
		e, err = loadEvidence(tx, l.reg, id)
		return err
	})
	return e, err
}

// loadReports loads the later reports of e. A stored record must name e,
// and it can never list e's own original finding.
func loadReports(tx *bolt.Tx, e admission.Evidence) (admission.ReportLinks, error) {
	raw := tx.Bucket([]byte(admissionReportsBucket)).Get([]byte(e.ID()))
	if raw == nil {
		return admission.ReportLinks{Evidence: e.ID()}, nil
	}
	links, err := admission.UnmarshalReportLinks(raw)
	if err != nil {
		return admission.ReportLinks{}, err
	}
	if links.Evidence != e.ID() || slices.Contains(links.Links, e.FindingID()) {
		return admission.ReportLinks{}, admission.ErrCorruptRecord
	}
	return links, nil
}

// LinkReport records a later finding that reported published evidence.
func (l *AdmissionLedger) LinkReport(id admission.EvidenceID, findingID string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.update("link", func(tx *bolt.Tx) error { return linkTx(tx, id, findingID) })
}

// linkTx links a report to stored evidence. Links are metadata: they do not
// depend on the evidence passing current policy.
func linkTx(tx *bolt.Tx, id admission.EvidenceID, findingID string) error {
	original, err := loadStoredEvidence(tx, id)
	if err != nil {
		return err
	}
	links, err := loadReports(tx, original)
	if err != nil {
		return err
	}
	if findingID == original.FindingID() {
		return nil
	}
	next, changed, err := links.Add(findingID)
	if err != nil || !changed {
		return err
	}
	data, err := next.MarshalBinary()
	if err != nil {
		return err
	}
	return tx.Bucket([]byte(admissionReportsBucket)).Put([]byte(id), data)
}

// Reports returns the later findings linked to published evidence, whether
// or not it passes current policy.
func (l *AdmissionLedger) Reports(id admission.EvidenceID) ([]string, uint32, error) {
	var links admission.ReportLinks
	err := l.db.bolt.View(func(tx *bolt.Tx) error {
		e, err := loadStoredEvidence(tx, id)
		if err != nil {
			return err
		}
		links, err = loadReports(tx, e)
		return err
	})
	return links.Links, links.Dropped, err
}
