package store

import (
	"slices"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

func loadEvidence(tx *bolt.Tx, reg *admission.Registry, id admission.EvidenceID) (admission.Evidence, error) {
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
	data, err := e.MarshalBinary()
	if err != nil {
		return false, err
	}
	id := []byte(e.ID())
	l.mu.Lock()
	defer l.mu.Unlock()
	published := false
	err = l.update("publish", func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(admissionEvidenceBucket))
		if raw := b.Get(id); raw != nil {
			old, decodeErr := admission.UnmarshalEvidence(raw)
			if decodeErr != nil {
				return corruptRecord(decodeErr)
			}
			if old.ID() != e.ID() {
				return admission.ErrCorruptRecord
			}
			if !old.Equal(e) {
				return admission.ErrEvidenceConflict
			}
			return nil
		}
		published = true
		return b.Put(id, data)
	})
	if err != nil {
		return false, err
	}
	return published, nil
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
	return l.update("link", func(tx *bolt.Tx) error {
		original, err := loadEvidence(tx, l.reg, id)
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
	})
}

// Reports returns the later findings linked to published evidence.
func (l *AdmissionLedger) Reports(id admission.EvidenceID) ([]string, uint32, error) {
	var links admission.ReportLinks
	err := l.db.bolt.View(func(tx *bolt.Tx) error {
		e, err := loadEvidence(tx, l.reg, id)
		if err != nil {
			return err
		}
		links, err = loadReports(tx, e)
		return err
	})
	return links.Links, links.Dropped, err
}
