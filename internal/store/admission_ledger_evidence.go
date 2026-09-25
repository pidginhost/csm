package store

import (
	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

func loadEvidence(tx *bolt.Tx, reg *admission.Registry, id admission.EvidenceID) (admission.Evidence, error) {
	if _, err := admission.ParseEvidenceID(string(id)); err != nil {
		return admission.Evidence{}, err
	}
	raw := tx.Bucket([]byte(admissionEvidenceBucket)).Get([]byte(id))
	if raw == nil {
		return admission.Evidence{}, refusal(admission.ReasonInvalid, "evidence is not published")
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
				return refusal(admission.ReasonInvalid, "evidence ID already holds a different record")
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

func loadReports(tx *bolt.Tx, id admission.EvidenceID) (admission.ReportLinks, error) {
	raw := tx.Bucket([]byte(admissionReportsBucket)).Get([]byte(id))
	if raw == nil {
		return admission.ReportLinks{}, nil
	}
	return admission.UnmarshalReportLinks(raw)
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
		links, err := loadReports(tx, id)
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
		if _, err := loadEvidence(tx, l.reg, id); err != nil {
			return err
		}
		var err error
		links, err = loadReports(tx, id)
		return err
	})
	return links.Links, links.Dropped, err
}
