package state

import (
	"errors"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

// AppendHistoryDurable requires the bbolt history store and returns write
// failures so a caller can acknowledge records only after they are saved.
func (s *Store) AppendHistoryDurable(findings []alert.Finding) error {
	if len(findings) == 0 {
		return nil
	}
	db := store.Global()
	if db == nil {
		return errors.New("the history database is not open")
	}
	if err := db.AppendHistory(findings); err != nil {
		return err
	}
	recordFindings(findings)
	return nil
}
