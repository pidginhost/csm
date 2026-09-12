package store

import (
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// WPVerificationResult describes a completed attempt without storing command
// output, which may contain account credentials or arbitrary PHP output.
type WPVerificationResult struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

// WPVerificationRecord retains the last result and a bounded failure streak.
type WPVerificationRecord struct {
	WPVerificationResult
	Account    string    `json:"account,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
	AttemptAt  time.Time `json:"attempt_at"`
	Failures   int       `json:"failures"`
}

type wpVerificationState struct {
	Rows map[string]WPVerificationRecord `json:"rows"`
	// Completed discovery watermarks prevent a late scan from resurrecting
	// installations removed by a newer full or account-scoped discovery.
	Discovery map[string]time.Time `json:"discovery"`
}

func wpVerificationKey(kind string) ([]byte, error) {
	if kind != "core" && kind != "plugins" {
		return nil, fmt.Errorf("unknown WordPress verification kind %q", kind)
	}
	return []byte("wp_verification:" + kind), nil
}

func readWPVerification(b *bolt.Bucket, key []byte) (wpVerificationState, error) {
	s := wpVerificationState{}
	if data := b.Get(key); data != nil {
		if err := json.Unmarshal(data, &s); err != nil {
			return s, fmt.Errorf("decode WordPress verification state: %w", err)
		}
	}
	if s.Rows == nil {
		s.Rows = make(map[string]WPVerificationRecord)
	}
	if s.Discovery == nil {
		s.Discovery = make(map[string]time.Time)
	}
	return s, nil
}

// UpdateWPVerification atomically merges one scan's actual attempts. Discovery
// alone never increments failures. Repeated consumers of the same scan share
// at, so they cannot turn one failed attempt into a persistent failure.
func (db *DB) UpdateWPVerification(kind string, at time.Time, scope string, discovered map[string]string, results map[string]WPVerificationResult, complete bool) error {
	key, err := wpVerificationKey(kind)
	if err != nil {
		return err
	}
	if at.IsZero() {
		return fmt.Errorf("WordPress verification requires a scan time")
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("meta"))
		s, err := readWPVerification(b, key)
		if err != nil {
			return err
		}
		for path, account := range discovered {
			if scope != "" && account != scope {
				continue
			}
			if s.Discovery[""].After(at) || s.Discovery[account].After(at) {
				continue
			}
			row := s.Rows[path]
			if row.ObservedAt.After(at) {
				continue
			}
			row.Account, row.ObservedAt = account, at
			if result, ok := results[path]; ok && at.After(row.AttemptAt) {
				switch result.State {
				case "verified", "modified", "not_wordpress", "unverified":
				default:
					return fmt.Errorf("invalid WordPress verification result %q", result.State)
				}
				if result.State == "unverified" {
					if row.Failures < 2 {
						row.Failures++
					}
				} else {
					row.Failures = 0
				}
				row.WPVerificationResult, row.AttemptAt = result, at
			}
			s.Rows[path] = row
		}
		if complete && !s.Discovery[""].After(at) && !s.Discovery[scope].After(at) {
			for path, row := range s.Rows {
				if _, found := discovered[path]; !found && (scope == "" || row.Account == scope) && !row.ObservedAt.After(at) {
					delete(s.Rows, path)
				}
			}
			if scope == "" {
				for account, prior := range s.Discovery {
					if !prior.After(at) {
						delete(s.Discovery, account)
					}
				}
			}
			s.Discovery[scope] = at
		}
		data, err := json.Marshal(s)
		if err != nil {
			return err
		}
		return b.Put(key, data)
	})
}

// WPVerification reports persisted coverage, returning read errors rather than
// presenting missing evidence as a clean empty inventory.
func (db *DB) WPVerification(kind string) (map[string]WPVerificationRecord, error) {
	key, err := wpVerificationKey(kind)
	if err != nil {
		return nil, err
	}
	var rows map[string]WPVerificationRecord
	err = db.bolt.View(func(tx *bolt.Tx) error {
		s, readErr := readWPVerification(tx.Bucket([]byte("meta")), key)
		rows = s.Rows
		return readErr
	})
	return rows, err
}
