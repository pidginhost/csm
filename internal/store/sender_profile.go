package store

import (
	"encoding/json"

	bolt "go.etcd.io/bbolt"
)

// senderProfileBucket holds one SenderProfile per authenticated mail account.
const senderProfileBucket = "email:sender"

// SenderDay summarises one UTC day of authenticated sends for a mailbox. The
// distinct sets are capped by the writer, so a counted value is a floor once
// the cap is reached.
type SenderDay struct {
	Sends int `json:"sends"`
	// IPs are the distinct source addresses seen.
	IPs []string `json:"ips,omitempty"`
	// MaxHourIPs is the most distinct source addresses seen inside any one
	// rolling hour of the day.
	MaxHourIPs int `json:"max_hour_ips"`
	// Countries are the distinct source countries resolved for the day.
	Countries []string `json:"countries,omitempty"`
	// Recipients are the distinct envelope recipients, lower-cased.
	Recipients []string `json:"recipients,omitempty"`
	// SingleRecipients excludes bulk announcements from individual fan-out.
	SingleRecipients []string `json:"single_recipients,omitempty"`
}

// SenderProfile is a mailbox's recent sending history keyed by UTC day
// ("2006-01-02"). The realtime detector compares today against the prior
// days to judge whether a change in sources or fan-out is the owner's habit
// or someone else's.
type SenderProfile struct {
	Days map[string]*SenderDay `json:"days"`
}

// SetSenderProfile stores the sending profile for a mailbox.
func (db *DB) SetSenderProfile(mailbox string, p SenderProfile) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		val, err := json.Marshal(p)
		if err != nil {
			return err
		}
		return tx.Bucket([]byte(senderProfileBucket)).Put([]byte(mailbox), val)
	})
}

// GetSenderProfile retrieves the sending profile for a mailbox. A missing
// profile is empty; unreadable history is an error, never a fresh baseline.
func (db *DB) GetSenderProfile(mailbox string) (SenderProfile, error) {
	var p SenderProfile
	err := db.bolt.View(func(tx *bolt.Tx) error {
		v := tx.Bucket([]byte(senderProfileBucket)).Get([]byte(mailbox))
		if v == nil {
			return nil
		}
		return json.Unmarshal(v, &p)
	})
	if err != nil {
		return SenderProfile{}, err
	}
	return p, nil
}

// PruneSenderProfiles expires old days even for mailboxes that never send
// again. Empty profiles are removed instead of retaining recipient history.
func (db *DB) PruneSenderProfiles(oldest string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(senderProfileBucket))
		cursor := bucket.Cursor()
		for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
			var p SenderProfile
			if err := json.Unmarshal(value, &p); err != nil {
				return err
			}
			changed := false
			for day := range p.Days {
				if day < oldest {
					delete(p.Days, day)
					changed = true
				}
			}
			if len(p.Days) == 0 {
				if err := cursor.Delete(); err != nil {
					return err
				}
			} else if changed {
				encoded, err := json.Marshal(p)
				if err != nil {
					return err
				}
				if err := bucket.Put(key, encoded); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
