package store

import (
	"encoding/json"
	"time"

	bolt "go.etcd.io/bbolt"
)

const geoAlertPrefix = "email:geo_alert:"

func (db *DB) readGeoHistory(b *bolt.Bucket, mailbox string) (GeoHistory, bool, error) {
	var h GeoHistory
	raw := b.Get([]byte(mailbox))
	found := raw != nil
	if found {
		if err := json.Unmarshal(raw, &h); err != nil {
			return GeoHistory{}, false, err
		}
	}
	for _, alias := range db.legacyGeoKeys[mailbox] {
		raw := b.Get([]byte(alias))
		if raw == nil {
			continue
		}
		var old GeoHistory
		if err := json.Unmarshal(raw, &old); err != nil {
			return GeoHistory{}, false, err
		}
		found = true
		h.LoginCount += old.LoginCount
		if h.Countries == nil {
			h.Countries = make(map[string]int64)
		}
		for country, at := range old.Countries {
			h.Countries[country] = max(h.Countries[country], at)
		}
		if old.Webmail != nil && (h.Webmail == nil || old.Webmail.At.After(h.Webmail.At)) {
			h.Webmail = old.Webmail
		}
	}
	return h, found, nil
}

func (db *DB) putGeoHistory(b *bolt.Bucket, mailbox string, h GeoHistory) error {
	v, err := json.Marshal(h)
	if err != nil {
		return err
	}
	if err := b.Put([]byte(mailbox), v); err != nil {
		return err
	}
	for _, alias := range db.legacyGeoKeys[mailbox] {
		if err := b.Delete([]byte(alias)); err != nil {
			return err
		}
	}
	return nil
}

type GeoLoginResult struct {
	History GeoHistory
	Notify  bool
}

// UpdateGeoLogin commits a login and claims its summary cooldown. The caller
// records evidence after commit so mail response never holds a transaction.
func (db *DB) UpdateGeoLogin(account string, now time.Time, cooldown time.Duration, update func(*GeoHistory) bool) (GeoLoginResult, error) {
	mailbox := MailboxEvidenceKey(account)
	var result GeoLoginResult
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("email:geo"))
		history, _, err := db.readGeoHistory(b, mailbox)
		if err != nil {
			return err
		}
		novel := update(&history)
		if putErr := db.putGeoHistory(b, mailbox, history); putErr != nil {
			return putErr
		}
		result.History = history
		if !novel {
			return nil
		}
		meta := tx.Bucket([]byte("meta"))
		alertKey := []byte(geoAlertPrefix + mailbox)
		if last := geoNoticeTime(meta, alertKey); now.Sub(last) < cooldown {
			return nil
		}
		result.Notify = true
		return meta.Put(alertKey, []byte(now.Format(time.RFC3339Nano)))
	})
	if err != nil {
		return GeoLoginResult{}, err
	}
	return result, nil
}

// A mailbox's next write folds its legacy spellings together. Deferring
// the decode keeps one damaged row from preventing the daemon from starting.
func (db *DB) indexLegacyGeoKeys(tx *bolt.Tx) error {
	meta := tx.Bucket([]byte("meta"))
	marker := []byte("email:geo_case_v1")
	if meta.Get(marker) != nil {
		return nil
	}
	c := tx.Bucket([]byte("email:geo")).Cursor()
	for k, _ := c.First(); k != nil; k, _ = c.Next() {
		alias := string(k)
		mailbox := MailboxEvidenceKey(alias)
		if alias == mailbox {
			continue
		}
		if db.legacyGeoKeys == nil {
			db.legacyGeoKeys = make(map[string][]string)
		}
		db.legacyGeoKeys[mailbox] = append(db.legacyGeoKeys[mailbox], alias)
		oldKey, key := []byte(geoAlertPrefix+alias), []byte(geoAlertPrefix+mailbox)
		if oldTime := geoNoticeTime(meta, oldKey); oldTime.After(geoNoticeTime(meta, key)) {
			if err := meta.Put(key, []byte(oldTime.Format(time.RFC3339Nano))); err != nil {
				return err
			}
		}
		if err := meta.Delete(oldKey); err != nil {
			return err
		}
	}
	if len(db.legacyGeoKeys) == 0 {
		return meta.Put(marker, []byte("1"))
	}
	return nil
}

// An absent or unparseable notice time has never suppressed a geo notice.
func geoNoticeTime(meta *bolt.Bucket, key []byte) time.Time {
	at, _ := time.Parse(time.RFC3339, string(meta.Get(key)))
	return at
}
