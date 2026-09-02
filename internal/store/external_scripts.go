package store

import (
	"time"

	bolt "go.etcd.io/bbolt"
)

// externalScriptsBucket remembers every external <script src> host seen in
// a site's wp_options, keyed "<site>|<option>|<host>" -> RFC3339 first-seen
// time, plus "<site>|" -> baseline completion time. The structural
// classifier only flags attacker markers, so a loader on an unremarkable
// HTTPS host is invisible to it; remembering hosts lets the scan report a
// host the first time it appears after the site's baseline, once.
const externalScriptsBucket = "db:external_scripts"

func externalScriptKey(site, option, host string) []byte {
	return []byte(site + "|" + option + "|" + host)
}

func externalScriptBaselineKey(site string) []byte {
	return []byte(site + "|")
}

// MarkExternalScriptSeen records host for (site, option) and reports whether
// it is new. Nothing is new until FinishExternalScriptBaseline has run for
// the site: the first scan records what is already there without reporting
// it, the way file_index treats its first pass.
func (db *DB) MarkExternalScriptSeen(site, option, host string, now time.Time) (bool, error) {
	if db == nil || db.bolt == nil {
		return false, nil
	}
	isNew := false
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(externalScriptsBucket))
		if err != nil {
			return err
		}
		key := externalScriptKey(site, option, host)
		if b.Get(key) != nil {
			return nil
		}
		isNew = b.Get(externalScriptBaselineKey(site)) != nil
		return b.Put(key, []byte(now.UTC().Format(time.RFC3339)))
	})
	return isNew, err
}

// FinishExternalScriptBaseline marks the site's first scan as complete, so
// hosts recorded from now on count as new.
func (db *DB) FinishExternalScriptBaseline(site string, now time.Time) error {
	if db == nil || db.bolt == nil {
		return nil
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(externalScriptsBucket))
		if err != nil {
			return err
		}
		key := externalScriptBaselineKey(site)
		if b.Get(key) != nil {
			return nil
		}
		return b.Put(key, []byte(now.UTC().Format(time.RFC3339)))
	})
}
