package store

import (
	"encoding/json"
	"time"

	bolt "go.etcd.io/bbolt"
)

// PluginInfo holds cached metadata for a WordPress plugin from the API.
type PluginInfo struct {
	LatestVersion string `json:"latest_version"`
	TestedUpTo    string `json:"tested_up_to"`
	LastChecked   int64  `json:"last_checked_unix"`
}

// SitePluginEntry describes a single plugin installed on a WordPress site.
type SitePluginEntry struct {
	Slug             string `json:"slug"`
	Name             string `json:"name"`
	Status           string `json:"status"`
	InstalledVersion string `json:"installed_version"`
	UpdateVersion    string `json:"update_version"`
}

// SitePlugins holds the full plugin inventory for a WordPress installation.
type SitePlugins struct {
	Account string            `json:"account"`
	Domain  string            `json:"domain"`
	Plugins []SitePluginEntry `json:"plugins"`
}

// SetPluginInfo stores plugin metadata keyed by slug in the plugins bucket.
func (db *DB) SetPluginInfo(slug string, info PluginInfo) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("plugins"))
		val, err := json.Marshal(info)
		if err != nil {
			return err
		}
		return b.Put([]byte(slug), val)
	})
}

// GetPluginInfo retrieves plugin metadata for the given slug.
// Returns the entry and true if found, or a zero value and false if not.
func (db *DB) GetPluginInfo(slug string) (PluginInfo, bool) {
	var info PluginInfo
	var found bool

	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("plugins"))
		v := b.Get([]byte(slug))
		if v == nil {
			return nil
		}
		if json.Unmarshal(v, &info) != nil {
			return nil //nolint:nilerr // skip corrupt entry
		}
		found = true
		return nil
	})

	return info, found
}

// SetSitePlugins stores the plugin inventory for a WordPress installation
// keyed by its filesystem path in the plugins:sites bucket.
func (db *DB) SetSitePlugins(wpPath string, site SitePlugins) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("plugins:sites"))
		val, err := json.Marshal(site)
		if err != nil {
			return err
		}
		return b.Put([]byte(wpPath), val)
	})
}

// GetSitePlugins retrieves the plugin inventory for a WordPress installation.
// Returns the entry and true if found, or a zero value and false if not.
func (db *DB) GetSitePlugins(wpPath string) (SitePlugins, bool) {
	var site SitePlugins
	var found bool

	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("plugins:sites"))
		v := b.Get([]byte(wpPath))
		if v == nil {
			return nil
		}
		if json.Unmarshal(v, &site) != nil {
			return nil //nolint:nilerr // skip corrupt entry
		}
		found = true
		return nil
	})

	return site, found
}

// DeleteSitePlugins removes the plugin inventory for a WordPress installation.
func (db *DB) DeleteSitePlugins(wpPath string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("plugins:sites"))
		return b.Delete([]byte(wpPath))
	})
}

// AllSitePlugins returns all site plugin inventories keyed by WordPress path.
func (db *DB) AllSitePlugins() map[string]SitePlugins {
	entries := make(map[string]SitePlugins)
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("plugins:sites")).ForEach(func(k, v []byte) error {
			var s SitePlugins
			if json.Unmarshal(v, &s) != nil {
				return nil //nolint:nilerr // skip corrupt entry
			}
			entries[string(k)] = s
			return nil
		})
	})
	return entries
}

// GetPluginRefreshTime reads the last plugin refresh timestamp from the meta bucket.
// Returns the zero time if not set.
func (db *DB) GetPluginRefreshTime() time.Time {
	var t time.Time

	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("meta"))
		v := b.Get([]byte("plugins:last_refresh"))
		if v == nil {
			return nil
		}
		parsed, err := time.Parse(time.RFC3339, string(v))
		if err != nil {
			return nil //nolint:nilerr // skip corrupt entry
		}
		t = parsed
		return nil
	})

	return t
}

// SetPluginRefreshTime writes the plugin refresh timestamp to the meta bucket.
func (db *DB) SetPluginRefreshTime(t time.Time) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("meta"))
		return b.Put([]byte("plugins:last_refresh"), []byte(t.Format(time.RFC3339)))
	})
}
