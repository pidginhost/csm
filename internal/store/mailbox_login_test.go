package store

import (
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestGeoHistorySharesLegacyAliasesAndCooldown(t *testing.T) {
	dir := t.TempDir()
	old, openErr := bolt.Open(filepath.Join(dir, "csm.db"), 0600, nil)
	if openErr != nil {
		t.Fatal(openErr)
	}
	const account = "user@victim.example"
	const alias = "User@Victim.Example"
	now := time.Now().UTC().Truncate(time.Second)
	if err := old.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucket([]byte("email:geo"))
		if err != nil {
			return err
		}
		meta, err := tx.CreateBucket([]byte("meta"))
		if err != nil {
			return err
		}
		if err := b.Put([]byte(alias), []byte(`{"countries":{"DE":5,"RO":15},"login_count":2}`)); err != nil {
			return err
		}
		if err := b.Put([]byte(account), []byte(`{"countries":{"RO":10},"login_count":3}`)); err != nil {
			return err
		}
		return meta.Put([]byte("email:geo_alert:"+alias), []byte(now.Format(time.RFC3339)))
	}); err != nil {
		t.Fatal(err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	for _, name := range []string{account, alias} {
		h, ok := db.GetGeoHistory(name)
		if !ok || h.LoginCount != 5 || len(h.Countries) != 2 || h.Countries["DE"] != 5 || h.Countries["RO"] != 15 {
			t.Errorf("geo history for %s = %+v (%t)", name, h, ok)
		}
	}
	if got := db.GetMetaString("email:geo_alert:" + account); got != now.Format(time.RFC3339) {
		t.Errorf("cooldown = %q, want %s", got, now)
	}
	for i := 1; i <= 2; i++ {
		result, err := db.UpdateGeoLogin(alias, now, time.Hour, func(h *GeoHistory) bool {
			h.LoginCount++
			return true
		})
		if err != nil || result.Notify || result.History.LoginCount != 5+i {
			t.Fatalf("login %d after upgrade: %+v, %v", i, result, err)
		}
	}
}

func TestUnreadableLegacyGeoHistoryIsIsolatedToMailbox(t *testing.T) {
	dir := t.TempDir()
	old, openErr := bolt.Open(filepath.Join(dir, "csm.db"), 0600, nil)
	if openErr != nil {
		t.Fatal(openErr)
	}
	if err := old.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucket([]byte("email:geo"))
		if err != nil {
			return err
		}
		return b.Put([]byte("User@victim.example"), []byte("{"))
	}); err != nil {
		t.Fatal(err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("one unreadable mailbox prevented opening the store: %v", err)
	}
	defer func() { _ = db.Close() }()
	observe := func(account string) error {
		_, err := db.UpdateGeoLogin(account, time.Now(), 24*time.Hour, func(h *GeoHistory) bool {
			h.LoginCount++
			return false
		})
		return err
	}
	if err := observe("user@victim.example"); err == nil {
		t.Error("overwrote unreadable history from a different spelling")
	}
	if err := observe("other@victim.example"); err != nil {
		t.Errorf("could not record another mailbox: %v", err)
	}
}
