package daemon

import (
	"bytes"
	"encoding/gob"
	"errors"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

const (
	settingsBucket    = "phprelay:settings"
	dryRunOverrideKey = "dry_run_override"
)

type dryRunOverrideRow struct {
	Value     bool
	UpdatedAt time.Time
	UpdatedBy string
}

func writeDryRunOverride(db *store.DB, val bool, by string) error {
	if db == nil {
		return errors.New("db nil")
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(dryRunOverrideRow{Value: val, UpdatedAt: time.Now(), UpdatedBy: by}); err != nil {
		return err
	}
	return db.PHPRelayPut(settingsBucket, dryRunOverrideKey, buf.Bytes())
}

func deleteDryRunOverride(db *store.DB) error {
	if db == nil {
		return nil
	}
	return db.PHPRelayDelete(settingsBucket, dryRunOverrideKey)
}

func readDryRunOverride(db *store.DB) (bool, bool, error) {
	if db == nil {
		return false, false, nil
	}
	raw, ok, err := db.PHPRelayGet(settingsBucket, dryRunOverrideKey)
	if err != nil || !ok {
		return false, false, err
	}
	var row dryRunOverrideRow
	if err := gob.NewDecoder(bytes.NewReader(raw)).Decode(&row); err != nil {
		return false, false, err
	}
	return row.Value, true, nil
}
