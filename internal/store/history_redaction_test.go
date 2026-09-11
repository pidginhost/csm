package store

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	bolt "go.etcd.io/bbolt"
)

// Readback alone can hide plaintext persistence behind output filtering. Check
// the actual bucket value as well as the finding returned to history consumers.
func TestAppendHistoryRedactsStoredText(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	f := alert.Finding{
		Check: "cpanel_login_realtime", Severity: alert.Warning,
		Message: "password=message-fixture", Details: "[cpaneld] NEW shop:session-fixture",
		SourceIP: "198.51.100.23", TenantID: "shop", Timestamp: time.Now().UTC(),
		FilePath: "/home/shop/password=filename", DedupKey: "stable-fixture",
	}
	want := f
	want.Message = "password=[REDACTED]"
	want.Details = "[cpaneld] NEW shop:[REDACTED]"
	input := []alert.Finding{f}
	if err := db.AppendHistory(input); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(input, []alert.Finding{f}) {
		t.Fatal("history redaction mutated the caller's finding")
	}
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		_, value := tx.Bucket([]byte("history")).Cursor().First()
		var stored alert.Finding
		if err := json.Unmarshal(value, &stored); err != nil {
			return err
		}
		if !reflect.DeepEqual(stored, want) {
			t.Errorf("stored finding = %+v, want %+v", stored, want)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got, total := db.ReadHistory(10, 0)
	if total != 1 || !reflect.DeepEqual(got, []alert.Finding{want}) {
		t.Errorf("history = %+v, total %d; want %+v, total 1", got, total, want)
	}
}
