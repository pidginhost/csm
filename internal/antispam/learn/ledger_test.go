package learn

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

func openLedger(t *testing.T) (*Ledger, *store.DB) {
	t.Helper()
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return Open(db), db
}

func TestBindFirstTimeAndMatch(t *testing.T) {
	l, _ := openLedger(t)
	if err := l.Bind("gen1", "prefix1"); err != nil {
		t.Fatal(err)
	}
	if err := l.Bind("gen1", "prefix1"); err != nil {
		t.Fatalf("matching binding refused: %v", err)
	}
	err := l.View(func(v LedgerView) error {
		b, ok, err := v.Binding()
		if err != nil || !ok || b.HashGeneration != "gen1" || b.Prefix != "prefix1" || b.Created.IsZero() {
			t.Errorf("binding %+v ok %v err %v", b, ok, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestBindMismatchRefuses(t *testing.T) {
	l, _ := openLedger(t)
	if err := l.Bind("gen1", "prefix1"); err != nil {
		t.Fatal(err)
	}
	for _, b := range [][2]string{{"gen2", "prefix1"}, {"gen1", "prefix2"}} {
		if err := l.Bind(b[0], b[1]); !errors.Is(err, ErrStateMismatch) {
			t.Fatalf("bind %v: %v", b, err)
		}
	}
	if err := l.Bind("", ""); err == nil {
		t.Fatal("empty binding accepted")
	}
}

func TestBindRefusesOldPrefixWithEmptyLedger(t *testing.T) {
	l, _ := openLedger(t)
	if err := l.Update(func(tx LedgerTx) error {
		return tx.PutCluster(Cluster{ID: 1, Anchor: digest('a')})
	}); err != nil {
		t.Fatal(err)
	}
	if err := l.Bind("gen1", "prefix1"); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("unbound ledger with clusters accepted: %v", err)
	}
}

func TestClusterIDsNeverReused(t *testing.T) {
	l, _ := openLedger(t)
	var first, second uint64
	if err := l.Update(func(tx LedgerTx) error {
		var err error
		if first, err = tx.NextClusterID(); err != nil {
			return err
		}
		if err := tx.PutCluster(Cluster{ID: first, Anchor: digest('a')}); err != nil {
			return err
		}
		return tx.DeleteCluster(first)
	}); err != nil {
		t.Fatal(err)
	}
	if err := l.Update(func(tx LedgerTx) error {
		var err error
		second, err = tx.NextClusterID()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if first != 1 || second != 2 {
		t.Fatalf("ids %d then %d", first, second)
	}
}

func TestUsageChargedOncePerAdmission(t *testing.T) {
	l, _ := openLedger(t)
	intent := Intent{ID: "op-1", Kind: IntentReport, UID: 1001, Admitted: time.Now().UTC()}
	charge := Usage{BodyBytes: 4096, Aliases: 2}
	for range 2 {
		if err := l.Update(func(tx LedgerTx) error {
			_, err := tx.Reserve(intent, 1001, false, charge)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.View(func(v LedgerView) error {
		u, err := v.Usage(1001, false)
		if err != nil || u != charge {
			t.Errorf("usage %+v err %v", u, err)
		}
		other, err := v.Usage(0, true)
		if err != nil || other != (Usage{}) {
			t.Errorf("operator usage %+v err %v", other, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Anchor bodies live only in the body store; no ledger record can carry
// message bytes.
func TestRecordsNeverHoldBodies(t *testing.T) {
	for _, rec := range []any{Binding{}, Cluster{}, Target{}, Intent{}, IntentCluster{}, Seed{}, OpRecord{}, Usage{}} {
		typ := reflect.TypeOf(rec)
		for i := range typ.NumField() {
			f := typ.Field(i)
			if f.Type.Kind() == reflect.Slice && f.Type.Elem().Kind() == reflect.Uint8 && f.Name != "Outcome" {
				t.Errorf("%s.%s can hold raw bytes", typ.Name(), f.Name)
			}
			name := strings.ToLower(f.Name)
			if !strings.HasSuffix(name, "sha") && (name == "body" || strings.Contains(name, "snapshot") || strings.Contains(name, "message") || strings.Contains(name, "content")) {
				t.Errorf("%s.%s names message content", typ.Name(), f.Name)
			}
		}
		data, err := json.Marshal(rec)
		if err != nil || strings.Contains(strings.ToLower(string(data)), `"body"`) {
			t.Errorf("%s encodes a body field: %s", typ.Name(), data)
		}
	}
}
