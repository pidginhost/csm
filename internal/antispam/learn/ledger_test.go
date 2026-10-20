package learn

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

func openLedger(t testing.TB) (*Ledger, *store.DB) {
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

func TestBindRefusesRecordsInEveryUnboundBucket(t *testing.T) {
	for _, bucket := range store.LearnBuckets {
		t.Run(bucket, func(t *testing.T) {
			l, db := openLedger(t)
			if err := db.LearnUpdate(func(tx store.LearnTx) error {
				return tx.Put(bucket, []byte("existing"), []byte(`{}`))
			}); err != nil {
				t.Fatal(err)
			}
			if err := l.Bind("gen1", "prefix1"); !errors.Is(err, ErrStateMismatch) {
				t.Fatalf("unbound ledger with records accepted: %v", err)
			}
			if err := l.View(func(v LedgerView) error {
				_, ok, err := v.Binding()
				if ok {
					t.Error("failed bind persisted a binding")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestClusterIDsNeverReused(t *testing.T) {
	l, db := openLedger(t)
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
	compacted := t.TempDir()
	if _, _, err := db.CompactInto(filepath.Join(compacted, "csm.db"), 0); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(compacted)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	l = Open(reopened)
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

type failedCommitKV struct {
	*store.DB
	err error
}

func (db failedCommitKV) LearnUpdate(fn func(store.LearnTx) error) error {
	return db.DB.LearnUpdate(func(tx store.LearnTx) error {
		if err := fn(tx); err != nil {
			return err
		}
		return db.err
	})
}

func TestReserveRollbackAndRetryAfterReopen(t *testing.T) {
	for _, operator := range []bool{false, true} {
		t.Run(map[bool]string{false: "account", true: "operator"}[operator], func(t *testing.T) {
			dir := t.TempDir()
			db, openErr := store.Open(dir)
			if openErr != nil {
				t.Fatal(openErr)
			}
			t.Cleanup(func() { _ = db.Close() })
			intent := Intent{ID: "admission", Kind: IntentReport, UID: 1001, Admitted: time.Now().UTC()}
			charge := Usage{BodyBytes: 4096, Aliases: 2}
			commitErr := errors.New("commit failed")
			l := &Ledger{db: failedCommitKV{DB: db, err: commitErr}}
			reserve := func(tx LedgerTx) error {
				_, err := tx.Reserve(intent, intent.UID, operator, charge)
				return err
			}
			if err := l.Update(reserve); !errors.Is(err, commitErr) {
				t.Fatalf("failed commit returned %v", err)
			}
			if err := l.View(func(v LedgerView) error {
				if _, ok, err := v.Intent(intent.ID); err != nil || ok {
					t.Errorf("rolled-back intent exists: %v, %v", ok, err)
				}
				if usage, err := v.Usage(intent.UID, operator); err != nil || usage != (Usage{}) {
					t.Errorf("rolled-back usage: %+v, %v", usage, err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			l = Open(db)
			if err := l.Update(reserve); err != nil {
				t.Fatal(err)
			}
			intent.Done = true
			if err := l.Update(func(tx LedgerTx) error { return tx.PutIntent(intent) }); err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, reopenErr := store.Open(dir)
			if reopenErr != nil {
				t.Fatal(reopenErr)
			}
			t.Cleanup(func() { _ = reopened.Close() })
			l = Open(reopened)
			retry := intent
			retry.Admitted = intent.Admitted.Add(time.Hour)
			retry.Done = false
			if err := l.Update(func(tx LedgerTx) error {
				stored, err := tx.Reserve(retry, intent.UID, operator, charge)
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(stored, intent) {
					t.Error("retry changed the original admission or terminal result")
				}
				usage, err := tx.Usage(intent.UID, operator)
				if usage != charge {
					t.Errorf("retry charged usage again: %+v", usage)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOpOutcomeDoesNotPersistMessageFields(t *testing.T) {
	l, db := openLedger(t)
	var record OpRecord
	if err := json.Unmarshal([]byte(`{"request_id":"op-1","action":"spam","outcome":{"clusters":[{"cluster_id":7,"result":"committed"}],"outcome":"committed","exit_ok":true,"body":"synthetic message","headers":{"subject":"synthetic"}}}`), &record); err != nil {
		t.Fatal(err)
	}
	if err := l.Update(func(tx LedgerTx) error { return tx.PutOp(record) }); err != nil {
		t.Fatal(err)
	}
	if err := db.LearnView(func(tx store.LearnTx) error {
		data, err := tx.Get(store.LearnOpsBucket, []byte(record.RequestID))
		if err != nil {
			return err
		}
		var stored struct {
			Outcome map[string]json.RawMessage `json:"outcome"`
		}
		if err := json.Unmarshal(data, &stored); err != nil {
			return err
		}
		if _, ok := stored.Outcome["body"]; ok {
			t.Error("operator outcome persisted a message body")
		}
		if _, ok := stored.Outcome["headers"]; ok {
			t.Error("operator outcome persisted message headers")
		}
		for key, want := range map[string]string{
			"clusters": `[{"cluster_id":7,"result":"committed"}]`,
			"outcome":  `"committed"`,
			"exit_ok":  "true",
		} {
			if string(stored.Outcome[key]) != want {
				t.Errorf("operator outcome lost %s", key)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
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
	var checkType func(reflect.Type)
	seen := make(map[reflect.Type]bool)
	checkType = func(typ reflect.Type) {
		if seen[typ] || typ == reflect.TypeFor[time.Time]() {
			return
		}
		seen[typ] = true
		switch typ.Kind() {
		case reflect.Pointer:
			checkType(typ.Elem())
		case reflect.Slice, reflect.Array:
			if typ.Elem().Kind() == reflect.Uint8 {
				t.Errorf("%s can hold raw bytes", typ)
			}
			checkType(typ.Elem())
		case reflect.Map, reflect.Interface:
			t.Errorf("%s can hold arbitrary message fields", typ)
		case reflect.Struct:
			for i := range typ.NumField() {
				f := typ.Field(i)
				name := strings.ToLower(f.Name)
				if !strings.HasSuffix(name, "sha") && (name == "body" || strings.Contains(name, "snapshot") || strings.Contains(name, "message") || strings.Contains(name, "content") || strings.Contains(name, "header") || strings.Contains(name, "subject")) {
					t.Errorf("%s.%s names message content", typ.Name(), f.Name)
				}
				checkType(f.Type)
			}
		}
	}
	for _, rec := range []any{Binding{}, Cluster{}, Target{}, Intent{}, IntentCluster{}, Seed{}, OpRecord{}, Usage{}} {
		typ := reflect.TypeOf(rec)
		checkType(typ)
		data, err := json.Marshal(rec)
		if err != nil || strings.Contains(strings.ToLower(string(data)), `"body"`) {
			t.Errorf("%s encodes a body field: %s", typ.Name(), data)
		}
	}
}
