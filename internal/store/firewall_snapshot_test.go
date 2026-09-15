package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
	bolt "go.etcd.io/bbolt"
	boltErrors "go.etcd.io/bbolt/errors"
)

// Snapshot clients receive domain values, never database transactions.
type firewallSnapshotStore interface {
	ReadFirewallState() (firewall.FirewallState, uint64, error)
	ReplaceFirewallState(uint64, firewall.FirewallState) (uint64, error)
}

func snapshotStore(t *testing.T, db *DB) firewallSnapshotStore {
	t.Helper()
	s, ok := any(db).(firewallSnapshotStore)
	if !ok {
		t.Fatal("store lacks lossless atomic firewall state contract")
	}
	return s
}

func openSnapshotDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func completeFirewallState() firewall.FirewallState {
	past := time.Date(2001, 2, 3, 4, 5, 6, 123456789, time.UTC)
	return firewall.FirewallState{
		Blocked: []firewall.BlockedEntry{
			{IP: "203.0.113.90", Reason: "expired", Source: "explicit", BlockedAt: past, ExpiresAt: past.Add(time.Hour)},
			{IP: "192.0.2.1", Reason: "permanent", BlockedAt: past},
		},
		BlockedNet: []firewall.SubnetEntry{{CIDR: "2001:db8::/64", Reason: "subnet", Source: "manual", BlockedAt: past, ExpiresAt: past.Add(2 * time.Hour)}},
		Allowed: []firewall.AllowedEntry{
			{IP: "198.51.100.2", Reason: "first", Source: "manual", Port: 443, ExpiresAt: past},
			{IP: "198.51.100.2", Reason: "second", Source: "system"},
			{IP: "198.51.100.2", Reason: "third", Source: "manual", Port: 80},
		},
		PortAllowed: []firewall.PortAllowEntry{{IP: "2001:db8::2", Port: 53, Proto: "udp", Reason: "resolver", Source: "explicit"}},
	}
}

func assertFirewallSnapshot(t *testing.T, s firewallSnapshotStore, want firewall.FirewallState, revision uint64) {
	t.Helper()
	got, rev, err := s.ReadFirewallState()
	if err != nil || rev != revision || !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot = %#v, revision %d, error %v; want %#v, revision %d", got, rev, err, want, revision)
	}
}

func TestFirewallSnapshotRoundTripReopenAndOwnership(t *testing.T) {
	db := openSnapshotDB(t)
	s := snapshotStore(t, db)
	state, rev, err := s.ReadFirewallState()
	if err == nil || rev != 0 || !reflect.DeepEqual(state, firewall.FirewallState{}) {
		t.Fatal("uninitialized state must return only an error")
	}
	input := completeFirewallState()
	rev, err = s.ReplaceFirewallState(0, input)
	if err != nil || rev != 1 {
		t.Fatalf("replace = %d, %v", rev, err)
	}
	assertFirewallSnapshot(t, s, completeFirewallState(), 1)
	input.Blocked[0].Reason = "caller edit"
	input.BlockedNet[0].Reason = "caller edit"
	input.Allowed[0].Reason = "caller edit"
	input.PortAllowed[0].Reason = "caller edit"
	got, _, err := s.ReadFirewallState()
	if err != nil {
		t.Fatal(err)
	}
	got.Blocked[0].IP = "192.0.2.8"
	got.BlockedNet[0].CIDR = "192.0.2.0/24"
	got.Allowed[0].Reason = "reader edit"
	got.PortAllowed[0].Reason = "reader edit"
	assertFirewallSnapshot(t, s, completeFirewallState(), 1)
	path := db.path
	if closeErr := db.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	reopened, err := bolt.Open(path, 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	db.bolt = reopened
	assertFirewallSnapshot(t, s, completeFirewallState(), 1)
	empty := firewall.FirewallState{Allowed: []firewall.AllowedEntry{}}
	if rev, err := s.ReplaceFirewallState(1, empty); err != nil || rev != 2 {
		t.Fatalf("empty replace = %d, %v", rev, err)
	}
	assertFirewallSnapshot(t, s, empty, 2)
}

func TestFirewallSnapshotFailedCommitPreservesAllCollections(t *testing.T) {
	db := openSnapshotDB(t)
	s := snapshotStore(t, db)
	want := completeFirewallState()
	if _, err := s.ReplaceFirewallState(0, want); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("commit refused after callback")
	previous := boltUpdate
	t.Cleanup(func() { boltUpdate = previous })
	boltUpdate = func(b *bolt.DB, fn func(*bolt.Tx) error) error {
		return b.Update(func(tx *bolt.Tx) error {
			if err := fn(tx); err != nil {
				return err
			}
			return injected
		})
	}
	if rev, err := s.ReplaceFirewallState(1, firewall.FirewallState{}); !errors.Is(err, injected) || rev != 0 {
		t.Fatalf("failed replace = %d, %v", rev, err)
	}
	assertFirewallSnapshot(t, s, want, 1)
}

func TestFirewallSnapshotRejectsStaleConcurrentWriters(t *testing.T) {
	db := openSnapshotDB(t)
	s := snapshotStore(t, db)
	if _, err := s.ReplaceFirewallState(0, completeFirewallState()); err != nil {
		t.Fatal(err)
	}
	const writers = 12
	var wg sync.WaitGroup
	successes := make(chan firewall.FirewallState, writers)
	failures := make(chan error, writers)
	for i := range writers {
		wg.Go(func() {
			next := completeFirewallState()
			next.Allowed[0].Port = 1000 + i
			rev, err := s.ReplaceFirewallState(1, next)
			if err == nil && rev == 2 {
				successes <- next
			} else {
				failures <- err
			}
		})
	}
	wg.Wait()
	if len(successes) != 1 || len(failures) != writers-1 {
		t.Fatalf("successes=%d failures=%d", len(successes), len(failures))
	}
	close(failures)
	for err := range failures {
		if !errors.Is(err, firewall.ErrStateConflict) {
			t.Fatalf("concurrent loser: %v", err)
		}
	}
	winner := <-successes
	assertFirewallSnapshot(t, s, winner, 2)
	if rev, err := s.ReplaceFirewallState(1, firewall.FirewallState{}); err == nil || rev != 0 {
		t.Fatalf("stale replace = %d, %v", rev, err)
	}
	assertFirewallSnapshot(t, s, winner, 2)
}

func TestFirewallSnapshotRejectsCorruptionWithoutPartialState(t *testing.T) {
	for _, bucket := range []string{"fw:blocked", "fw:subnets", "fw:allowed", "fw:port_allowed"} {
		for _, damage := range []string{"invalid JSON", "missing row", "extra row", "nested bucket", "valid JSON edit", "missing bucket"} {
			t.Run(bucket+"/"+damage, func(t *testing.T) {
				db := openSnapshotDB(t)
				s := snapshotStore(t, db)
				if _, err := s.ReplaceFirewallState(0, completeFirewallState()); err != nil {
					t.Fatal(err)
				}
				if err := db.bolt.Update(func(tx *bolt.Tx) error {
					b := tx.Bucket([]byte(bucket))
					k, _ := b.Cursor().First()
					switch damage {
					case "invalid JSON":
						return b.Put(k, []byte("{"))
					case "missing row":
						return b.Delete(k)
					case "extra row":
						return b.Put([]byte("unexpected"), []byte("{}"))
					case "nested bucket":
						_, err := b.CreateBucket([]byte("unexpected"))
						return err
					case "valid JSON edit":
						return b.Put(k, []byte("{}"))
					case "missing bucket":
						return tx.DeleteBucket([]byte(bucket))
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				got, rev, err := s.ReadFirewallState()
				if err == nil || rev != 0 || !reflect.DeepEqual(got, firewall.FirewallState{}) {
					t.Fatalf("corrupt read returned usable state: %#v, %d, %v", got, rev, err)
				}
				if rev, err := s.ReplaceFirewallState(1, firewall.FirewallState{}); err == nil || rev != 0 {
					t.Fatalf("corrupt store overwritten: %d, %v", rev, err)
				}
			})
		}
	}
}

func TestFirewallSnapshotClosedDBReturnsOnlyError(t *testing.T) {
	db := openSnapshotDB(t)
	s := snapshotStore(t, db)
	if _, err := s.ReplaceFirewallState(0, completeFirewallState()); err != nil {
		t.Fatal(err)
	}
	if closeErr := db.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	got, rev, err := s.ReadFirewallState()
	if !errors.Is(err, boltErrors.ErrDatabaseNotOpen) || rev != 0 || !reflect.DeepEqual(got, firewall.FirewallState{}) {
		t.Fatalf("closed read: %#v, %d, %v", got, rev, err)
	}
	if rev, err := s.ReplaceFirewallState(1, firewall.FirewallState{}); !errors.Is(err, boltErrors.ErrDatabaseNotOpen) || rev != 0 {
		t.Fatalf("closed write: %d, %v", rev, err)
	}
}

func TestFirewallSnapshotRejectsLossyEncoding(t *testing.T) {
	for _, field := range []string{"blocked reason", "allow source", "subnet reason", "port reason", "timestamp", "timestamp offset"} {
		t.Run(field, func(t *testing.T) {
			db := openSnapshotDB(t)
			s := snapshotStore(t, db)
			want := completeFirewallState()
			if _, err := s.ReplaceFirewallState(0, want); err != nil {
				t.Fatal(err)
			}
			next := completeFirewallState()
			switch field {
			case "blocked reason":
				next.Blocked[0].Reason = string([]byte{0xff})
			case "allow source":
				next.Allowed[0].Source = string([]byte{0xff})
			case "subnet reason":
				next.BlockedNet[0].Reason = string([]byte{0xff})
			case "port reason":
				next.PortAllowed[0].Reason = string([]byte{0xff})
			case "timestamp offset":
				next.Blocked[0].BlockedAt = time.Date(2001, 1, 1, 0, 0, 0, 0, time.FixedZone("historic", 61))
			case "timestamp":
				next.Blocked[0].BlockedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
			}
			if rev, err := s.ReplaceFirewallState(1, next); err == nil || rev != 0 {
				t.Fatalf("lossy replacement = %d, %v", rev, err)
			}
			assertFirewallSnapshot(t, s, want, 1)
		})
	}
}

func TestFirewallSnapshotRealCommitFailureSurvivesReopen(t *testing.T) {
	db := openSnapshotDB(t)
	s := snapshotStore(t, db)
	want := completeFirewallState()
	if _, err := s.ReplaceFirewallState(0, want); err != nil {
		t.Fatal(err)
	}
	if closeErr := db.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	limited, err := bolt.Open(db.path, 0600, &bolt.Options{MaxSize: 1024 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	db.bolt = limited
	next := completeFirewallState()
	next.PortAllowed[0].Reason = strings.Repeat("x", 2*1024*1024)
	failures := storageMetric(t, "csm_storage_firewall_commit_failures_total")
	if rev, writeErr := s.ReplaceFirewallState(1, next); writeErr == nil || rev != 0 {
		t.Fatalf("oversized commit = %d, %v", rev, writeErr)
	}
	if got := storageMetric(t, "csm_storage_firewall_commit_failures_total") - failures; got != 1 {
		t.Fatalf("commit failures = %f", got)
	}
	assertFirewallSnapshot(t, s, want, 1)
	if closeErr := db.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	reopened, err := bolt.Open(db.path, 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	db.bolt = reopened
	assertFirewallSnapshot(t, s, want, 1)
}

func TestFirewallSnapshotLegacyEditsCannotBypassRevision(t *testing.T) {
	db := openSnapshotDB(t)
	s := snapshotStore(t, db)
	if err := db.BlockIP("192.0.2.99", "legacy", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ReadFirewallState(); !errors.Is(err, firewall.ErrStateUninitialized) {
		t.Fatalf("legacy rows implicitly adopted: %v", err)
	}
	if _, err := s.ReplaceFirewallState(0, completeFirewallState()); err != nil {
		t.Fatal(err)
	}
	if _, ok := db.GetBlockedIP("192.0.2.99"); ok {
		t.Fatal("replacement retained destination-only row")
	}
	if err := db.AllowIP("198.51.100.2", "legacy change", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ReadFirewallState(); !errors.Is(err, firewall.ErrStateCorrupt) {
		t.Fatalf("out-of-band edit hidden: %v", err)
	}
	if _, err := s.ReplaceFirewallState(1, firewall.FirewallState{}); !errors.Is(err, firewall.ErrStateCorrupt) {
		t.Fatalf("out-of-band edit overwritten: %v", err)
	}
}

func TestFirewallSnapshotRejectsMalformedMetadata(t *testing.T) {
	for _, raw := range []string{"{", "null", `{}`, `{"version":2,"revision":1,"collections":[]}`, `{"version":1,"revision":0,"collections":[]}`} {
		t.Run(raw, func(t *testing.T) {
			db := openSnapshotDB(t)
			s := snapshotStore(t, db)
			if _, err := s.ReplaceFirewallState(0, completeFirewallState()); err != nil {
				t.Fatal(err)
			}
			if err := db.bolt.Update(func(tx *bolt.Tx) error {
				return tx.Bucket([]byte(firewallSnapshotBucket)).Put([]byte(firewallSnapshotKey), []byte(raw))
			}); err != nil {
				t.Fatal(err)
			}
			got, rev, err := s.ReadFirewallState()
			if !errors.Is(err, firewall.ErrStateCorrupt) || rev != 0 || !reflect.DeepEqual(got, firewall.FirewallState{}) {
				t.Fatalf("metadata read: %#v, %d, %v", got, rev, err)
			}
			if _, err := s.ReplaceFirewallState(0, firewall.FirewallState{}); !errors.Is(err, firewall.ErrStateCorrupt) {
				t.Fatalf("metadata overwritten: %v", err)
			}
		})
	}
}

func TestFirewallSnapshotRejectsUndecodableRowsWithMatchingDigest(t *testing.T) {
	for _, raw := range []string{
		`{"port":"invalid"}`, `null`, "{\"reason\":\"\xff\"}",
		`{"reason":"\ud800"}`, `{"reason":"\udfff"}`,
		`{"reason":"\ud800\u0041"}`, `{"reason":"\ud800\\udc00"}`,
	} {
		t.Run(raw, func(t *testing.T) {
			db := openSnapshotDB(t)
			s := snapshotStore(t, db)
			if _, err := s.ReplaceFirewallState(0, completeFirewallState()); err != nil {
				t.Fatal(err)
			}
			if updateErr := db.bolt.Update(func(tx *bolt.Tx) error {
				meta, err := readFirewallSnapshotMeta(tx)
				if err != nil {
					return err
				}
				// Damage the final collection so earlier rows would otherwise escape.
				collection := &meta.Collections[3]
				if putErr := tx.Bucket([]byte("fw:port_allowed")).Put([]byte(collection.Keys[0]), []byte(raw)); putErr != nil {
					return putErr
				}
				collection.Digest = digestFirewallCollection(collection.Keys, [][]byte{[]byte(raw)})
				encoded, err := json.Marshal(meta)
				if err != nil {
					return err
				}
				return tx.Bucket([]byte(firewallSnapshotBucket)).Put([]byte(firewallSnapshotKey), encoded)
			}); updateErr != nil {
				t.Fatal(updateErr)
			}
			got, rev, err := s.ReadFirewallState()
			if !errors.Is(err, firewall.ErrStateCorrupt) || rev != 0 || !reflect.DeepEqual(got, firewall.FirewallState{}) {
				t.Fatalf("decode returned usable state: %#v, %d, %v", got, rev, err)
			}
			if _, err := s.ReplaceFirewallState(1, firewall.FirewallState{}); !errors.Is(err, firewall.ErrStateCorrupt) {
				t.Fatalf("undecodable state overwritten: %v", err)
			}
		})
	}
}

func TestFirewallSnapshotReadersSeeOneCommittedRevision(t *testing.T) {
	db := openSnapshotDB(t)
	s := snapshotStore(t, db)
	stateFor := func(revision uint64) firewall.FirewallState {
		state := completeFirewallState()
		reason := fmt.Sprintf("revision %d", revision)
		state.Blocked[0].Reason = reason
		state.BlockedNet[0].Reason = reason
		state.Allowed[0].Reason = reason
		state.PortAllowed[0].Reason = reason
		return state
	}
	if _, err := s.ReplaceFirewallState(0, stateFor(1)); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	ready := make(chan struct{}, 3)
	failures := make(chan error, 3)
	var readers sync.WaitGroup
	for range 3 {
		readers.Go(func() {
			ready <- struct{}{}
			for {
				select {
				case <-stop:
					return
				default:
				}
				got, revision, err := s.ReadFirewallState()
				if err != nil {
					failures <- err
					return
				}
				if !reflect.DeepEqual(got, stateFor(revision)) {
					failures <- fmt.Errorf("mixed snapshot at revision %d", revision)
					return
				}
			}
		})
	}
	for range 3 {
		<-ready
	}
	for revision := uint64(1); revision <= 30; revision++ {
		if _, err := s.ReplaceFirewallState(revision, stateFor(revision+1)); err != nil {
			t.Error(err)
			break
		}
	}
	close(stop)
	readers.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	assertFirewallSnapshot(t, s, stateFor(31), 31)
}

func TestFirewallSnapshotDecodesValidUnicode(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want string
	}{
		{`{"reason":"\ud83d\ude00"}`, "\U0001f600"},
		{`{"reason":"\uD83D\uDE00"}`, "\U0001f600"},
		{`{"reason":"\\ud800"}`, `\ud800`},
		{`{"reason":"\\\ud83d\ude00"}`, "\\\U0001f600"},
		{`{"reason":"\ufffd"}`, "\ufffd"},
		{`{"reason":"\u0041"}`, "A"},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			got, err := decodeFirewallCollection[firewall.PortAllowEntry]([][]byte{[]byte(tc.raw)}, true)
			if err != nil || len(got) != 1 || got[0].Reason != tc.want {
				t.Fatalf("valid Unicode decode = %#v, %v; want reason %q", got, err, tc.want)
			}
		})
	}
}

func TestFirewallSnapshotLostCommitAcknowledgementIsUncertain(t *testing.T) {
	db := openSnapshotDB(t)
	s := snapshotStore(t, db)
	if _, err := s.ReplaceFirewallState(0, completeFirewallState()); err != nil {
		t.Fatal(err)
	}
	original := boltUpdate
	t.Cleanup(func() { boltUpdate = original })
	injected := errors.New("final metadata sync failed")
	boltUpdate = func(b *bolt.DB, fn func(*bolt.Tx) error) error {
		if err := b.Update(fn); err != nil {
			return err
		}
		return injected
	}
	next := completeFirewallState()
	next.Allowed[0].Reason = "new revision already visible"
	revision, err := s.ReplaceFirewallState(1, next)
	if revision != 0 || !errors.Is(err, injected) || !errors.Is(err, firewall.ErrStateCommitUncertain) {
		t.Fatalf("unacknowledged commit = %d, %v; need uncertainty with original cause", revision, err)
	}
	assertFirewallSnapshot(t, s, next, 2)
}

func TestFirewallSnapshotRefusedWritesAreNotUncertain(t *testing.T) {
	db := openSnapshotDB(t)
	s := snapshotStore(t, db)
	if _, err := s.ReplaceFirewallState(0, completeFirewallState()); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []uint64{0, 2} {
		revision, err := s.ReplaceFirewallState(expected, firewall.FirewallState{})
		if revision != 0 || !errors.Is(err, firewall.ErrStateConflict) || errors.Is(err, firewall.ErrStateCommitUncertain) {
			t.Fatalf("revision refusal = %d, %v", revision, err)
		}
	}
	assertFirewallSnapshot(t, s, completeFirewallState(), 1)
}
