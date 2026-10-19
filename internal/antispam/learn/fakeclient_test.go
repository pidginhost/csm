package learn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeStorage is a deterministic fuzzy storage: one value per digest, with
// hooks that inject lost replies, lost writes, refusals and read failures.
type fakeStorage struct {
	mu     sync.Mutex
	values map[Digest]int64
	// bodies maps an anchor body to the digest its text hashes to.
	bodies map[string]Digest
	// onAdd and onDelete decide whether a mutation applies and what the
	// caller hears; nil applies and succeeds.
	onAdd     func(d Digest, w int32) (apply bool, err error)
	onDelete  func(d Digest) (apply bool, err error)
	readErr   error
	adds      []int32
	deletes   int
	syncs     int
	inspected int
}

func newStorage() *fakeStorage {
	return &fakeStorage{values: map[Digest]int64{}, bodies: map[string]Digest{}}
}

func (s *fakeStorage) value(d Digest) (int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.values[d]
	return v, ok
}

func (s *fakeStorage) set(d Digest, v int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[d] = v
}

func (s *fakeStorage) Inspect(_ context.Context, body []byte) (Inspection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readErr != nil {
		return Inspection{}, s.readErr
	}
	d, ok := s.bodies[string(body)]
	if !ok {
		return Inspection{}, errors.New("unknown body")
	}
	return Inspection{Results: []Result{s.result(d)}, Distinct: 1}, nil
}

func (s *fakeStorage) result(d Digest) Result {
	v, ok := s.values[d]
	if !ok {
		return Result{Queried: d}
	}
	return Result{Queried: d, Stored: d, Found: true, Confirmed: true, Prob: 1, Value: v, Flag: 1}
}

func (s *fakeStorage) InspectDigests(_ context.Context, ds []Digest) (Inspection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inspected++
	if s.readErr != nil {
		return Inspection{}, s.readErr
	}
	insp := Inspection{Distinct: len(ds)}
	for _, d := range ds {
		insp.Results = append(insp.Results, s.result(d))
	}
	return insp, nil
}

func (s *fakeStorage) Add(_ context.Context, body []byte, w int32) error {
	s.mu.Lock()
	d := s.bodies[string(body)]
	hook := s.onAdd
	s.adds = append(s.adds, w)
	s.mu.Unlock()
	apply, err := true, error(nil)
	if hook != nil {
		apply, err = hook(d, w)
	}
	if apply {
		s.mu.Lock()
		s.values[d] += int64(w)
		s.mu.Unlock()
	}
	return err
}

func (s *fakeStorage) DeleteHash(_ context.Context, d Digest) error {
	s.mu.Lock()
	hook := s.onDelete
	s.deletes++
	s.mu.Unlock()
	apply, err := true, error(nil)
	if hook != nil {
		apply, err = hook(d)
	}
	if apply {
		s.mu.Lock()
		delete(s.values, d)
		s.mu.Unlock()
	}
	return err
}

func (s *fakeStorage) Sync(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncs++
	return nil
}

func (s *fakeStorage) counts() (adds []int32, deletes int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]int32(nil), s.adds...), s.deletes
}

// publishFixture is one cluster with a committed anchor body and a target.
type publishFixture struct {
	ledger  *Ledger
	bodies  *Bodies
	storage *fakeStorage
	anchor  Digest
	body    []byte
}

func newPublishFixture(t *testing.T, target int32) *publishFixture {
	t.Helper()
	l, _ := openLedger(t)
	f := &publishFixture{ledger: l, bodies: testBodies(t), storage: newStorage(), anchor: digest('a'), body: []byte("From: x@example.com\r\n\r\nanchor text\r\n")}
	f.storage.bodies[string(f.body)] = f.anchor
	s := stageCommit(t, f.bodies, f.body, 1)
	if err := l.Update(func(tx LedgerTx) error {
		if err := tx.PutCluster(Cluster{ID: 1, Anchor: f.anchor, BodyLen: s.Len, BodySHA: s.SHA, Revision: 1}); err != nil {
			return err
		}
		return tx.PutTarget(Target{Digest: f.anchor, ClusterID: 1, T: target, Revision: 1, Phase: PhaseRead})
	}); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *publishFixture) publisher() *Publisher {
	p := NewPublisher(f.storage, f.ledger, f.bodies)
	p.poll, p.deadline = time.Millisecond, 20*time.Millisecond
	return p
}

func (f *publishFixture) target(t *testing.T) Target {
	t.Helper()
	var got Target
	if err := f.ledger.View(func(v LedgerView) error {
		var err error
		got, _, err = v.Target(f.anchor)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return got
}

func sha(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
