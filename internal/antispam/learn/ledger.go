package learn

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// ErrStateMismatch: the ledger does not belong to the current hash keys and
// storage, or holds records without a binding (spec 10 state_mismatch).
var ErrStateMismatch = errors.New("learning ledger does not match the current storage")

const bindingKey = "binding"

// kv is the store's learning transaction API; tests wrap it to inject
// commit failures.
type kv interface {
	LearnUpdate(func(store.LearnTx) error) error
	LearnView(func(store.LearnTx) error) error
}

// Ledger owns the learning buckets. Only the engine writes it.
type Ledger struct {
	db kv
}

// Open returns the ledger stored in db.
func Open(db *store.DB) *Ledger {
	return &Ledger{db: db}
}

// LedgerView reads the ledger.
type LedgerView struct {
	tx store.LearnTx
}

// LedgerTx reads and writes the ledger in one transaction.
type LedgerTx struct {
	LedgerView
}

// View runs fn in a read-only transaction.
func (l *Ledger) View(fn func(LedgerView) error) error {
	return l.db.LearnView(func(tx store.LearnTx) error { return fn(LedgerView{tx: tx}) })
}

// Update runs fn in one read-write transaction; an error rolls it back.
func (l *Ledger) Update(fn func(LedgerTx) error) error {
	return l.db.LearnUpdate(func(tx store.LearnTx) error { return fn(LedgerTx{LedgerView{tx: tx}}) })
}

// Bind records the hash generation and prefix on first use and refuses a
// different one later. Records without a binding are ErrStateMismatch: they
// belong to storage CSM can no longer identify.
func (l *Ledger) Bind(gen, prefix string) error {
	if gen == "" || prefix == "" {
		return errors.New("learning binding needs a hash generation and prefix")
	}
	return l.Update(func(tx LedgerTx) error {
		b, ok, err := tx.Binding()
		if err != nil {
			return err
		}
		if ok {
			if b.HashGeneration != gen || b.Prefix != prefix {
				return ErrStateMismatch
			}
			return nil
		}
		for _, name := range store.LearnBuckets {
			empty := true
			if err := tx.tx.ForEach(name, func(_, _ []byte) error { empty = false; return errStop }); err != nil && !errors.Is(err, errStop) {
				return err
			}
			if !empty {
				return ErrStateMismatch
			}
		}
		return tx.put(store.LearnMetaBucket, []byte(bindingKey), Binding{HashGeneration: gen, Prefix: prefix, Created: time.Now().UTC()})
	})
}

var errStop = errors.New("stop")

func clusterKey(id uint64) []byte { return binary.BigEndian.AppendUint64(nil, id) }

func usageKey(uid int, operator bool) []byte {
	if operator {
		return []byte("operator")
	}
	return []byte("uid:" + strconv.Itoa(uid))
}

// get decodes the record at key; ok is false when it is absent.
func (v LedgerView) get(bucket string, key []byte, out any) (bool, error) {
	data, err := v.tx.Get(bucket, key)
	if err != nil || data == nil {
		return false, err
	}
	if err := json.Unmarshal(data, out); err != nil {
		return false, fmt.Errorf("learning ledger record in %s is unreadable", bucket)
	}
	return true, nil
}

func (tx LedgerTx) put(bucket string, key []byte, rec any) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return tx.tx.Put(bucket, key, data)
}

// Binding returns the stored binding.
func (v LedgerView) Binding() (Binding, bool, error) {
	var b Binding
	ok, err := v.get(store.LearnMetaBucket, []byte(bindingKey), &b)
	return b, ok, err
}

// Cluster returns cluster id.
func (v LedgerView) Cluster(id uint64) (Cluster, bool, error) {
	var c Cluster
	ok, err := v.get(store.LearnClustersBucket, clusterKey(id), &c)
	return c, ok, err
}

// Alias returns the cluster an accepted alias belongs to.
func (v LedgerView) Alias(d Digest) (uint64, bool, error) {
	data, err := v.tx.Get(store.LearnAliasesBucket, []byte(d))
	if err != nil || data == nil {
		return 0, false, err
	}
	if len(data) != 8 {
		return 0, false, errors.New("learning ledger alias is unreadable")
	}
	return binary.BigEndian.Uint64(data), true, nil
}

// Target returns the current target of d.
func (v LedgerView) Target(d Digest) (Target, bool, error) {
	var t Target
	ok, err := v.get(store.LearnTargetsBucket, []byte(d), &t)
	return t, ok, err
}

// Intent returns intent id.
func (v LedgerView) Intent(id string) (Intent, bool, error) {
	var i Intent
	ok, err := v.get(store.LearnIntentsBucket, []byte(id), &i)
	return i, ok, err
}

// Op returns the operator request record.
func (v LedgerView) Op(requestID string) (OpRecord, bool, error) {
	var o OpRecord
	ok, err := v.get(store.LearnOpsBucket, []byte(requestID), &o)
	return o, ok, err
}

// Usage returns what an account (or the operator) has been charged.
func (v LedgerView) Usage(uid int, operator bool) (Usage, error) {
	var u Usage
	_, err := v.get(store.LearnUsageBucket, usageKey(uid, operator), &u)
	return u, err
}

// NextClusterID allocates a cluster ID; IDs are never reused.
func (tx LedgerTx) NextClusterID() (uint64, error) {
	return tx.tx.NextSequence(store.LearnClustersBucket)
}

// PutCluster stores c.
func (tx LedgerTx) PutCluster(c Cluster) error {
	if c.ID == 0 {
		return errors.New("cluster has no ID")
	}
	return tx.put(store.LearnClustersBucket, clusterKey(c.ID), c)
}

// DeleteCluster removes cluster id.
func (tx LedgerTx) DeleteCluster(id uint64) error {
	return tx.tx.Delete(store.LearnClustersBucket, clusterKey(id))
}

// PutAlias maps an accepted alias to its cluster.
func (tx LedgerTx) PutAlias(d Digest, clusterID uint64) error {
	return tx.tx.Put(store.LearnAliasesBucket, []byte(d), clusterKey(clusterID))
}

// DeleteAlias removes an alias.
func (tx LedgerTx) DeleteAlias(d Digest) error {
	return tx.tx.Delete(store.LearnAliasesBucket, []byte(d))
}

// PutTarget stores the current target of t.Digest.
func (tx LedgerTx) PutTarget(t Target) error {
	return tx.put(store.LearnTargetsBucket, []byte(t.Digest), t)
}

// PutIntent stores i.
func (tx LedgerTx) PutIntent(i Intent) error {
	return tx.put(store.LearnIntentsBucket, []byte(i.ID), i)
}

// DeleteIntent removes intent id.
func (tx LedgerTx) DeleteIntent(id string) error {
	return tx.tx.Delete(store.LearnIntentsBucket, []byte(id))
}

// PutOp stores an operator request record.
func (tx LedgerTx) PutOp(o OpRecord) error {
	return tx.put(store.LearnOpsBucket, []byte(o.RequestID), o)
}

// AddUsage adds delta (which may be negative) to an account's charge.
func (tx LedgerTx) AddUsage(uid int, operator bool, delta Usage) error {
	u, err := tx.Usage(uid, operator)
	if err != nil {
		return err
	}
	u.BodyBytes += delta.BodyBytes
	u.Aliases += delta.Aliases
	if u.BodyBytes < 0 || u.Aliases < 0 {
		return errors.New("learning usage would go negative")
	}
	return tx.put(store.LearnUsageBucket, usageKey(uid, operator), u)
}

// Reserve stores a new intent and charges its admission once. A retry with
// an existing intent ID charges nothing and returns the stored intent.
func (tx LedgerTx) Reserve(i Intent, uid int, operator bool, charge Usage) (Intent, error) {
	stored, ok, err := tx.Intent(i.ID)
	if err != nil || ok {
		return stored, err
	}
	if err := tx.AddUsage(uid, operator, charge); err != nil {
		return Intent{}, err
	}
	return i, tx.PutIntent(i)
}
