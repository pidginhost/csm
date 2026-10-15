package store

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// dryRunBlocksBucket holds examples of responses a dry run would have run:
// the legacy firewall writer's and, while an admission owner runs blocks,
// the owner's forecast examples (spec 3.6). Its count is a count of the
// retained examples, not of addresses or predictions.
const dryRunBlocksBucket = "dry_run_blocks"

// Bounds of the forecast examples (spec 3.6).
const (
	maxDryRunBlocks = 20000
	// maxDryRunBatch bounds one write: one turn's examples.
	maxDryRunBatch = admission.MaxBatchMembers
	// maxDryRunMaintenance bounds the records one maintenance step visits
	// or deletes, cap trimming included.
	maxDryRunMaintenance = 256
	maxDryRunKeyBytes    = 128
	maxDryRunValueBytes  = 1024
)

// dryRunKeyTime is the fixed-width UTC time that leads a forecast example's
// key, so keys sort by time within the format.
const dryRunKeyTime = "2006-01-02T15:04:05.000000000Z"

// ErrDryRunBlocksFull refuses new examples while the bucket holds more than
// its cap, until maintenance trims it.
var ErrDryRunBlocksFull = errors.New("dry-run examples are above their cap")

var errNoStore = errors.New("the state database is not open")

// DryRunBlock is one example of a forecast pick that passed the modelled
// capacity checks: a preview, never a record of an applied block.
type DryRunBlock struct {
	// At is when the forecast predicted it.
	At time.Time
	// IP is the canonical address and Check the registered check that
	// asked for the response.
	IP, Check string
	Candidate admission.CandidateID
	// Session is the forecast session, 32 lowercase hex digits.
	Session string
	Kind    admission.Kind
	// ExpiresAt is when the response would have ended.
	ExpiresAt time.Time
}

type dryRunExampleRecord struct {
	IP          string `json:"ip"`
	Reason      string `json:"reason"`
	TimeoutSec  int64  `json:"timeout_sec"`
	CandidateID string `json:"candidate_id"`
	SessionID   string `json:"session_id"`
	Kind        string `json:"kind"`
	ExpiresAt   string `json:"expires_at"`
}

// encode validates b and returns its key and value.
func (b DryRunBlock) encode() (key, value []byte, err error) {
	at := b.At.UTC()
	addr, parseErr := netip.ParseAddr(b.IP)
	switch {
	case b.At.IsZero() || at.Year() < 1 || at.Year() > 9999:
		return nil, nil, errors.New("example time is out of range")
	case parseErr != nil || addr.String() != b.IP || addr.Zone() != "" || addr.Is4In6():
		return nil, nil, errors.New("example address is not canonical")
	case !checkText(b.Check):
		return nil, nil, errors.New("example reason is not a check name")
	case !lowerHexText(b.Session, 32):
		return nil, nil, errors.New("example session is malformed")
	case !b.Kind.Valid():
		return nil, nil, errors.New("example kind is unknown")
	case !b.ExpiresAt.After(b.At):
		return nil, nil, errors.New("example has no lifetime left")
	}
	if _, err = admission.ParseCandidateID(string(b.Candidate)); err != nil {
		return nil, nil, err
	}
	key = []byte(at.Format(dryRunKeyTime) + ":" + b.IP + ":" + string(b.Candidate))
	value, err = json.Marshal(dryRunExampleRecord{
		IP: b.IP, Reason: b.Check, TimeoutSec: int64(b.ExpiresAt.Sub(b.At) / time.Second),
		CandidateID: string(b.Candidate), SessionID: b.Session, Kind: b.Kind.String(),
		ExpiresAt: b.ExpiresAt.UTC().Format(time.RFC3339Nano),
	})
	switch {
	case err != nil:
		return nil, nil, err
	case len(key) > maxDryRunKeyBytes || len(value) > maxDryRunValueBytes:
		return nil, nil, fmt.Errorf("example is %d+%d bytes, above its bound", len(key), len(value))
	}
	return key, value, nil
}

// checkText reports whether s has the form of a registered check name.
func checkText(s string) bool {
	return s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyz0123456789_") == ""
}

func lowerHexText(s string, n int) bool {
	_, err := hex.DecodeString(s)
	return len(s) == n && err == nil && strings.ToLower(s) == s
}

// RecordDryRunBlocks writes one turn's forecast examples in one
// transaction, at most one batch. Every record is validated before anything
// is written, and a bad one refuses the batch. A full bucket makes room by
// evicting its first keys in key order, at most the batch's size; one above
// its cap takes nothing (ErrDryRunBlocksFull) until maintenance trims it.
func (db *DB) RecordDryRunBlocks(blocks []DryRunBlock) error {
	if db == nil || db.bolt == nil {
		return errNoStore
	}
	if len(blocks) > maxDryRunBatch {
		return fmt.Errorf("%d examples exceed one batch", len(blocks))
	}
	keys, values := make([][]byte, len(blocks)), make([][]byte, len(blocks))
	for i, b := range blocks {
		var err error
		if keys[i], values[i], err = b.encode(); err != nil {
			return err
		}
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte(dryRunBlocksBucket))
		if err != nil {
			return err
		}
		held := bucket.Stats().KeyN
		if held > maxDryRunBlocks {
			return ErrDryRunBlocksFull
		}
		fresh := map[string]bool{}
		for _, k := range keys {
			if bucket.Get(k) == nil {
				fresh[string(k)] = true
			}
		}
		var evict [][]byte
		c := bucket.Cursor()
		for k, _ := c.First(); k != nil && len(evict) < held+len(fresh)-maxDryRunBlocks; k, _ = c.Next() {
			evict = append(evict, append([]byte(nil), k...))
		}
		for _, k := range evict {
			if err = bucket.Delete(k); err != nil {
				return err
			}
		}
		for i, k := range keys {
			if err = bucket.Put(k, values[i]); err != nil {
				return err
			}
		}
		return nil
	})
}

// DryRunMaintenance is one bounded step of the pass that keeps the examples
// within their bounds.
type DryRunMaintenance struct {
	// Cursor is the last key the pass visited; nil starts a pass.
	Cursor []byte
	// Cutoff removes records whose key time is strictly before it. A key
	// whose time does not parse stays for the cap and purges to remove.
	Cutoff time.Time
	// Purge removes every record of a session other than Keep, legacy and
	// unreadable records included; with Keep empty it removes all.
	Purge bool
	Keep  string
}

// DryRunMaintained is what one step did.
type DryRunMaintained struct {
	// Next resumes the pass; Done is set once it has visited the last key.
	Next []byte
	Done bool
	// Visited counts the records the step read, Removed those it deleted.
	Visited, Removed int
}

// MaintainDryRunBlocks runs one step of the maintenance pass: at most 256
// records visited or deleted, first trimming a bucket above its cap from
// its first keys, then resuming the pass after Cursor. A read decides
// whether anything is due, so a step that removes nothing writes nothing.
// A failed step changes nothing; resume from the same cursor.
func (db *DB) MaintainDryRunBlocks(step DryRunMaintenance) (DryRunMaintained, error) {
	if db == nil || db.bolt == nil {
		return DryRunMaintained{}, errNoStore
	}
	var res DryRunMaintained
	var victims [][]byte
	plan := func(tx *bolt.Tx) error {
		res, victims = DryRunMaintained{Next: step.Cursor}, nil
		bucket := tx.Bucket([]byte(dryRunBlocksBucket))
		if bucket == nil {
			res.Done, res.Next = true, nil
			return nil
		}
		trimmed := map[string]bool{}
		c := bucket.Cursor()
		over := bucket.Stats().KeyN - maxDryRunBlocks
		for k, _ := c.First(); k != nil && over > 0 && res.Visited < maxDryRunMaintenance; k, _ = c.Next() {
			victims, trimmed[string(k)] = append(victims, append([]byte(nil), k...)), true
			over--
			res.Visited++
		}
		k, v := c.First()
		if step.Cursor != nil {
			if k, v = c.Seek(step.Cursor); k != nil && string(k) == string(step.Cursor) {
				k, v = c.Next()
			}
		}
		for ; k != nil && res.Visited < maxDryRunMaintenance; k, v = c.Next() {
			if trimmed[string(k)] {
				continue
			}
			res.Visited++
			res.Next = append([]byte(nil), k...)
			if dryRunKeyBefore(k, step.Cutoff) || (step.Purge && dryRunSession(v) != step.Keep) {
				victims = append(victims, res.Next)
			}
		}
		if k == nil {
			res.Done, res.Next = true, nil
		}
		return nil
	}
	if err := db.bolt.View(plan); err != nil || len(victims) == 0 {
		return res, err
	}
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		if err := plan(tx); err != nil {
			return err
		}
		bucket := tx.Bucket([]byte(dryRunBlocksBucket))
		for _, k := range victims {
			if err := bucket.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return DryRunMaintained{}, err
	}
	res.Removed = len(victims)
	return res, nil
}

// dryRunKeyBefore reports whether key's time, legacy or forecast form,
// parses and is strictly before cutoff.
func dryRunKeyBefore(key []byte, cutoff time.Time) bool {
	at, ok := dryRunKeyAt(string(key))
	return ok && at.Before(cutoff)
}

// dryRunKeyAt parses the UTC time that leads a key. Both writers end it
// with Z, and an IPv6 address after it contains colons, so the first "Z:"
// ends the time.
func dryRunKeyAt(key string) (time.Time, bool) {
	end := strings.Index(key, "Z:")
	if end < 0 {
		return time.Time{}, false
	}
	at, err := time.Parse(time.RFC3339Nano, key[:end+1])
	return at, err == nil
}

// dryRunSession is a record's forecast session, empty for a legacy or
// unreadable one.
func dryRunSession(value []byte) string {
	var rec struct {
		SessionID string `json:"session_id"`
	}
	if json.Unmarshal(value, &rec) != nil {
		return ""
	}
	return rec.SessionID
}
