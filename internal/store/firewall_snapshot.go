package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/pidginhost/csm/internal/firewall"
	bolt "go.etcd.io/bbolt"
)

var _ firewall.StateStore = (*DB)(nil)

const firewallSnapshotBucket = "fw:state"
const firewallSnapshotKey = "snapshot"
const firewallSnapshotVersion = 1

// Fixed collection order is part of the versioned storage format. Metadata
// lives under fw:* so a future atomic firewall restore can include it.
var firewallSnapshotBuckets = [...]string{"fw:blocked", "fw:subnets", "fw:allowed", "fw:port_allowed"}

type firewallCollection struct {
	// Keys preserve engine order, including distinct entries for the same IP.
	// Nil and empty keys preserve nil and empty domain slices respectively.
	Keys   []string `json:"keys"`
	Digest string   `json:"sha256"`
}

type firewallSnapshotMeta struct {
	Version     int                  `json:"version"`
	Revision    uint64               `json:"revision"`
	Collections []firewallCollection `json:"collections"`
}

type firewallSnapshotRows [4][][]byte

// ReadFirewallState copies a single consistent snapshot before decoding domain
// values. No bbolt-owned bytes or partially decoded state escape this method.
func (db *DB) ReadFirewallState() (result firewall.FirewallState, revision uint64, err error) {
	started := time.Now()
	defer func() {
		firewallReadDuration.Observe(time.Since(started).Seconds())
		if err != nil {
			firewallReadFailures.Inc()
		}
	}()
	var meta firewallSnapshotMeta
	var rows firewallSnapshotRows
	err = db.bolt.View(func(tx *bolt.Tx) error {
		var readErr error
		meta, readErr = readFirewallSnapshotMeta(tx)
		if readErr != nil {
			return readErr
		}
		rows, readErr = readFirewallSnapshotRows(tx, meta)
		return readErr
	})
	if err != nil {
		return firewall.FirewallState{}, 0, err
	}
	state, err := decodeFirewallSnapshot(rows, meta)
	if err != nil {
		return firewall.FirewallState{}, 0, err
	}
	return state, meta.Revision, nil
}

// ReplaceFirewallState encodes outside the writer lock and publishes state and
// revision together. Existing runtime callers continue using their current
// backend; this API is not an implicit migration or a cutover marker.
func (db *DB) ReplaceFirewallState(expectedRevision uint64, state firewall.FirewallState) (revision uint64, err error) {
	defer func() { recordFirewallWriteError(err) }()
	if expectedRevision == math.MaxUint64 {
		return 0, fmt.Errorf("%w: revision exhausted", firewall.ErrStateConflict)
	}
	meta, rows, err := encodeFirewallSnapshot(state)
	if err != nil {
		return 0, err
	}
	meta.Revision = expectedRevision + 1
	encoded, err := json.Marshal(meta)
	if err != nil {
		return 0, err
	}
	err = db.updateFirewallSnapshot(len(state.Blocked)+len(state.BlockedNet)+len(state.Allowed)+len(state.PortAllowed), func(tx *bolt.Tx) error {
		return replaceFirewallSnapshot(tx, expectedRevision, meta, rows, encoded)
	})
	if err != nil {
		return 0, err
	}
	return meta.Revision, nil
}

// replaceFirewallSnapshot is private so future action admission can share this
// transaction without exporting CRUD or transaction callbacks to domain code.
func replaceFirewallSnapshot(tx *bolt.Tx, expected uint64, next firewallSnapshotMeta, rows firewallSnapshotRows, encoded []byte) error {
	current, metaErr := readFirewallSnapshotMeta(tx)
	if metaErr == firewall.ErrStateUninitialized {
		if expected != 0 {
			return firewall.ErrStateConflict
		}
	} else {
		if metaErr != nil {
			return metaErr
		}
		if current.Revision != expected {
			return firewall.ErrStateConflict
		}
		// An out-of-band legacy bucket write cannot silently bypass the revision.
		currentRows, readErr := readFirewallSnapshotRows(tx, current)
		if readErr != nil {
			return readErr
		}
		if _, err := decodeFirewallSnapshot(currentRows, current); err != nil {
			return err
		}
	}
	for i, name := range firewallSnapshotBuckets {
		if tx.Bucket([]byte(name)) != nil {
			if err := tx.DeleteBucket([]byte(name)); err != nil {
				return err
			}
		}
		b, err := tx.CreateBucket([]byte(name))
		if err != nil {
			return err
		}
		for j, key := range next.Collections[i].Keys {
			if err := b.Put([]byte(key), rows[i][j]); err != nil {
				return err
			}
		}
	}
	b, err := tx.CreateBucketIfNotExists([]byte(firewallSnapshotBucket))
	if err != nil {
		return err
	}
	return b.Put([]byte(firewallSnapshotKey), encoded)
}

func readFirewallSnapshotMeta(tx *bolt.Tx) (firewallSnapshotMeta, error) {
	var meta firewallSnapshotMeta
	b := tx.Bucket([]byte(firewallSnapshotBucket))
	if b == nil {
		return meta, firewall.ErrStateUninitialized
	}
	raw := b.Get([]byte(firewallSnapshotKey))
	if raw == nil {
		return meta, fmt.Errorf("%w: missing metadata", firewall.ErrStateCorrupt)
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		return meta, fmt.Errorf("%w: metadata decode: %v", firewall.ErrStateCorrupt, err)
	}
	if meta.Version != firewallSnapshotVersion || meta.Revision == 0 || len(meta.Collections) != len(firewallSnapshotBuckets) {
		return meta, fmt.Errorf("%w: metadata version, revision or collections", firewall.ErrStateCorrupt)
	}
	return meta, nil
}

func readFirewallSnapshotRows(tx *bolt.Tx, meta firewallSnapshotMeta) (firewallSnapshotRows, error) {
	var rows firewallSnapshotRows
	for i, name := range firewallSnapshotBuckets {
		b := tx.Bucket([]byte(name))
		if b == nil {
			return rows, fmt.Errorf("%w: missing collection %s", firewall.ErrStateCorrupt, name)
		}
		collection := meta.Collections[i]
		expected := make(map[string]struct{}, len(collection.Keys))
		for _, key := range collection.Keys {
			if _, exists := expected[key]; exists || key == "" {
				return rows, fmt.Errorf("%w: invalid collection keys", firewall.ErrStateCorrupt)
			}
			expected[key] = struct{}{}
			raw := b.Get([]byte(key))
			if raw == nil {
				return rows, fmt.Errorf("%w: missing row in %s", firewall.ErrStateCorrupt, name)
			}
			rows[i] = append(rows[i], bytes.Clone(raw))
		}
		if err := b.ForEach(func(k, v []byte) error {
			if _, ok := expected[string(k)]; !ok || v == nil {
				return fmt.Errorf("%w: unexpected row in %s", firewall.ErrStateCorrupt, name)
			}
			return nil
		}); err != nil {
			return rows, err
		}
		if digestFirewallCollection(collection.Keys, rows[i]) != collection.Digest {
			return rows, fmt.Errorf("%w: changed collection %s", firewall.ErrStateCorrupt, name)
		}
	}
	return rows, nil
}

func digestFirewallCollection(keys []string, rows [][]byte) string {
	hash := sha256.New()
	var size [8]byte
	for i, key := range keys {
		binary.BigEndian.PutUint64(size[:], uint64(len(key)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write([]byte(key))
		binary.BigEndian.PutUint64(size[:], uint64(len(rows[i])))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write(rows[i])
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func encodeFirewallSnapshot(state firewall.FirewallState) (firewallSnapshotMeta, firewallSnapshotRows, error) {
	meta := firewallSnapshotMeta{Version: firewallSnapshotVersion, Collections: make([]firewallCollection, 4)}
	var rows firewallSnapshotRows
	var err error
	meta.Collections[0], rows[0], err = encodeFirewallCollection(state.Blocked, func(e firewall.BlockedEntry) string { return e.IP })
	if err != nil {
		return meta, rows, err
	}
	meta.Collections[1], rows[1], err = encodeFirewallCollection(state.BlockedNet, func(e firewall.SubnetEntry) string { return e.CIDR })
	if err != nil {
		return meta, rows, err
	}
	meta.Collections[2], rows[2], err = encodeFirewallCollection(state.Allowed, func(e firewall.AllowedEntry) string { return e.IP })
	if err != nil {
		return meta, rows, err
	}
	meta.Collections[3], rows[3], err = encodeFirewallCollection(state.PortAllowed, func(e firewall.PortAllowEntry) string { return portAllowKey(e.IP, e.Port, e.Proto) })
	return meta, rows, err
}

func encodeFirewallCollection[T any](entries []T, identity func(T) string) (firewallCollection, [][]byte, error) {
	var collection firewallCollection
	var rows [][]byte
	if entries != nil {
		collection.Keys = make([]string, 0, len(entries))
	}
	used := make(map[string]bool, len(entries))
	for i, entry := range entries {
		key := identity(entry)
		if key == "" || used[key] {
			key = fmt.Sprintf("\x00%d", i)
		}
		if used[key] {
			return collection, nil, fmt.Errorf("invalid firewall row identity")
		}
		used[key] = true
		if !validFirewallRowEncoding(entry) {
			return collection, nil, fmt.Errorf("firewall row cannot be encoded losslessly")
		}
		row, err := json.Marshal(entry)
		if err != nil {
			return collection, nil, fmt.Errorf("encode firewall row: %w", err)
		}
		collection.Keys = append(collection.Keys, key)
		rows = append(rows, row)
	}
	collection.Digest = digestFirewallCollection(collection.Keys, rows)
	return collection, rows, nil
}

func decodeFirewallSnapshot(rows firewallSnapshotRows, meta firewallSnapshotMeta) (firewall.FirewallState, error) {
	var state firewall.FirewallState
	var err error
	state.Blocked, err = decodeFirewallCollection[firewall.BlockedEntry](rows[0], meta.Collections[0].Keys != nil)
	if err != nil {
		return firewall.FirewallState{}, err
	}
	state.BlockedNet, err = decodeFirewallCollection[firewall.SubnetEntry](rows[1], meta.Collections[1].Keys != nil)
	if err != nil {
		return firewall.FirewallState{}, err
	}
	state.Allowed, err = decodeFirewallCollection[firewall.AllowedEntry](rows[2], meta.Collections[2].Keys != nil)
	if err != nil {
		return firewall.FirewallState{}, err
	}
	state.PortAllowed, err = decodeFirewallCollection[firewall.PortAllowEntry](rows[3], meta.Collections[3].Keys != nil)
	if err != nil {
		return firewall.FirewallState{}, err
	}
	return state, nil
}

func decodeFirewallCollection[T any](rows [][]byte, nonNil bool) ([]T, error) {
	var entries []T
	if nonNil {
		entries = make([]T, 0, len(rows))
	}
	for _, row := range rows {
		var entry T
		// A matching checksum does not make malformed text decodable. JSON
		// silently replaces invalid Unicode, which would alter stored evidence.
		if !validFirewallJSONText(row) {
			return nil, fmt.Errorf("%w: row is not valid Unicode", firewall.ErrStateCorrupt)
		}
		trimmed := bytes.TrimSpace(row)
		if len(trimmed) == 0 || trimmed[0] != '{' {
			return nil, fmt.Errorf("%w: row is not an object", firewall.ErrStateCorrupt)
		}
		if err := json.Unmarshal(row, &entry); err != nil {
			return nil, fmt.Errorf("%w: row decode: %v", firewall.ErrStateCorrupt, err)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// The JSON decoder checks syntax but accepts invalid UTF-8 and unpaired UTF-16
// surrogate escapes. Check those first without rejecting literal backslashes
// or valid surrogate pairs. Non-Unicode escapes are left to the JSON decoder.
func validFirewallJSONText(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		code, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil || code >= 0xdc00 && code <= 0xdfff {
			return false
		}
		i += 4
		if code < 0xd800 || code > 0xdbff {
			continue
		}
		if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
			return false
		}
		low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
		if err != nil || low < 0xdc00 || low > 0xdfff {
			return false
		}
		i += 6
	}
	return true
}

// encoding/json replaces invalid UTF-8 and rounds timezone offsets to minutes.
// Reject either loss before a successful write can acknowledge altered evidence.
func validFirewallRowEncoding(entry any) bool {
	var fields []string
	var times []time.Time
	switch e := entry.(type) {
	case firewall.BlockedEntry:
		times = []time.Time{e.BlockedAt, e.ExpiresAt}
		fields = []string{e.IP, e.Reason, e.Source}
	case firewall.SubnetEntry:
		times = []time.Time{e.BlockedAt, e.ExpiresAt}
		fields = []string{e.CIDR, e.Reason, e.Source}
	case firewall.AllowedEntry:
		times = []time.Time{e.ExpiresAt}
		fields = []string{e.IP, e.Reason, e.Source}
	case firewall.PortAllowEntry:
		fields = []string{e.IP, e.Proto, e.Reason, e.Source}
	default:
		return false
	}
	for _, timestamp := range times {
		_, offset := timestamp.Zone()
		if offset%60 != 0 {
			return false
		}
	}
	for _, field := range fields {
		if !utf8.ValidString(field) {
			return false
		}
	}
	return true
}
