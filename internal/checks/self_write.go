package checks

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/state"
)

// selfWriteTTL bounds how long a CSM-performed write to a sensitive path
// suppresses the sensitive-file detectors. Short enough that an independent
// tamper layered on later is still caught by the next scan.
const selfWriteTTL = 15 * time.Minute

var (
	selfWriteMu  sync.Mutex
	selfWrites   = map[string]selfWriteRecord{}
	selfWriteNow = time.Now // overridable in tests

	// selfWriteStore persists self-write hashes across restarts. Nil in unit
	// tests and one-shot CLI runs, where the in-memory ledger is enough.
	selfWriteStore *state.Store
)

// selfWriteKey namespaces the durable record. The leading underscore marks it
// as housekeeping so the state sweeper never evicts it; the record is cleared
// explicitly by forgetSelfWrites, or superseded by the next write to the path.
func selfWriteKey(path string) string { return "_selfwrite:" + path }

// SetSelfWriteStore gives the self-write ledger somewhere durable to record
// what CSM wrote. Without it, a daemon restart -- or a crontab the cPanel
// wrapper reformats after CSM hands it over -- makes CSM's own write look like
// a third-party change to the sensitive-file detectors.
func SetSelfWriteStore(st *state.Store) {
	selfWriteMu.Lock()
	defer selfWriteMu.Unlock()
	selfWriteStore = st
}

type selfWriteRecord struct {
	hash    string
	expires time.Time
}

// RecordSelfWrite registers that CSM remediation just wrote content to a
// sensitive watched file. The sensitive-file detectors suppress a finding only
// when the file still holds exactly this content within the TTL, so a malicious
// change layered on top (different hash) is still reported -- this is not a path
// allowlist.
func RecordSelfWrite(path string, content []byte) {
	sum := sha256.Sum256(content)
	selfWriteMu.Lock()
	defer selfWriteMu.Unlock()
	now := selfWriteNow()
	pruneExpiredSelfWritesLocked(now)
	hash := hex.EncodeToString(sum[:])
	selfWrites[path] = selfWriteRecord{
		hash:    hash,
		expires: now.Add(selfWriteTTL),
	}
	if selfWriteStore != nil {
		selfWriteStore.SetRaw(selfWriteKey(path), hash)
	}
}

func forgetSelfWrites(paths ...string) {
	selfWriteMu.Lock()
	defer selfWriteMu.Unlock()
	for _, path := range paths {
		delete(selfWrites, path)
		if selfWriteStore != nil {
			selfWriteStore.DeleteRaw(selfWriteKey(path))
		}
	}
}

// isExpectedSelfWrite reports whether content at path is byte-identical to a
// CSM self-write recorded within the TTL. Expired entries are pruned and treated
// as not-expected.
func isExpectedSelfWrite(path string, content []byte) bool {
	selfWriteMu.Lock()
	defer selfWriteMu.Unlock()
	now := selfWriteNow()
	pruneExpiredSelfWritesLocked(now)
	sum := sha256.Sum256(content)
	got := hex.EncodeToString(sum[:])
	if rec, ok := selfWrites[path]; ok {
		return got == rec.hash
	}
	// The in-memory record is gone (expired, or lost with the last daemon).
	// The durable one has no TTL because it is content-bound: it suppresses
	// exactly the bytes CSM wrote and nothing else, so an edit layered on top
	// still reports no matter how much later it happens.
	if selfWriteStore == nil {
		return false
	}
	want, ok := selfWriteStore.GetRaw(selfWriteKey(path))
	return ok && want != "" && got == want
}

func pruneExpiredSelfWritesLocked(now time.Time) {
	for path, rec := range selfWrites {
		if now.After(rec.expires) {
			delete(selfWrites, path)
		}
	}
}
