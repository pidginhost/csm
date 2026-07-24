package checks

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/state"
)

// selfWriteTTL bounds how long a CSM-performed write to a sensitive path
// suppresses the sensitive-file detectors. Short enough that an independent
// tamper layered on later is still caught by the next scan.
const selfWriteTTL = 15 * time.Minute
const durableSelfWriteVersion = 1

var (
	selfWriteMu  sync.Mutex
	selfWrites   = map[string]selfWriteRecord{}
	selfWriteNow = time.Now // overridable in tests

	// selfWriteStore persists self-write content and file identity across
	// restarts. Nil in unit tests and one-shot CLI runs, where the in-memory
	// ledger is enough.
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
	hash     string
	identity *selfWriteFileIdentity
	expires  time.Time
}

type selfWriteFileIdentity struct {
	Device     uint64 `json:"device"`
	Inode      uint64 `json:"inode"`
	ChangeSec  int64  `json:"change_sec"`
	ChangeNsec int64  `json:"change_nsec"`
}

type durableSelfWriteRecord struct {
	Version  int                   `json:"version"`
	Hash     string                `json:"hash"`
	Identity selfWriteFileIdentity `json:"identity"`
}

// RecordSelfWrite registers that CSM remediation just wrote content to a
// sensitive watched file. A current file is also recorded durably with its
// identity; a provisional record made before the write stays memory-only.
func RecordSelfWrite(path string, content []byte) {
	sum := sha256.Sum256(content)
	hash := hex.EncodeToString(sum[:])
	identity, hasIdentity := currentSelfWriteIdentity(path, content)

	selfWriteMu.Lock()
	defer selfWriteMu.Unlock()
	now := selfWriteNow()
	pruneExpiredSelfWritesLocked(now)
	rec := selfWriteRecord{
		hash:    hash,
		expires: now.Add(selfWriteTTL),
	}
	if hasIdentity {
		rec.identity = &identity
	}
	selfWrites[path] = rec

	if selfWriteStore != nil && hasIdentity {
		// Marshal of a fixed struct of scalars cannot fail; if it somehow did,
		// losing the durable record costs a redundant finding, not safety, so
		// remediation must not die here.
		raw, err := json.Marshal(durableSelfWriteRecord{
			Version:  durableSelfWriteVersion,
			Hash:     hash,
			Identity: identity,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "self-write: encode %s: %v\n", path, err)
			return
		}
		if err := selfWriteStore.SetRawAndSave(selfWriteKey(path), string(raw)); err != nil {
			fmt.Fprintf(os.Stderr, "self-write: persist %s: %v\n", path, err)
		}
	}
}

func forgetSelfWrites(paths ...string) {
	selfWriteMu.Lock()
	defer selfWriteMu.Unlock()
	for _, path := range paths {
		delete(selfWrites, path)
		if selfWriteStore != nil {
			if err := selfWriteStore.DeleteRawAndSave(selfWriteKey(path)); err != nil {
				fmt.Fprintf(os.Stderr, "self-write: forget %s: %v\n", path, err)
			}
		}
	}
}

// isExpectedSelfWrite reports whether content and file identity still match a
// CSM self-write. Provisional in-memory records expire; identity-bound durable
// records do not.
func isExpectedSelfWrite(path string, content []byte) bool {
	selfWriteMu.Lock()
	defer selfWriteMu.Unlock()
	now := selfWriteNow()
	pruneExpiredSelfWritesLocked(now)
	sum := sha256.Sum256(content)
	got := hex.EncodeToString(sum[:])
	if rec, ok := selfWrites[path]; ok {
		if got != rec.hash {
			return false
		}
		// A provisional record is installed immediately before CSM invokes
		// crontab so a synchronous filesystem event can be suppressed. Once
		// the write finishes, RecordSelfWrite replaces it with file identity.
		if rec.identity == nil {
			return len(content) > 0
		}
		identity, ok := currentSelfWriteIdentity(path, content)
		return ok && identity == *rec.identity
	}
	if selfWriteStore == nil {
		return false
	}
	raw, ok := selfWriteStore.GetRaw(selfWriteKey(path))
	if !ok {
		return false
	}
	var want durableSelfWriteRecord
	if err := json.Unmarshal([]byte(raw), &want); err != nil ||
		want.Version != durableSelfWriteVersion ||
		want.Hash == "" ||
		got != want.Hash {
		return false
	}
	identity, ok := currentSelfWriteIdentity(path, content)
	return ok && identity == want.Identity
}

func pruneExpiredSelfWritesLocked(now time.Time) {
	for path, rec := range selfWrites {
		if now.After(rec.expires) {
			delete(selfWrites, path)
		}
	}
}

func currentSelfWriteIdentity(path string, content []byte) (selfWriteFileIdentity, bool) {
	f, err := osFS.Open(path)
	if err != nil {
		return selfWriteFileIdentity{}, false
	}
	defer func() { _ = f.Close() }()

	got, err := io.ReadAll(io.LimitReader(f, int64(len(content))+1))
	if err != nil || !bytes.Equal(got, content) {
		return selfWriteFileIdentity{}, false
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return selfWriteFileIdentity{}, false
	}
	return selfWriteIdentityFromFileInfo(info)
}
