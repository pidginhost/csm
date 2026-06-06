package checks

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// selfWriteTTL bounds how long a CSM-performed write to a sensitive path
// suppresses the sensitive-file detectors. Short enough that an independent
// tamper layered on later is still caught by the next scan.
const selfWriteTTL = 15 * time.Minute

var (
	selfWriteMu  sync.Mutex
	selfWrites   = map[string]selfWriteRecord{}
	selfWriteNow = time.Now // overridable in tests
)

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
	selfWrites[path] = selfWriteRecord{
		hash:    hex.EncodeToString(sum[:]),
		expires: selfWriteNow().Add(selfWriteTTL),
	}
}

// isExpectedSelfWrite reports whether content at path is byte-identical to a
// CSM self-write recorded within the TTL. Expired entries are pruned and treated
// as not-expected.
func isExpectedSelfWrite(path string, content []byte) bool {
	selfWriteMu.Lock()
	defer selfWriteMu.Unlock()
	rec, ok := selfWrites[path]
	if !ok {
		return false
	}
	if selfWriteNow().After(rec.expires) {
		delete(selfWrites, path)
		return false
	}
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:]) == rec.hash
}
