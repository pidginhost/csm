package daemon

import (
	"fmt"
	"os"
	"sync"

	"github.com/pidginhost/csm/internal/integrity"
)

// hashBinary hashes the daemon binary; a var so tests can count reads.
var hashBinary = integrity.HashFile

// binaryHashCache keeps the running binary's hash until the file changes,
// so the status API does not read the whole binary on every poll.
type binaryHashCache struct {
	mu   sync.Mutex
	key  string
	hash string
}

func (c *binaryHashCache) get(path string) string {
	before, err := os.Stat(path)
	if err != nil {
		return ""
	}
	key := binaryFileKey(before)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hash != "" && key == c.key {
		return c.hash
	}
	h, err := hashBinary(path)
	if err != nil {
		return ""
	}
	// A file replaced while it was read gives a hash of neither version
	// for certain; report it but do not keep it.
	if after, err := os.Stat(path); err != nil || binaryFileKey(after) != key {
		return h
	}
	c.key, c.hash = key, h
	return h
}

// binaryFileKey changes when the file at a path is replaced or rewritten.
func binaryFileKey(info os.FileInfo) string {
	return fmt.Sprintf("%d:%d:%s", info.Size(), info.ModTime().UnixNano(), fileChangeIdentity(info))
}
