package checks

import (
	"os"
	"sync"

	"github.com/pidginhost/csm/internal/store"
)

// Keep unpersisted progress while the daemon is alive. Otherwise one failed
// cursor write repeatedly spends the host's entire budget on the same account.
// Successful writes evict the fallback; account removal and database changes
// discard it too, so historical accounts cannot accumulate in memory.
var rollingContentCursors = phpContentCursors{}

type phpContentCursors struct {
	mu      sync.Mutex
	db      *store.DB
	pending map[string]store.ScanCursorRecord
}

func (c *phpContentCursors) resetLocked(db *store.DB) {
	if c.db != db {
		c.db = db
		c.pending = make(map[string]store.ScanCursorRecord)
	}
}

func (c *phpContentCursors) retain(db *store.DB, entries []os.DirEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resetLocked(db)
	live := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			live[entry.Name()] = true
		}
	}
	for account := range c.pending {
		if !live[account] {
			delete(c.pending, account)
		}
	}
}

func (c *phpContentCursors) load(db *store.DB, account string) (store.ScanCursorRecord, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resetLocked(db)
	cur, _, err := db.GetScanCursor(account, rollingScanCheck)
	if pending, ok := c.pending[account]; ok {
		return pending, err
	}
	return cur, err
}

func (c *phpContentCursors) save(db *store.DB, cur store.ScanCursorRecord) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resetLocked(db)
	if err := db.PutScanCursor(cur); err != nil {
		c.pending[cur.Account] = cur
		return err
	}
	delete(c.pending, cur.Account)
	return nil
}
