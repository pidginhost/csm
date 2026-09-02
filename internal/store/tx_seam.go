package store

import (
	"fmt"
	"os"

	bolt "go.etcd.io/bbolt"
)

// boltUpdate runs fn in a read-write transaction. A variable so tests can
// make the commit fail after fn has run, which is the failure the prune
// helpers must report honestly.
var boltUpdate = func(b *bolt.DB, fn func(*bolt.Tx) error) error {
	return b.Update(fn)
}

// committedCount turns a per-transaction deletion count into what actually
// happened: a transaction that failed to commit removed nothing, whatever
// the loop inside it counted.
func committedCount(what string, err error, removed int) int {
	if err != nil {
		fmt.Fprintf(os.Stderr, "store: %s prune failed to commit, %d row(s) kept: %v\n", what, removed, err)
		return 0
	}
	return removed
}
