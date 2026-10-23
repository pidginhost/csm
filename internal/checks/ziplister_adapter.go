package checks

import (
	"context"
	"os"
	"sync"

	"github.com/pidginhost/csm/internal/workerproc"
)

// ZipLister lists a tenant zip's entries in a process the daemon can kill.
// The daemon supplies one; there is no in-process fallback.
type ZipLister interface {
	ListZip(ctx context.Context, zip *os.File, size int64, maxDirBytes uint64, visit func(name string, dir bool) error) error
}

var (
	zipListerMu sync.RWMutex
	zipLister   ZipLister

	// zipStrikes remembers, by SHA-256, zips that made the worker fail.
	zipStrikes = workerproc.NewStrikes()
)

// SetZipLister installs the supervised lister. Passing nil removes it, after
// which phishing-kit zips are reported as not checked.
func SetZipLister(l ZipLister) {
	zipListerMu.Lock()
	defer zipListerMu.Unlock()
	zipLister = l
}

func currentZipLister() ZipLister {
	zipListerMu.RLock()
	defer zipListerMu.RUnlock()
	return zipLister
}
