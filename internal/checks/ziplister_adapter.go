package checks

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/crashsample"
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

	crashSamplesMu sync.RWMutex
	crashSamples   *crashsample.Store
)

// SetCrashSamples installs the store that keeps zips which crash the parse
// worker. Nil, the default, keeps none.
func SetCrashSamples(s *crashsample.Store) {
	crashSamplesMu.Lock()
	defer crashSamplesMu.Unlock()
	crashSamples = s
}

// saveZipCrashSample keeps a copy of a zip that made the worker fail, when
// crash samples are on. A failed save changes nothing else.
func saveZipCrashSample(sum string, f *os.File, size int64) {
	crashSamplesMu.RLock()
	store := crashSamples
	crashSamplesMu.RUnlock()
	if store == nil {
		return
	}
	if err := store.Save("zip-"+sum, []crashsample.File{{Name: "archive.zip", Src: f, Size: size}}); err != nil {
		fmt.Fprintf(os.Stderr, "[%s] phishing: keeping crash sample of zip %s: %v\n", time.Now().Format("2006-01-02 15:04:05"), sum, err)
	}
}

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
