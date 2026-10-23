package checks

import (
	"context"
	"os"

	"github.com/pidginhost/csm/internal/parseworker"
)

// inProcessZipLister walks the zip with the same code the parse worker runs,
// so the classification tests need no worker process.
type inProcessZipLister struct{}

func (inProcessZipLister) ListZip(ctx context.Context, zip *os.File, size int64, maxDirBytes uint64, visit func(name string, dir bool) error) error {
	return parseworker.ListEntries(ctx, zip, size, maxDirBytes, visit)
}
