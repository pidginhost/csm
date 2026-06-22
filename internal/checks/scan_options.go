package checks

import (
	"context"

	"github.com/pidginhost/csm/internal/config"
)

// AccountScanOptions controls how RunAccountScanWithOptions enumerates and
// content-scans an account. The zero value is NOT the default: MaxFiles 0 means
// uncapped. Callers use DefaultAccountScanOptions for normal behaviour.
type AccountScanOptions struct {
	MaxFiles       int   // 0 = uncapped path ranking
	ForceContent   bool  // true = bypass clean-file content caches
	ForceFileIndex bool  // true = bypass file-index dir mtime cache, do not write live index
	RespectIgnores bool  // false = also scan suppressions.ignore_paths
	MaxFileBytes   int64 // 0 = use each check's existing per-file limit
}

// DefaultAccountScanOptions returns the options that reproduce today's
// RunAccountScan behaviour. All callers that want the existing cap and cache
// semantics should use this rather than constructing AccountScanOptions directly.
func DefaultAccountScanOptions(cfg *config.Config) AccountScanOptions {
	return AccountScanOptions{
		MaxFiles:       effectiveAccountScanMaxFiles(cfg),
		ForceContent:   false,
		ForceFileIndex: false,
		RespectIgnores: true,
		MaxFileBytes:   0,
	}
}

type scanOptionsKey struct{}

// ContextWithScanOptions attaches opts to ctx so that helpers called during a
// scan can read the active options without threading a parameter through every
// call site. Use ScanOptionsFromContext to retrieve them.
func ContextWithScanOptions(ctx context.Context, opts AccountScanOptions) context.Context {
	return context.WithValue(ctx, scanOptionsKey{}, opts)
}

// ScanOptionsFromContext retrieves the AccountScanOptions stored by
// ContextWithScanOptions. ok is false when the context carries no options,
// which callers should treat as "use defaults".
func ScanOptionsFromContext(ctx context.Context) (AccountScanOptions, bool) {
	opts, ok := ctx.Value(scanOptionsKey{}).(AccountScanOptions)
	return opts, ok
}
