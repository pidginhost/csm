package checks

import (
	"context"

	"github.com/pidginhost/csm/internal/config"
)

// scanForceContent reports whether the current scan should bypass the
// clean-file content cache (phpcontentcache.json). True only when ctx carries
// AccountScanOptions with ForceContent=true, i.e. an explicit full-scan audit.
// Normal scheduled scans and any context without options return false.
func scanForceContent(ctx context.Context) bool {
	opts, ok := ScanOptionsFromContext(ctx)
	return ok && opts.ForceContent
}

// scanForceFileIndex reports whether the current scan is a file-index audit
// run. True only when ctx carries AccountScanOptions with ForceFileIndex=true.
// In audit mode CheckFileIndex enumerates only the in-scope account, bypasses
// the directory mtime cache, and writes none of the three live state files
// (fileindex.current, fileindex.previous, dircache.json).
func scanForceFileIndex(ctx context.Context) bool {
	opts, ok := ScanOptionsFromContext(ctx)
	return ok && opts.ForceFileIndex
}

// scanRespectsIgnores reports whether the current scan should honour
// cfg.Suppressions.IgnorePaths. When ctx carries AccountScanOptions with
// RespectIgnores=false (i.e. an explicit full-scan / audit request), the caller
// wants full coverage and ignore_paths is bypassed. Normal scheduled scans and
// any call without options carry RespectIgnores=true (the safe default).
func scanRespectsIgnores(ctx context.Context, _ *config.Config) bool {
	if opts, ok := ScanOptionsFromContext(ctx); ok {
		return opts.RespectIgnores
	}
	return true
}

// accountScanMaxFiles returns the effective file cap for the current scan. When
// ctx carries AccountScanOptions (i.e. the caller is RunAccountScanWithOptions),
// the options MaxFiles value wins so a full scan (MaxFiles=0) is uncapped.
// Otherwise it falls back to the config-derived value so normal scheduled scans
// are unaffected.
func accountScanMaxFiles(ctx context.Context, cfg *config.Config) int {
	if opts, ok := ScanOptionsFromContext(ctx); ok {
		return opts.MaxFiles
	}
	return effectiveAccountScanMaxFiles(cfg)
}

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
