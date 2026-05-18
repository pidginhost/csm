//go:build !linux || !bpf

package daemon

import "github.com/pidginhost/csm/internal/processctx"

// wireAncestryProbeIfAvailable is a no-op on hosts built without the bpf
// build tag. checks.AncestryProbe stays nil; rescoreSensitive falls back to
// the package-manager log mtime signal alone.
func wireAncestryProbeIfAvailable(*processctx.Cache) {}
