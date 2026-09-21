//go:build !linux || !bpf

package daemon

import "github.com/pidginhost/csm/internal/processctx"

// wireAncestryCache is a no-op on hosts built without the bpf build tag.
// cachedAncestryEvidence stays nil and ancestry falls back to the live /proc
// walk, which is racy for short-lived writers but fails closed.
func wireAncestryCache(*processctx.Cache) {}
