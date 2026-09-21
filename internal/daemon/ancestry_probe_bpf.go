//go:build linux && bpf

package daemon

import (
	"math"
	"sync/atomic"

	"github.com/pidginhost/csm/internal/processctx"
)

var ancestryCache atomic.Pointer[processctx.Cache]

func init() { cachedAncestryEvidence = cacheAncestryEvidence }

// wireAncestryCache publishes the optional cache while file monitors may
// already be reading provenance. The probe itself stays fixed after init.
func wireAncestryCache(cache *processctx.Cache) { ancestryCache.Store(cache) }

func cacheAncestryEvidence(pid uint32, panelRoots []string) ancestryEvidence {
	var ev ancestryEvidence
	cache := ancestryCache.Load()
	if cache == nil || pid == 0 || pid > math.MaxInt32 {
		return ev
	}
	for cur := cache.Materialize(int(pid)); cur != nil; cur = cur.Parent {
		if isPackageManagerComm(cur.Comm) {
			ev.packageManager = true
		}
		if !ev.panelTool && cur.ExeResolved && exeInPanelRoot(cur.Exe, panelRoots) {
			if mode, uid, err := exeStat(cur.Exe); err == nil {
				ev.panelTool = panelToolExeTrusted(cur.Exe, panelRoots, mode, uid)
			}
		}
	}
	return ev
}
