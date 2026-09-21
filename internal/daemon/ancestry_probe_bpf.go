//go:build linux && bpf

package daemon

import (
	"math"
	"sync"

	"github.com/pidginhost/csm/internal/processctx"
)

var ancestryProbeOnce sync.Once

// wireAncestryCache installs a cached ancestry probe backed by the
// daemon-wide processctx cache. It is preferred over the live /proc walk
// because it survives process exit, which the walk cannot do for a
// short-lived writer. Hosts without BPF use the stub in
// ancestry_probe_nobpf.go and fall back to the walk.
func wireAncestryCache(cache *processctx.Cache) {
	if cache == nil {
		return
	}
	ancestryProbeOnce.Do(func() {
		cachedAncestryEvidence = func(pid uint32, panelRoots []string) ancestryEvidence {
			var ev ancestryEvidence
			if pid == 0 || pid > math.MaxInt32 {
				return ev
			}
			for cur := cache.Materialize(int(pid)); cur != nil; cur = cur.Parent {
				if isPackageManagerComm(cur.Comm) {
					ev.packageManager = true
				}
				if !ev.panelTool && cur.Exe != "" && exeInPanelRoot(cur.Exe, panelRoots) {
					if mode, uid, err := exeStat(cur.Exe); err == nil {
						ev.panelTool = panelToolExeTrusted(cur.Exe, panelRoots, mode, uid)
					}
				}
			}
			return ev
		}
	})
}
