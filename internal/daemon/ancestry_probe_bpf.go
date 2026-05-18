//go:build linux && bpf

package daemon

import (
	"math"
	"sync"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/processctx"
)

var ancestryProbeOnce sync.Once

// wireAncestryProbeIfAvailable installs a checks.AncestryProbe backed by the
// daemon-wide processctx cache. Hosts without BPF use the no-op stub in
// ancestry_probe_nobpf.go and rely on rescoreSensitive's package-manager log
// mtime signal alone.
func wireAncestryProbeIfAvailable(cache *processctx.Cache) {
	if cache == nil {
		return
	}
	ancestryProbeOnce.Do(func() {
		checks.AncestryProbe = func(pid uint32) bool {
			if pid == 0 || pid > math.MaxInt32 {
				return false
			}
			pc := cache.Materialize(int(pid))
			for cur := pc; cur != nil; cur = cur.Parent {
				if isPackageManagerComm(cur.Comm) {
					return true
				}
			}
			return false
		}
	})
}
