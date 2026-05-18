//go:build linux && bpf

package daemon

import (
	"math"
	"sync"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/processctx"
)

// pkgManagerComms are the process names CSM treats as evidence that an
// observed sensitive-file write originated from a legitimate root-driven
// package transaction. The list intentionally omits shells (sh, bash) and
// generic utilities (cp, mv) -- attackers reuse those. Matching the package
// manager binary itself anywhere in the parent chain is the discriminator.
var pkgManagerComms = map[string]struct{}{
	"dnf":         {},
	"dnf-3":       {},
	"microdnf":    {},
	"yum":         {},
	"rpm":         {},
	"dpkg":        {},
	"apt":         {},
	"apt-get":     {},
	"unattended-": {}, // unattended-upgrade is comm-truncated to TASK_COMM_LEN-1
}

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
				if _, ok := pkgManagerComms[cur.Comm]; ok {
					return true
				}
			}
			return false
		}
	})
}
