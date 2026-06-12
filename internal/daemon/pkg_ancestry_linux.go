//go:build linux

package daemon

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/checks"
)

// procRootDir is the procfs mount used by the ancestry walker. A var so
// tests can point it at a synthetic tree.
var procRootDir = "/proc"

// maxAncestryDepth bounds the PPid walk. Real package-manager chains are
// short (cpio <- weak-modules <- dnf <- systemd); a cap keeps a hostile or
// corrupt PPid chain from turning event handling into an unbounded scan.
const maxAncestryDepth = 16

// Injection points for tests; defaults are the real implementations.
var (
	tmpExecPkgWindow   = checks.PkgManagerRecentlyActive
	tmpExecPkgAncestry = pkgManagerAncestry
	tmpExecDemote      = demoteTmpExec
)

// procAncestryIsPackageManager walks pid's PPid chain through procfs and
// reports whether any ancestor's comm is a known package manager. Any read
// or parse failure fails closed (no demotion): a vanished process means we
// cannot prove provenance, so the alert keeps its original severity.
func procAncestryIsPackageManager(pid int32) bool {
	for depth := 0; depth < maxAncestryDepth && pid > 1; depth++ {
		dir := fmt.Sprintf("%s/%d", procRootDir, pid)
		// #nosec G304 -- procfs pseudo-files under a fixed root; pid is from the fanotify event.
		comm, err := os.ReadFile(dir + "/comm")
		if err != nil {
			return false
		}
		if isPackageManagerComm(strings.TrimSpace(string(comm))) {
			return true
		}
		// #nosec G304 -- procfs pseudo-files under a fixed root; pid is from the fanotify event.
		status, err := os.ReadFile(dir + "/status")
		if err != nil {
			return false
		}
		ppid := int32(-1)
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "PPid:") {
				n, convErr := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")), 10, 32)
				if convErr != nil {
					return false
				}
				ppid = int32(n)
				break
			}
		}
		pid = ppid
	}
	return false
}

// pkgManagerAncestry reports whether pid's process chain contains a package
// manager. The BPF processctx cache is preferred because it survives process
// exit; hosts without BPF fall back to a live /proc walk, which is racy for
// short-lived writers but fails closed into the original Critical severity.
func pkgManagerAncestry(pid int32) bool {
	if pid <= 0 {
		return false
	}
	if probe := checks.AncestryProbe; probe != nil && probe(uint32(pid)) {
		return true
	}
	return procAncestryIsPackageManager(pid)
}

// demoteTmpExec decides whether an executable_in_tmp_realtime finding is
// demoted from Critical to Warning. All three gates must hold:
//
//   - the file is root-owned (a non-root attacker can never qualify),
//   - a package-manager log was touched within the provenance window,
//   - the writing process descends from a package manager.
//
// Process names and paths are attacker-influenced and are never used as the
// sole gate. The finding is rescored, never suppressed, so the evidence
// trail survives even if the heuristic is wrong.
func demoteTmpExec(uid uint32, pid int32, now time.Time) (bool, string) {
	if uid != 0 || pid <= 0 {
		return false, ""
	}
	if !tmpExecPkgWindow(now) {
		return false, ""
	}
	if !tmpExecPkgAncestry(pid) {
		return false, ""
	}
	return true, "package manager ancestry during active package window"
}
