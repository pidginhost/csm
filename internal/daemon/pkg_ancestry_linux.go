//go:build linux

package daemon

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/platform"
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
	tmpExecPkgWindow = checks.PkgManagerRecentlyActive
	tmpExecAncestry  = ancestryEvidenceFor
	tmpExecDemote    = demoteTmpExec
)

// ancestryEvidence is what one walk of a process chain proved. The two
// signals are kept apart because they are corroborated differently: a comm
// can be set by the process itself and needs a package transaction in the
// same window to mean anything, while an exe under a panel root cannot be
// faked and stands on its own.
type ancestryEvidence struct {
	packageManager bool
	panelTool      bool
}

func (e ancestryEvidence) none() bool { return !e.packageManager && !e.panelTool }

// procAncestryEvidence walks pid's PPid chain through procfs and reports what
// the chain proves. Any read or parse failure ends the walk with what was
// collected so far: a vanished process cannot prove provenance, so a chain
// that proved nothing leaves the alert at its original severity.
func procAncestryEvidence(pid int32, panelRoots []string) ancestryEvidence {
	var ev ancestryEvidence
	for depth := 0; depth < maxAncestryDepth && pid > 1; depth++ {
		dir := fmt.Sprintf("%s/%d", procRootDir, pid)
		// #nosec G304 -- procfs pseudo-files under a fixed root; pid is from the fanotify event.
		comm, err := os.ReadFile(dir + "/comm")
		if err != nil {
			return ev
		}
		if isPackageManagerComm(strings.TrimSpace(string(comm))) {
			ev.packageManager = true
		}
		if !ev.panelTool && procExeIsPanelTool(dir, panelRoots) {
			ev.panelTool = true
		}
		if ev.packageManager && ev.panelTool {
			return ev
		}
		// #nosec G304 -- procfs pseudo-files under a fixed root; pid is from the fanotify event.
		status, err := os.ReadFile(dir + "/status")
		if err != nil {
			return ev
		}
		ppid := int32(-1)
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "PPid:") {
				n, convErr := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")), 10, 32)
				if convErr != nil {
					return ev
				}
				ppid = int32(n)
				break
			}
		}
		pid = ppid
	}
	return ev
}

// procExeIsPanelTool reports whether the process at procDir is running a
// binary the control panel installed. The path is tested before the file is
// stat()ed because an ancestor's exe can point anywhere.
func procExeIsPanelTool(procDir string, roots []string) bool {
	if len(roots) == 0 {
		return false
	}
	exe, err := os.Readlink(procDir + "/exe")
	if err != nil || !exeInPanelRoot(exe, roots) {
		return false
	}
	mode, uid, err := exeStat(exe)
	if err != nil {
		return false
	}
	return panelToolExeTrusted(exe, roots, mode, uid)
}

// panelToolRoots returns the detected panel's own tool directories. Detection
// is cached, so this is cheap enough to call per event. A var so tests can
// describe a cPanel host without one.
var panelToolRoots = func() []string { return platform.Detect().PanelToolRoots() }

// wireAncestryProvenance installs the ancestry hook the checks package uses to
// rescore sensitive-file findings. The /proc walk needs no BPF, so this runs
// on every Linux host; wireAncestryCache only adds a cache that survives
// process exit.
func wireAncestryProvenance() { checks.AncestryProvenance = ancestryProvenanceReason }

// ancestryEvidenceFor reports what pid's process chain proves. The BPF
// processctx cache is preferred because it survives process exit; hosts
// without BPF fall back to a live /proc walk, which is racy for short-lived
// writers but fails closed into the original severity.
func ancestryEvidenceFor(pid int32) ancestryEvidence {
	if pid <= 0 {
		return ancestryEvidence{}
	}
	roots := panelToolRoots()
	if probe := cachedAncestryEvidence; probe != nil {
		if ev := probe(uint32(pid), roots); !ev.none() {
			return ev
		}
	}
	return procAncestryEvidence(pid, roots)
}

// cachedAncestryEvidence reads the same evidence out of the BPF processctx
// cache. Nil on hosts built or running without BPF.
var cachedAncestryEvidence func(pid uint32, panelRoots []string) ancestryEvidence

const (
	pkgAncestryReason       = "ancestor is package manager"
	panelToolAncestryReason = "ancestor is control panel maintenance"
)

// ancestryProvenanceReason names the trusted component behind pid, or "" when
// the chain proves nothing. Panel tooling is reported first: its evidence is
// an executable an unprivileged user cannot place, while a package-manager
// comm is only a name.
func ancestryProvenanceReason(pid uint32) string {
	if pid == 0 || pid > math.MaxInt32 {
		return ""
	}
	ev := ancestryEvidenceFor(int32(pid))
	switch {
	case ev.panelTool:
		return panelToolAncestryReason
	case ev.packageManager:
		return pkgAncestryReason
	default:
		return ""
	}
}

// demoteTmpExec decides whether an executable_in_tmp_realtime finding is
// demoted from Critical to Warning. The file must be root-owned in every
// case -- a non-root attacker can never qualify -- and then one of two
// provenance arms has to hold:
//
//   - the writer descends from the control panel's own tooling, proven by an
//     ancestor's executable path,
//   - or it descends from a package manager AND a package-manager log was
//     touched within the provenance window. The comm behind that arm is
//     attacker-settable, so it is never the sole gate.
//
// The finding is rescored, never suppressed, so the evidence trail survives
// even if the heuristic is wrong.
func demoteTmpExec(uid uint32, pid int32, now time.Time) (bool, string) {
	if uid != 0 || pid <= 0 {
		return false, ""
	}
	// Both cheap gates first. The walk costs up to maxAncestryDepth procfs
	// reads and runs for every root-owned executable written under a temp
	// root, so it must not run when neither arm could change the verdict:
	// no package transaction in the window, and no panel root for an exe to
	// resolve inside.
	window := tmpExecPkgWindow(now)
	panelRooted := len(panelToolRoots()) > 0
	if !window && !panelRooted {
		return false, ""
	}
	ev := tmpExecAncestry(pid)
	if panelRooted && ev.panelTool {
		return true, "control panel maintenance ancestry"
	}
	if window && ev.packageManager {
		return true, "package manager ancestry during active package window"
	}
	return false, ""
}
