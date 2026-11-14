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

// ancestryEvidence is what one walk of a process chain proved. The signals
// are kept apart because they are corroborated differently: a comm can be set
// by the process itself, so a package manager's needs a package transaction
// in the same window and an initramfs builder's needs a live root process chain,
// while an exe under a panel root cannot be faked and stands on its own.
type ancestryEvidence struct {
	packageManager   bool
	panelTool        bool
	initramfsBuilder bool
}

func (e ancestryEvidence) none() bool {
	return !e.packageManager && !e.panelTool && !e.initramfsBuilder
}

// procAncestryEvidence walks pid's PPid chain through procfs and reports what
// the chain proves. Any read or parse failure ends the walk with what was
// collected so far: a vanished process cannot prove provenance, so a chain
// that proved nothing leaves the alert at its original severity.
func procAncestryEvidence(pid int32, panelRoots []string) ancestryEvidence {
	var ev ancestryEvidence
	rootChain := true
	for depth := 0; depth < maxAncestryDepth && pid > 1; depth++ {
		dir := fmt.Sprintf("%s/%d", procRootDir, pid)
		// #nosec G304 -- procfs pseudo-files under a fixed root; pid is from the fanotify event.
		commRaw, err := os.ReadFile(dir + "/comm")
		if err != nil {
			return ev
		}
		comm := strings.TrimSpace(string(commRaw))
		if isPackageManagerComm(comm) {
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
		root := false
		statusComm := ""
		for _, line := range strings.Split(string(status), "\n") {
			switch {
			case strings.HasPrefix(line, "Name:"):
				statusComm = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
			case strings.HasPrefix(line, "PPid:"):
				n, convErr := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")), 10, 32)
				if convErr != nil {
					return ev
				}
				ppid = int32(n)
			case strings.HasPrefix(line, "Uid:"):
				root = statusUIDIsRoot(line)
			}
		}
		// A privileged ancestor does not vouch for descendants that dropped
		// privileges. Read the name with the credentials, not from an earlier
		// comm lookup that may have addressed a previous occupant of the PID.
		rootChain = rootChain && root
		if rootChain && isInitramfsBuilderComm(statusComm) {
			ev.initramfsBuilder = true
		}
		pid = ppid
	}
	return ev
}

// statusUIDIsRoot reports whether a /proc status Uid line names root as both
// the real and the effective user. A set-uid helper started by another user
// keeps that user's real id, so it never qualifies.
func statusUIDIsRoot(line string) bool {
	ids := strings.Fields(strings.TrimPrefix(line, "Uid:"))
	return len(ids) >= 2 && ids[0] == "0" && ids[1] == "0"
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

// ancestryEvidenceFor preserves cached panel and package evidence after
// process exit. Initramfs evidence requires a live root process chain;
// missing credentials leave that arm at the original severity.
func ancestryEvidenceFor(pid int32) ancestryEvidence {
	if pid <= 0 {
		return ancestryEvidence{}
	}
	roots := panelToolRoots()
	var cached ancestryEvidence
	if probe := cachedAncestryEvidence; probe != nil {
		cached = probe(uint32(pid), roots)
		if cached.panelTool {
			return cached
		}
	}
	// The cache has neither both current credentials nor a pinned parent
	// chain. Only live procfs evidence can authorize initramfs demotion.
	live := procAncestryEvidence(pid, roots)
	live.packageManager = live.packageManager || cached.packageManager
	return live
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
// case -- a non-root attacker can never qualify -- and then one of three
// provenance arms has to hold:
//
//   - the writer descends from the control panel's own tooling, proven by an
//     ancestor's executable path,
//   - or it descends from a package manager AND a package-manager log was
//     touched within the provenance window. The comm behind that arm is
//     attacker-settable, so it is never the sole gate,
//   - or its live ancestry through an initramfs builder runs entirely as root.
//
// The walk runs for every root-owned executable written under a temp root:
// the last arm needs no window or panel, so no cheaper gate can rule it out.
//
// The finding is rescored, never dropped by this decision, so the evidence
// trail survives even if the heuristic is wrong.
func demoteTmpExec(uid uint32, pid int32, now time.Time) (bool, string) {
	if uid != 0 || pid <= 0 {
		return false, ""
	}
	window := tmpExecPkgWindow(now)
	panelRooted := len(panelToolRoots()) > 0
	ev := tmpExecAncestry(pid)
	switch {
	case panelRooted && ev.panelTool:
		return true, "control panel maintenance ancestry"
	case window && ev.packageManager:
		return true, "package manager ancestry during active package window"
	case ev.initramfsBuilder:
		return true, "initramfs build ancestry"
	}
	return false, ""
}
