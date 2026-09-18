//go:build linux

package daemon

import (
	"encoding/hex"
	"errors"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/wpcheck"
)

// dropperFSProbe resolves a tracked candidate against the live filesystem for
// the probe loop. It distinguishes a confirmed deletion (ENOENT) from a
// permission or transient I/O failure so the engine can requeue the latter
// rather than reporting a phantom self-delete.
type dropperFSProbe struct {
	quarantines *dropperQuarantineLedger
	// coreChecksums compares a version probe with the official file of the
	// release it declares, and a core package file with the release now
	// installed. Nil leaves every such candidate unverified.
	coreChecksums interface {
		Describe(path string) wpcheck.Verification
		Verify(wpcheck.Verification) wpcheck.Verdict
	}
}

func (p dropperFSProbe) probe(c dropperCandidate) dropperProbe {
	state, err := statPathToFileState(c.Path, false)
	switch {
	case err == nil:
		// Every identity field came from one open fd. A matching identity means
		// the tracked file survived; a different one means it was replaced.
		return dropperProbe{Conclusive: true, AtPath: &state.file}
	case !errors.Is(err, unix.ENOENT):
		// Permission or I/O error: cannot prove deletion. Inconclusive.
		return dropperProbe{Conclusive: false}
	}

	// Confirmed absent. Attribute it to an install rename or a removed docroot
	// before treating it as a self-delete.
	result := dropperProbe{Conclusive: true}
	if p.quarantines.matched(c, time.Now()) {
		result.QuarantineMatched = true
		return result
	}
	if target, ts, ok, renameErr := dropperFindRenameTarget(c); renameErr != nil {
		return dropperProbe{Conclusive: false}
	} else if ok {
		result.RenamedTo = target
		result.RenameTarget = &ts
	}
	if c.WPCoreRelease != nil && p.coreChecksums != nil {
		result.OfficialWPCoreFile = p.coreChecksums.Verify(*c.WPCoreRelease) == wpcheck.VerdictVerified
	}
	result.OfficialWPCorePackageFile = p.officialCorePackageFile(c)
	var dst unix.Stat_t
	if derr := unix.Stat(c.Docroot, &dst); derr != nil && errors.Is(derr, unix.ENOENT) {
		result.DocrootRemoved = true
	}
	if c.Parent.known() {
		if current, perr := statDropperParent(filepath.Dir(c.Path)); perr == nil {
			result.ParentRemoved = dropperParentChanged(c.Parent, current)
		} else if errors.Is(perr, unix.ENOENT) {
			result.ParentRemoved = true
		}
	}
	return result
}

// officialCorePackageFile compares a vanished file of an unpacked core
// release with the release installed at its WordPress root. The staged tree,
// and with it the staged version header, is gone by the time of the probe.
// A completed update has installed that release, so its header names the
// manifest to check. An aborted one leaves the old release, whose manifest
// does not match the new bytes, and the candidate stays reported.
func (p dropperFSProbe) officialCorePackageFile(c dropperCandidate) bool {
	if p.coreChecksums == nil || !c.CoreMD5Known {
		return false
	}
	wpRoot, rel, ok := wpUpgradeCorePackageFile(c.Path, c.Docroot)
	if !ok {
		return false
	}
	v := p.coreChecksums.Describe(filepath.Join(wpRoot, "wp-includes", "version.php"))
	if v.Kind != wpcheck.KindCore || v.Root != wpRoot || v.Version == "" {
		return false
	}
	v.Rel, v.Digest = rel, hex.EncodeToString(c.CoreMD5[:])
	return p.coreChecksums.Verify(v) == wpcheck.VerdictVerified
}

// dropperFindRenameTarget snapshots the install destinations WordPress and the
// atomic-write helper may move or copy a staged file to. A matching destination
// wins; otherwise the first regular destination is returned as replacement
// evidence.
func dropperFindRenameTarget(c dropperCandidate) (string, dropperFileState, bool, error) {
	return dropperFindRenameTargetWithStat(c, statPathToFileState)
}

func dropperFindRenameTargetWithStat(c dropperCandidate, stat func(string, bool) (dropperPathState, error)) (string, dropperFileState, bool, error) {
	targets := wpUpgradeInstallDestinations(c.Path, c.Docroot)
	if atomic := atomicWriteRenameCandidate(c.Path); atomic != "" {
		targets = append(targets, atomic)
	}
	var firstTarget string
	var firstState dropperFileState
	var transientErr error
	for _, target := range targets {
		if !dropperRenameTargetAllowed(c, target) {
			continue
		}
		state, err := stat(target, false)
		// An unreachable destination cannot prove a benign move. Treating it
		// as transient would let a broken install path exhaust probe retries.
		if dropperInstallPathUnreachable(err) {
			continue
		}
		if err != nil {
			transientErr = err
			continue
		}
		if state.mode&unix.S_IFMT != unix.S_IFREG {
			continue
		}
		if dropperSameIdentity(c, state.file) {
			return target, state.file, true, nil
		}
		if c.DigestKnown && c.Size == state.file.Size {
			state, err = stat(target, true)
			if dropperInstallPathUnreachable(err) {
				continue
			}
			if err != nil {
				transientErr = err
				continue
			}
			if dropperRenameMatch(c, state.file) {
				return target, state.file, true, nil
			}
		}
		if firstTarget == "" {
			firstTarget, firstState = target, state.file
		}
	}
	if transientErr != nil {
		return "", dropperFileState{}, false, transientErr
	}
	if firstTarget != "" {
		return firstTarget, firstState, true, nil
	}
	return "", dropperFileState{}, false, nil
}

func dropperInstallPathUnreachable(err error) bool {
	return errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP)
}
