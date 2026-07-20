//go:build linux

package daemon

import (
	"errors"
	"time"

	"golang.org/x/sys/unix"
)

// dropperFSProbe resolves a tracked candidate against the live filesystem for
// the probe loop. It distinguishes a confirmed deletion (ENOENT) from a
// permission or transient I/O failure so the engine can requeue the latter
// rather than reporting a phantom self-delete.
type dropperFSProbe struct {
	quarantines *dropperQuarantineLedger
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
	var dst unix.Stat_t
	if derr := unix.Stat(c.Docroot, &dst); derr != nil && errors.Is(derr, unix.ENOENT) {
		result.DocrootRemoved = true
	}
	return result
}

// dropperFindRenameTarget snapshots the install destinations WordPress and the
// atomic-write helper may move a staged file to. A matching destination wins;
// otherwise the first regular destination is returned as replacement evidence.
func dropperFindRenameTarget(c dropperCandidate) (string, dropperFileState, bool, error) {
	targets := wpUpgradeRenameCandidates(c.Path, c.Docroot)
	if atomic := atomicWriteRenameCandidate(c.Path); atomic != "" {
		targets = append(targets, atomic)
	}
	var firstTarget string
	var firstState dropperFileState
	var transientErr error
	for _, target := range targets {
		state, err := statPathToFileState(target, false)
		if errors.Is(err, unix.ENOENT) {
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
			state, err = statPathToFileState(target, true)
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
