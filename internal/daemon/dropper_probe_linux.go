//go:build linux

package daemon

import (
	"errors"

	"golang.org/x/sys/unix"
)

// dropperFSProbe resolves a tracked candidate against the live filesystem for
// the probe loop. It distinguishes a confirmed deletion (ENOENT) from a
// permission or transient I/O failure so the engine can requeue the latter
// rather than reporting a phantom self-delete.
type dropperFSProbe struct{}

func (dropperFSProbe) probe(c dropperCandidate) dropperProbe {
	var st unix.Stat_t
	err := unix.Lstat(c.Path, &st)
	switch {
	case err == nil:
		// The path still resolves. Hand the current identity to the engine; a
		// matching device/inode/birth means the tracked file survived, a
		// different one means it was replaced.
		at := statToFileState(c.Path, &st)
		return dropperProbe{Conclusive: true, AtPath: &at}
	case !errors.Is(err, unix.ENOENT):
		// Permission or I/O error: cannot prove deletion. Inconclusive.
		return dropperProbe{Conclusive: false}
	}

	// Confirmed absent. Attribute it to an install rename or a removed docroot
	// before treating it as a self-delete.
	p := dropperProbe{Conclusive: true}
	if target, ts, ok := dropperFindRenameTarget(c); ok {
		p.RenamedTo = target
		p.RenameTarget = &ts
	}
	var dst unix.Stat_t
	if derr := unix.Stat(c.Docroot, &dst); derr != nil && errors.Is(derr, unix.ENOENT) {
		p.DocrootRemoved = true
	}
	return p
}

// dropperFindRenameTarget stats the install destinations WordPress and the
// atomic-write helper move a staged file to, returning the first that exists.
func dropperFindRenameTarget(c dropperCandidate) (string, dropperFileState, bool) {
	targets := wpUpgradeRenameCandidates(c.Path, c.Docroot)
	if atomic := atomicWriteRenameCandidate(c.Path); atomic != "" {
		targets = append(targets, atomic)
	}
	for _, target := range targets {
		var st unix.Stat_t
		if err := unix.Lstat(target, &st); err != nil {
			continue
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG {
			continue
		}
		return target, statToFileState(target, &st), true
	}
	return "", dropperFileState{}, false
}
