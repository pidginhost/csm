package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// cagefsSkeletonPath is CloudLinux's cage skeleton (SKELETON in cagefsctl).
// A registered mount point only reaches running cages once it appears here.
var cagefsSkeletonPath = "/usr/share/cagefs-skeleton"

// phpShieldCageFSDoctorChecks reports whether PHP Shield can actually deliver
// events on a CloudLinux host.
//
// Registering the event directory in cagefs.mp is not enough: until the cages
// are remounted the path does not exist inside them, PHP cannot reach the event
// socket, and every detection is dropped with nothing to distinguish it from a
// quiet server. The installer deliberately does not remount (that recreates
// every LVE on the box), so this check is what keeps a pending remount visible
// instead of leaving the Shield silently blind.
//
// Returns no checks at all off CloudLinux, where the mount-points file is
// absent and none of this applies.
func phpShieldCageFSDoctorChecks() []DoctorCheck {
	// #nosec G304 -- fixed CageFS configuration path, overridden only in tests.
	data, err := os.ReadFile(cagefsMountPointsPath)
	if err != nil {
		return nil
	}

	const name = "php shield: cagefs event mount"
	kind, found := cagefsMountForPath(string(data), phpShieldEventDir)
	if !found {
		return []DoctorCheck{{
			Name:    name,
			Status:  "fail",
			Message: "event directory is not a CageFS mount point, so PHP Shield events are dropped",
			Fix:     "run `csm enable --php-shield` to register it, then apply it with cagefsctl",
		}}
	}
	if kind != cagefsMountShared {
		return []DoctorCheck{{
			Name:    name,
			Status:  "fail",
			Message: fmt.Sprintf("event directory is mounted %s; PHP Shield needs a shared mount, so events are dropped", kind),
			Fix:     fmt.Sprintf("replace the %s entry for %s in %s with a plain shared mount", kind, phpShieldEventDir, cagefsMountPointsPath),
		}}
	}
	if _, err := os.Stat(filepath.Join(cagefsSkeletonPath, phpShieldEventDir)); err != nil {
		return []DoctorCheck{{
			Name:   name,
			Status: "fail",
			Message: "event mount is registered but has not been applied to the cages, " +
				"so PHP Shield events are dropped",
			Fix: "apply it in a maintenance window: `cagefsctl --remount-all` (recreates every LVE), " +
				"or `cagefsctl --remount <user>` per account",
		}}
	}
	return []DoctorCheck{{Name: name, Status: "ok"}}
}
