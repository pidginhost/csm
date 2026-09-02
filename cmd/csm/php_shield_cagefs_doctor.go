package main

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/pidginhost/csm/internal/platform"
)

// cagefsCageMountSample reports how many live cages lack the PHP Shield event
// mount, out of how many were sampled.
//
// The cage skeleton is deliberately NOT the signal. Remounting a single user
// creates the skeleton placeholder for every cage, so the directory turns up
// server-wide while only that one user has the real bind mount. Measured on a
// CloudLinux host: an unmounted cage sees an empty 0755 placeholder and cannot
// reach the socket, while the mount only shows up in that cage's own mount
// table.
var cagefsCageMountSample = sampleCageShieldMounts

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
	missing, sampled, err := cagefsCageMountSample()
	if err != nil || sampled == 0 {
		return []DoctorCheck{{
			Name:    name,
			Status:  "warn",
			Message: "event mount is registered, but no running cage could be sampled to confirm it was applied",
			Fix:     "re-run while sites are serving traffic",
		}}
	}
	if missing > 0 {
		return []DoctorCheck{{
			Name:    name,
			Status:  "fail",
			Message: fmt.Sprintf("%d of %d sampled cages lack the event mount, so PHP Shield events are dropped there", missing, sampled),
			Fix: "apply per account with `cagefsctl --remount <user>`, or all at once with " +
				"`cagefsctl --remount-all` in a maintenance window; a remount kills processes inside the cages it rebuilds",
		}}
	}
	return []DoctorCheck{{Name: name, Status: "ok"}}
}

// procPath is /proc, overridden in tests.
var procPath = "/proc"

// cagefsMinUID is the lowest uid CageFS will cage. CloudLinux keeps the real
// value in /etc/cagefs/cagefs.min.uid; 500 matches its default and is only a
// floor for which processes are worth sampling.
var cagefsMinUID uint64 = 500

// cagefsAccountHomeForUID resolves a uid to its home directory. A var so tests
// can supply one without a passwd entry.
var cagefsAccountHomeForUID = accountHomeForUID

func accountHomeForUID(uid uint64) (string, bool) {
	u, err := user.LookupId(strconv.FormatUint(uid, 10))
	if err != nil {
		return "", false
	}
	return u.HomeDir, true
}

// isHostingAccountHome reports whether a home directory is a hosting account's.
//
// CloudLinux in "Enable All" mode cages every uid above the minimum, service
// accounts included, so a mount namespace alone does not make a cage worth
// counting: rspamd, chrony and memcached each get one and none of them will
// ever execute PHP. Only an account whose home sits under the panel's account
// root can run the code PHP Shield inspects.
func isHostingAccountHome(home string, roots []string) bool {
	clean := filepath.Clean(home)
	for _, root := range roots {
		if strings.HasPrefix(clean, filepath.Clean(root)+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// sampleCageShieldMounts inspects one running process per cage and reports how
// many of those cages are missing the event mount.
//
// A cage is a mount namespace of its own, so the only place the mount reliably
// shows up is that process's /proc/<pid>/mounts. One process per uid is enough:
// every process of a user shares the user's cage.
func sampleCageShieldMounts() (missing, sampled int, err error) {
	entries, err := os.ReadDir(procPath)
	if err != nil {
		return 0, 0, err
	}
	rootNS, err := os.Readlink(filepath.Join(procPath, "1", "ns", "mnt"))
	if err != nil {
		return 0, 0, err
	}

	accountRoots := platform.Detect().AccountHomeRoots()

	// One sample per mount namespace: that is exactly one per cage, however
	// many processes the account is running.
	seen := make(map[string]struct{})
	for _, entry := range entries {
		if !entry.IsDir() || !isAllDigits(entry.Name()) {
			continue
		}
		dir := filepath.Join(procPath, entry.Name())
		info, statErr := os.Stat(dir)
		if statErr != nil {
			continue
		}
		// System accounts never get a cage. Skipping them also keeps
		// systemd-sandboxed root services -- which have private mount
		// namespaces of their own, csm.service included -- from being
		// counted as cages that lost the mount.
		uid, ok := fileOwnerUID(info)
		if !ok || uid < cagefsMinUID {
			continue
		}
		home, known := cagefsAccountHomeForUID(uid)
		if !known || !isHostingAccountHome(home, accountRoots) {
			continue
		}
		// A process sharing init's namespace is outside every cage.
		ns, linkErr := os.Readlink(filepath.Join(dir, "ns", "mnt"))
		if linkErr != nil || ns == rootNS {
			continue
		}
		if _, done := seen[ns]; done {
			continue
		}
		mounted, readErr := mountsContain(filepath.Join(dir, "mounts"), phpShieldEventDir)
		if readErr != nil {
			continue
		}
		seen[ns] = struct{}{}
		sampled++
		if !mounted {
			missing++
		}
	}
	return missing, sampled, nil
}

func fileOwnerUID(info os.FileInfo) (uint64, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(stat.Uid), true
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// mountsContain reports whether a mount table has target as a mount point. The
// mount point is the second field of each line.
func mountsContain(path, target string) (bool, error) {
	// #nosec G304 -- a /proc/<pid>/mounts path built from a numeric directory entry.
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[1] == target {
			return true, nil
		}
	}
	return false, scanner.Err()
}
