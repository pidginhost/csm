package main

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/pidginhost/csm/internal/platform"
)

// cagefsCageMountSample names the live cages that lack the PHP Shield event
// mount, and reports how many cages were sampled.
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
	if len(missing) > 0 {
		return []DoctorCheck{{
			Name:   name,
			Status: "fail",
			Message: fmt.Sprintf("%d of %d sampled cages lack the event mount (%s), so PHP Shield events are dropped there",
				len(missing), sampled, cageNameList(missing)),
			Fix: cageRemountFix(missing),
		}}
	}
	return []DoctorCheck{{Name: name, Status: "ok"}}
}

// cageNameCap bounds how many cages a report names; the count stays exact.
const cageNameCap = 5

// cageNameList renders the named cages, capped, with the remainder counted.
func cageNameList(names []string) string {
	if len(names) <= cageNameCap {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(names[:cageNameCap], ", "), len(names)-cageNameCap)
}

// cageRemountFix spells out the per-account remount for the cages named,
// and offers the host-wide remount when the list is long enough that a
// per-account pass is impractical.
func cageRemountFix(names []string) string {
	var cmds, unresolved []string
	for _, n := range names[:min(len(names), cageNameCap)] {
		// A passwd name cannot contain ':', so this is the display-only
		// fallback for a UID whose account lookup failed.
		if strings.HasPrefix(n, "uid:") {
			unresolved = append(unresolved, n)
			continue
		}
		cmds = append(cmds, "`cagefsctl --remount "+n+"`")
	}
	var steps []string
	if len(cmds) > 0 {
		steps = append(steps, "apply per account with "+strings.Join(cmds, ", "))
	}
	if len(unresolved) > 0 {
		steps = append(steps, "resolve account names for "+strings.Join(unresolved, ", ")+", then use `cagefsctl --remount <user>`")
	}
	fix := strings.Join(steps, "; ")
	if len(names) > cageNameCap {
		fix += ", or all at once with `cagefsctl --remount-all` in a maintenance window"
	}
	return fix + "; a remount kills processes inside the cages it rebuilds"
}

// cagefsAccountNameForUID resolves a uid to its account name. A var so tests
// can supply names without passwd entries.
var cagefsAccountNameForUID = accountNameForUID

func accountNameForUID(uid uint64) (string, bool) {
	u, err := user.LookupId(strconv.FormatUint(uid, 10))
	if err != nil {
		return "", false
	}
	return u.Username, true
}

// cageDisplayName names a cage by its account, or by uid when the account
// has no passwd entry; an unreadable account is still a reported cage.
func cageDisplayName(uid uint64) string {
	if name, ok := cagefsAccountNameForUID(uid); ok && name != "" {
		return name
	}
	return fmt.Sprintf("uid:%d", uid)
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

// serviceAccountHomeRoots are the trees a packaged daemon's home lives under.
// Nothing hosting a website is ever placed in one.
// Deliberately narrow. cPanel accepts an arbitrary absolute homedir, so /srv
// and /opt are left out even though no service account CSM has seen uses them:
// excluding a real account makes Doctor report OK over a cage that is actually
// blind, which is the failure this check exists to prevent.
var serviceAccountHomeRoots = []string{
	"/var/lib", "/var/run", "/var/cache", "/var/spool", "/var/empty",
	"/usr", "/etc", "/run", "/bin", "/sbin", "/lib", "/lib64",
	"/dev", "/proc", "/sys", "/boot",
	"/nonexistent",
}

// isHostingAccountHome reports whether a home directory could belong to an
// account that serves PHP.
//
// CloudLinux in "Enable All" mode cages every uid above the minimum, service
// accounts included, so a mount namespace alone does not make a cage worth
// counting: rspamd, chrony and memcached each get one and none will ever
// execute PHP.
//
// The test is which homes to *exclude*, not which to accept. cPanel spreads
// accounts over /home, /home2, /home3 and any root the operator configures, so
// an accept-list keyed on the panel's primary root would silently drop a real
// cage -- and under-reporting a blind cage is the failure that matters here.
// An unrecognised home is therefore counted.
func isHostingAccountHome(home string, panelRoots []string) bool {
	clean := filepath.Clean(home)
	if clean == "" || clean == "." || clean == "/" {
		return false
	}
	// The panel's own account roots win outright. Plesk puts accounts under
	// /var/www/vhosts, which sits inside a tree service accounts otherwise
	// occupy, so the exclusions below must not reach it.
	for _, root := range panelRoots {
		if pathUnder(clean, filepath.Clean(root)) {
			return true
		}
	}
	for _, root := range serviceAccountHomeRoots {
		if pathUnder(clean, root) {
			return false
		}
	}
	return true
}

func pathUnder(path, root string) bool {
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

// sampleCageShieldMounts inspects one running process per cage and reports how
// many of those cages are missing the event mount.
//
// A cage is a mount namespace of its own, so the only place the mount reliably
// shows up is that process's /proc/<pid>/mounts. One process per uid is enough:
// every process of a user shares the user's cage.
func sampleCageShieldMounts() (missing []string, sampled int, err error) {
	entries, err := os.ReadDir(procPath)
	if err != nil {
		return nil, 0, err
	}
	rootNS, err := os.Readlink(filepath.Join(procPath, "1", "ns", "mnt"))
	if err != nil {
		return nil, 0, err
	}

	panelRoots := platform.Detect().AccountHomeRoots()

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
		// A uid with no passwd entry is counted: an unreadable account is
		// not evidence that its cage can be ignored.
		if home, known := cagefsAccountHomeForUID(uid); known && !isHostingAccountHome(home, panelRoots) {
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
			missing = append(missing, cageDisplayName(uid))
		}
	}
	sort.Strings(missing)
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
