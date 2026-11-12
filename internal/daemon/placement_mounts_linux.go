//go:build linux

package daemon

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	csmlog "github.com/pidginhost/csm/internal/log"
)

// mountEntry is one /proc/self/mountinfo line. Dev uses the stat(2)
// encoding; Root is the directory of the superblock this mount shows.
type mountEntry struct {
	Dev        uint64
	Root       string
	MountPoint string
}

func readMountinfo() ([]mountEntry, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return parseMountinfo(f)
}

func parseMountinfo(r io.Reader) ([]mountEntry, error) {
	var mounts []mountEntry
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 {
			return nil, fmt.Errorf("mountinfo line has %d fields", len(fields))
		}
		major, minor, ok := strings.Cut(fields[2], ":")
		if !ok {
			return nil, fmt.Errorf("mountinfo device %q", fields[2])
		}
		maj, err := strconv.ParseUint(major, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("mountinfo device %q: %w", fields[2], err)
		}
		mnr, err := strconv.ParseUint(minor, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("mountinfo device %q: %w", fields[2], err)
		}
		mounts = append(mounts, mountEntry{
			Dev:        unix.Mkdev(uint32(maj), uint32(mnr)),
			Root:       unescapeMountinfo(fields[3]),
			MountPoint: unescapeMountinfo(fields[4]),
		})
	}
	return mounts, sc.Err()
}

// unescapeMountinfo reverses the kernel's octal escaping of space, tab,
// newline and backslash in mountinfo paths.
func unescapeMountinfo(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// placementMounts picks, for each watch root's device, the whole-superblock
// mount that holds that root. A placement path joined under it is the path
// the admission rules and the close-write events use.
func placementMounts(all []mountEntry, roots []watchRootMark) []mountEntry {
	var picked []mountEntry
	seen := make(map[uint64]bool)
	for _, r := range roots {
		if seen[r.device] {
			continue
		}
		best := placementRootMount(all, r)
		if best >= 0 {
			seen[r.device] = true
			picked = append(picked, all[best])
		}
	}
	return picked
}

// A deeper mount hides its ancestors even when it shows a different device
// or a subdirectory of the same filesystem. Filtering those mounts first
// would incorrectly treat a hidden whole-filesystem mount as usable.
func placementRootMount(all []mountEntry, root watchRootMark) int {
	best := placementVisibleMount(all, root)
	if best < 0 || all[best].Root != "/" {
		return -1
	}
	return best
}

// placementVisibleMount returns the mount that shows root, if it is on the
// root's recorded device.
func placementVisibleMount(all []mountEntry, root watchRootMark) int {
	best := visibleMount(all, root.path)
	if best < 0 || all[best].Dev != root.device {
		return -1
	}
	return best
}

// visibleMount returns the index of the mount that shows path: the deepest
// mount point above it, the later of two at one point being on top.
func visibleMount(all []mountEntry, path string) int {
	best := -1
	for i, m := range all {
		if pathWithin(path, m.MountPoint) && (best < 0 || len(m.MountPoint) >= len(all[best].MountPoint)) {
			best = i
		}
	}
	return best
}

func pathWithin(path, dir string) bool {
	return dir == "/" || path == dir || strings.HasPrefix(path, dir+"/")
}

// resolvePlacementPath joins leaf-first names under the whole-superblock
// mount of dev. Bind mounts of a subdirectory (a CageFS cage) share dev but
// show only part of the tree, so they cannot place a superblock-rooted path.
func resolvePlacementPath(dev uint64, leafFirst []string, mounts []mountEntry) (string, bool) {
	if len(leafFirst) == 0 {
		return "", false
	}
	for _, m := range mounts {
		if m.Dev != dev || m.Root != "/" {
			continue
		}
		parts := make([]string, 0, len(leafFirst)+1)
		parts = append(parts, m.MountPoint)
		for i := len(leafFirst) - 1; i >= 0; i-- {
			parts = append(parts, leafFirst[i])
		}
		return filepath.Join(parts...), true
	}
	return "", false
}

const placementUnresolvedCheck = "placement_unresolved_realtime"

// placementFromRaw turns a kernel record into the event handlePlacement
// takes. A record whose path cannot be rebuilt is reported, not dropped
// silently: nesting deeper than the kernel walk would otherwise hide a file.
func (fm *FileMonitor) placementFromRaw(raw PlacementRawEvent, mounts []mountEntry, at time.Time) (placementEvent, bool) {
	dev := userDeviceID(raw.Dev)
	path, ok := "", false
	if !raw.Truncated {
		path, ok = resolvePlacementPath(dev, raw.Components, mounts)
	}
	if !ok {
		fm.reportUnresolvedPlacement(dev, raw)
		return placementEvent{}, false
	}
	return placementEvent{
		Path: path, Dev: dev, Ino: raw.Ino, IsDir: raw.IsDir,
		PID:  int32(raw.PID), // #nosec G115 -- kernel pids fit in pid_t
		Kind: placementKind(raw.Kind), At: at,
	}, true
}

// reportUnresolvedPlacement keys its cooldown on the device, not the names:
// a writer can make every placement unresolvable.
func (fm *FileMonitor) reportUnresolvedPlacement(dev uint64, raw PlacementRawEvent) {
	device := deviceName(dev)
	if !fm.shouldAlert(placementUnresolvedCheck, "dev "+device) {
		return
	}
	names := make([]string, 0, len(raw.Components)+1)
	names = append(names, "...")
	for i := len(raw.Components) - 1; i >= 0; i-- {
		names = append(names, raw.Components[i])
	}
	reason := "the filesystem has no whole mount to resolve the path under"
	if raw.Truncated {
		reason = "the path is deeper or longer than realtime protection follows"
	}
	fm.sendAlert(alert.High, placementUnresolvedCheck,
		fmt.Sprintf("Realtime protection could not resolve the path of a file or directory moved or linked on device %s", device),
		fmt.Sprintf("Realtime protection did not check it because %s. Nearest names: %s; inode %d on that device, placed by PID %d. The next deep scan covers it.",
			reason, strings.Join(names, "/"), raw.Ino, raw.PID))
}

// reportUncoveredPlacementRoots names roots that the running backend's
// mounts, through which it turns events into paths, do not show. Sharing a
// device does not imply sharing that path.
func (fm *FileMonitor) reportUncoveredPlacementRoots(all, mounts []mountEntry) {
	for _, r := range fm.watchRoots {
		if i := visibleMount(all, r.path); i >= 0 && slices.Contains(mounts, all[i]) {
			continue
		}
		csmlog.Warn("placement: watch root is not visible through the placement mounts", "root", r.path, "device", deviceName(r.device))
		fm.sendAlert(alert.High, placementUnresolvedCheck,
			fmt.Sprintf("Realtime protection cannot see files moved or linked into %s (device %s)", r.path, deviceName(r.device)),
			"Realtime protection resolves placements on this filesystem through a mount that does not show this watch root, so it cannot match them to this location. The deep scan covers them.")
	}
}

func deviceName(dev uint64) string {
	return fmt.Sprintf("%d:%d", unix.Major(dev), unix.Minor(dev))
}
