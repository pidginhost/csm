//go:build linux

package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
)

func TestResolvePlacementPathUsesWholeFilesystemMount(t *testing.T) {
	home := unix.Mkdev(259, 3)
	mounts := []mountEntry{
		// A cage binds one site directory of the same superblock first.
		{Dev: home, Root: "/user/public_html", MountPoint: "/var/cage/user/public_html"},
		{Dev: home, Root: "/", MountPoint: "/home"},
		{Dev: unix.Mkdev(8, 2), Root: "/", MountPoint: "/"},
	}
	got, ok := resolvePlacementPath(home, []string{"shell.php", "public_html", "user"}, mounts)
	if !ok || got != "/home/user/public_html/shell.php" {
		t.Fatalf("resolved %q, %v", got, ok)
	}
	got, ok = resolvePlacementPath(unix.Mkdev(8, 2), []string{"x.php", "tmp"}, mounts)
	if !ok || got != "/tmp/x.php" {
		t.Fatalf("root filesystem resolved %q, %v", got, ok)
	}
}

func TestResolvePlacementPathWithoutWholeFilesystemMount(t *testing.T) {
	dev := unix.Mkdev(253, 5)
	mounts := []mountEntry{{Dev: dev, Root: "/user/public_html", MountPoint: "/var/cage/user/public_html"}}
	if got, ok := resolvePlacementPath(dev, []string{"x.php"}, mounts); ok {
		t.Fatalf("bind-only device resolved to %q", got)
	}
	if got, ok := resolvePlacementPath(unix.Mkdev(9, 9), []string{"x.php"}, mounts); ok {
		t.Fatalf("unknown device resolved to %q", got)
	}
	if got, ok := resolvePlacementPath(dev, nil, []mountEntry{{Dev: dev, Root: "/", MountPoint: "/home"}}); ok {
		t.Fatalf("an event without names resolved to the mount itself: %q", got)
	}
}

func TestParseMountinfo(t *testing.T) {
	const info = `22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw
40 22 259:300 / /home rw,relatime shared:20 master:3 - xfs /dev/nvme0n1p1 rw
41 22 259:300 /user/public_html /var/cage/a\040b rw - xfs /dev/nvme0n1p1 rw
`
	got, err := parseMountinfo(strings.NewReader(info))
	if err != nil {
		t.Fatal(err)
	}
	want := []mountEntry{
		{Dev: unix.Mkdev(8, 2), Root: "/", MountPoint: "/"},
		{Dev: unix.Mkdev(259, 300), Root: "/", MountPoint: "/home"},
		{Dev: unix.Mkdev(259, 300), Root: "/user/public_html", MountPoint: "/var/cage/a b"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("parsed %+v\nwant   %+v", got, want)
	}
	if _, err := parseMountinfo(strings.NewReader("22 1 8:2 /\n")); err == nil {
		t.Error("short mountinfo line parsed")
	}
}

func TestPlacementMountsPicksTheMountHoldingEachWatchRoot(t *testing.T) {
	root, home := unix.Mkdev(8, 2), unix.Mkdev(259, 3)
	all := []mountEntry{
		{Dev: root, Root: "/", MountPoint: "/"},
		// A whole-superblock view elsewhere must not win over the mount the
		// watch root lives on: admission rules match the real site path.
		{Dev: home, Root: "/", MountPoint: "/mnt/view"},
		{Dev: home, Root: "/", MountPoint: "/home"},
		{Dev: home, Root: "/user", MountPoint: "/var/cage/user"},
		{Dev: unix.Mkdev(0, 40), Root: "/", MountPoint: "/run"},
	}
	roots := []watchRootMark{
		{path: "/home", device: home},
		{path: "/home/user/public_html", device: home, coveredBy: "/home"},
		{path: "/var/www", device: root},
		// A root whose only mount is a subdirectory bind has nothing to join under.
		{path: "/srv/bound", device: unix.Mkdev(253, 1)},
	}
	got := placementMounts(all, roots)
	want := []mountEntry{
		{Dev: home, Root: "/", MountPoint: "/home"},
		{Dev: root, Root: "/", MountPoint: "/"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("placement mounts %+v\nwant %+v", got, want)
	}
}

func unresolvedPlacementFindings(t *testing.T, alerts chan alert.Finding) []alert.Finding {
	t.Helper()
	var out []alert.Finding
	for {
		select {
		case f := <-alerts:
			if f.Check == "placement_unresolved_realtime" {
				out = append(out, f)
			}
		default:
			return out
		}
	}
}

// Nesting a site deeper than the kernel walk follows must not hide a placed
// file silently: realtime says what it could not see.
func TestTruncatedPlacementRaisesFinding(t *testing.T) {
	alerts := make(chan alert.Finding, 8)
	fm := placementTestMonitor(alerts)
	home := unix.Mkdev(259, 3)
	mounts := []mountEntry{{Dev: home, Root: "/", MountPoint: "/home"}}
	raw, err := decodePlacementEvent(placementRecord(1, 0, 1, 77, kernelDeviceID(home), 12, "shell.php", "d63", "d62"))
	if err != nil {
		t.Fatal(err)
	}
	if ev, ok := fm.placementFromRaw(raw, mounts, time.Now()); ok {
		t.Fatalf("truncated placement resolved to %+v", ev)
	}
	found := unresolvedPlacementFindings(t, alerts)
	if len(found) != 1 {
		t.Fatalf("findings %+v, want one", found)
	}
	f := found[0]
	if f.Severity != alert.High || !strings.Contains(f.Message, "259:3") ||
		!strings.Contains(f.Details, ".../d62/d63/shell.php") || !strings.Contains(f.Details, "deep scan") ||
		!strings.Contains(f.Details, "inode 12") || !strings.Contains(f.Details, "PID 77") {
		t.Fatalf("finding does not name the device, the partial path and the fallback: %+v", f)
	}
	// Every placement can be made unresolvable, so the device shares one cooldown.
	raw.Components = []string{"other.php", "d63", "d62"}
	if _, ok := fm.placementFromRaw(raw, mounts, time.Now()); ok {
		t.Fatal("second truncated placement resolved")
	}
	if again := unresolvedPlacementFindings(t, alerts); len(again) != 0 {
		t.Fatalf("cooldown did not hold: %+v", again)
	}
}

func TestPlacementWithoutWholeMountRaisesFinding(t *testing.T) {
	alerts := make(chan alert.Finding, 8)
	fm := placementTestMonitor(alerts)
	dev := unix.Mkdev(253, 5)
	mounts := []mountEntry{{Dev: dev, Root: "/user", MountPoint: "/var/cage/user"}}
	raw := PlacementRawEvent{Kind: 1, Dev: kernelDeviceID(dev), Ino: 3, Components: []string{"x.php", "public_html", "user"}}
	if _, ok := fm.placementFromRaw(raw, mounts, time.Now()); ok {
		t.Fatal("placement without a whole-filesystem mount resolved")
	}
	found := unresolvedPlacementFindings(t, alerts)
	if len(found) != 1 || !strings.Contains(found[0].Message, "253:5") || !strings.Contains(found[0].Details, ".../user/public_html/x.php") {
		t.Fatalf("findings %+v", found)
	}
}

func TestPlacementFromRawConvertsTheDevice(t *testing.T) {
	fm := placementTestMonitor(make(chan alert.Finding, 1))
	home := unix.Mkdev(259, 3)
	at := time.Unix(1700000000, 0)
	raw := PlacementRawEvent{Kind: 2, IsDir: true, PID: 42, Dev: kernelDeviceID(home), Ino: 9, Components: []string{"plugin", "plugins"}}
	ev, ok := fm.placementFromRaw(raw, []mountEntry{{Dev: home, Root: "/", MountPoint: "/home"}}, at)
	want := placementEvent{Path: "/home/plugins/plugin", Dev: home, Ino: 9, IsDir: true, PID: 42, Kind: placementLink, At: at}
	if !ok || ev != want {
		t.Fatalf("placement %+v, %v; want %+v", ev, ok, want)
	}
}

// A watch root with no whole-filesystem mount is left out of the kernel
// filter, so placements under it are never reported. Startup says so.
func TestUncoveredPlacementRootsRaiseFindings(t *testing.T) {
	alerts := make(chan alert.Finding, 8)
	fm := placementTestMonitor(alerts)
	home, bound := unix.Mkdev(259, 3), unix.Mkdev(253, 1)
	fm.watchRoots = []watchRootMark{
		{path: "/home", device: home},
		{path: "/srv/bound", device: bound},
	}
	fm.reportUncoveredPlacementRoots([]mountEntry{{Dev: home, Root: "/", MountPoint: "/home"}}, []mountEntry{{Dev: home, Root: "/", MountPoint: "/home"}}, fm.watchRoots)
	found := unresolvedPlacementFindings(t, alerts)
	if len(found) != 1 {
		t.Fatalf("findings %+v, want one for the uncovered root", found)
	}
	f := found[0]
	if f.Severity != alert.High || !strings.Contains(f.Message, "/srv/bound") ||
		!strings.Contains(f.Message, "253:1") || !strings.Contains(f.Details, "deep scan") {
		t.Fatalf("finding does not name the root, its device and the fallback: %+v", f)
	}
}

func TestPlacementMountsRejectsShadowedWholeMount(t *testing.T) {
	dev := unix.Mkdev(8, 2)
	for _, overlay := range []mountEntry{
		{Dev: dev, Root: "/data/site", MountPoint: "/srv/site"},
		{Dev: unix.Mkdev(8, 3), Root: "/", MountPoint: "/srv"},
	} {
		all := []mountEntry{{Dev: dev, Root: "/", MountPoint: "/"}, overlay}
		got := placementMounts(all, []watchRootMark{{path: "/srv/site", device: dev}})
		if len(got) != 0 {
			t.Errorf("mount hidden by %+v selected as %+v", overlay, got)
		}
	}
}

func TestUncoveredPlacementAliasRaisesFinding(t *testing.T) {
	alerts := make(chan alert.Finding, 8)
	fm := placementTestMonitor(alerts)
	dev := unix.Mkdev(259, 3)
	fm.watchRoots = []watchRootMark{
		{path: "/home", device: dev},
		{path: "/srv/site", device: dev},
	}
	all := []mountEntry{
		{Dev: dev, Root: "/", MountPoint: "/home"},
		{Dev: dev, Root: "/user", MountPoint: "/srv/site"},
	}
	fm.reportUncoveredPlacementRoots(all, placementMounts(all, fm.watchRoots), fm.watchRoots)
	found := unresolvedPlacementFindings(t, alerts)
	if len(found) != 1 || !strings.Contains(found[0].Message, "/srv/site") {
		t.Fatalf("findings %+v, want one for the uncovered alias", found)
	}
}

func TestUncoveredPlacementBindBelowWholeMountRaisesFinding(t *testing.T) {
	alerts := make(chan alert.Finding, 8)
	fm := placementTestMonitor(alerts)
	dev := unix.Mkdev(8, 2)
	fm.watchRoots = []watchRootMark{{path: "/tmp", device: dev}, {path: "/srv/site", device: dev}}
	all := []mountEntry{{Dev: dev, Root: "/", MountPoint: "/"}, {Dev: dev, Root: "/data/site", MountPoint: "/srv/site"}}
	fm.reportUncoveredPlacementRoots(all, placementMounts(all, fm.watchRoots), fm.watchRoots)
	found := unresolvedPlacementFindings(t, alerts)
	if len(found) != 1 || !strings.Contains(found[0].Message, "/srv/site") {
		t.Fatalf("findings %+v, want one for the covered-over root", found)
	}
}

// The fanotify backend reads a filesystem without a whole mount through the
// first watch root's own mount. A second root on another bind of that
// filesystem reads back under the first, so it is reported as uncovered.
func TestUncoveredPlacementRootBesideSubtreeAnchor(t *testing.T) {
	alerts := make(chan alert.Finding, 8)
	fm := placementTestMonitor(alerts)
	dev := unix.Mkdev(253, 1)
	fm.watchRoots = []watchRootMark{{path: "/srv/a", device: dev}, {path: "/srv/a/sub", device: dev}, {path: "/srv/b", device: dev}}
	all := []mountEntry{
		{Dev: dev, Root: "/x", MountPoint: "/srv/a"},
		{Dev: dev, Root: "/y", MountPoint: "/srv/b"},
	}
	fm.reportUncoveredPlacementRoots(all, all[:1], fm.watchRoots)
	found := unresolvedPlacementFindings(t, alerts)
	if len(found) != 1 || !strings.Contains(found[0].Message, "/srv/b") {
		t.Fatalf("findings %+v, want one for the root outside the anchor mount", found)
	}
}

// cPanel's securetmp binds /tmp onto /var/tmp: two whole-filesystem mounts of
// one device. Placements on it resolve under the first, which shows both roots.
func TestPlacementSecureTmpBindIsCovered(t *testing.T) {
	alerts := make(chan alert.Finding, 8)
	fm := placementTestMonitor(alerts)
	root, tmp := unix.Mkdev(8, 2), unix.Mkdev(7, 0)
	fm.watchRoots = []watchRootMark{{path: "/tmp", device: tmp}, {path: "/var/tmp", device: tmp}}
	all := []mountEntry{
		{Dev: root, Root: "/", MountPoint: "/"},
		{Dev: tmp, Root: "/", MountPoint: "/tmp"},
		{Dev: tmp, Root: "/", MountPoint: "/var/tmp"},
	}
	mounts, roots, err := bpfPlacementMounts(all, fm.watchRoots)
	if err != nil {
		t.Fatal(err)
	}
	if want := all[1:2]; !slices.Equal(mounts, want) {
		t.Fatalf("placement mounts %+v, want %+v", mounts, want)
	}
	fm.reportUncoveredPlacementRoots(all, mounts, roots)
	if found := unresolvedPlacementFindings(t, alerts); len(found) != 0 {
		t.Fatalf("second whole mount of the device reported uncovered: %+v", found)
	}
}

// Kernel paths never contain a watch root's symlink alias, so the BPF
// backend matches roots by their resolved names, as the fanotify one does.
func TestBPFPlacementMountsFollowSymlinkWatchRoot(t *testing.T) {
	parent, target := t.TempDir(), t.TempDir()
	alias := filepath.Join(parent, "alias")
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	dev, err := statDevice(target)
	if err != nil {
		t.Fatal(err)
	}
	alerts := make(chan alert.Finding, 8)
	fm := placementTestMonitor(alerts)
	fm.watchRoots = []watchRootMark{{path: alias, device: dev}}
	all := []mountEntry{
		{Dev: dev + 1, Root: "/", MountPoint: parent},
		{Dev: dev, Root: "/", MountPoint: target},
	}
	mounts, roots, err := bpfPlacementMounts(all, fm.watchRoots)
	if err != nil {
		t.Fatal(err)
	}
	if want := all[1:]; !slices.Equal(mounts, want) {
		t.Fatalf("placement mounts %+v, want %+v", mounts, want)
	}
	fm.reportUncoveredPlacementRoots(all, mounts, roots)
	if found := unresolvedPlacementFindings(t, alerts); len(found) != 0 {
		t.Fatalf("symlinked watch root reported uncovered: %+v", found)
	}
	if fm.watchRoots[0].path != alias {
		t.Fatalf("close-write roots changed to %+v", fm.watchRoots)
	}
	missing := []watchRootMark{{path: filepath.Join(parent, "missing")}}
	if _, _, err := bpfPlacementMounts(all, missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unresolvable watch root error = %v, want not-exist", err)
	}
}
