package daemon

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestEngineRegroupsRemovedDirectoriesAfterBurstFiltering(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	root := "/home/alice/public_html"
	paths := []string{"pack/a.php", "pack/b.php", "pack/c.php", "pack/d.php", "other/e.php", "other/f.php", "lone/g.php", "pack/temp.php"}
	for _, tc := range []struct {
		name string
		keep []int
		want map[string]int // Finding path -> number of files (zero for a singleton).
	}{
		{"burst takes precedence", []int{0, 1, 2, 3, 4, 5, 6, 7}, map[string]int{".": 8}},
		{"below burst threshold", []int{0, 1, 2, 3, 4, 5, 6}, map[string]int{"pack": 4, "other": 2, "lone/g.php": 0}},
		{"other demotion stays separate", []int{0, 1, 4, 5, 6, 7}, map[string]int{"pack": 2, "other": 2, "lone/g.php": 0, "pack/temp.php": 0}},
		{"singleton fallback", []int{0}, map[string]int{"pack/a.php": 0}},
		{"all demoted files ignored", nil, map[string]int{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, got := newTestEngine(time.Minute)
			for i, path := range paths {
				c := freshDropperCandidate(now)
				c.Path, c.Docroot, c.Inode = filepath.Join(root, path), root, uint64(i+1)
				verdict := dropperDemotedDirRemoved
				if i == len(paths)-1 {
					verdict = dropperDemotedAtomicWrite
				}
				e.tr.HoldGone(c, verdict, now)
			}
			suspect := freshDropperCandidate(now)
			suspect.Path, suspect.Docroot = filepath.Join(root, "pack/shell.php"), root
			e.tr.HoldGone(suspect, dropperSuspect, now)
			findings := e.tr.FlushDue(now.Add(dropperGraceWindow))
			if len(findings) != 2 {
				t.Fatalf("got %d findings before filtering, want a burst and a suspect", len(findings))
			}
			keep := map[string]bool{suspect.Path: true}
			for _, i := range tc.keep {
				keep[filepath.Join(root, paths[i])] = true
			}
			// Model a suppression reload while the findings were held.
			e.ignorePath = func(path string) bool { return !keep[path] }
			for _, f := range findings {
				e.flushFinding(f)
			}
			if len(*got) != len(tc.want)+1 {
				t.Fatalf("alerts = %+v, want %d demoted findings and one suspect", *got, len(tc.want))
			}
			seen := make(map[string]bool)
			for _, a := range *got {
				if seen[a.path] {
					t.Fatalf("duplicate finding for %s", a.path)
				}
				seen[a.path] = true
				if a.path == suspect.Path {
					if a.sev != alert.Critical {
						t.Errorf("suspect severity = %v, want Critical", a.sev)
					}
					continue
				}
				rel, err := filepath.Rel(root, a.path)
				if err != nil {
					t.Fatal(err)
				}
				count, ok := tc.want[rel]
				if !ok || a.sev != alert.Warning || (count > 0 && !strings.HasPrefix(a.msg, fmt.Sprintf("%d ", count))) {
					t.Errorf("unexpected finding: %+v", a)
				}
				for _, path := range paths {
					full := filepath.Join(root, path)
					if !keep[full] && strings.Contains(a.details, full) {
						t.Errorf("ignored file %s leaked into details: %s", full, a.details)
					}
				}
			}
		})
	}
}

// WordPress unpacks a language pack flat into its own working directory and
// removes the whole directory when it is done with it. Each file was already
// demoted because its directory went away; reporting them one by one repeats
// the same event for every file in the pack.
func TestDropperFlushGroupsFilesOfOneRemovedDirectory(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	tr := newDropperTracker(3 * time.Minute)
	pack := "/home/alice/public_html/wp-content/upgrade/wordpress-7.0.4-ro_ro"
	other := "/home/alice/public_html/wp-content/upgrade/other"
	hold := func(path string, inode uint64, v dropperVerdict) {
		c := freshDropperCandidate(now)
		c.Path, c.Inode = path, inode
		tr.HoldGone(c, v, now)
	}
	for i, name := range []string{"ro_RO.l10n.php", "admin-ro_RO.l10n.php", "admin-network-ro_RO.l10n.php", "continents-cities-ro_RO.l10n.php"} {
		hold(filepath.Join(pack, name), uint64(100+i), dropperDemotedDirRemoved)
	}
	hold(filepath.Join(other, "lone.php"), 200, dropperDemotedDirRemoved)
	hold(filepath.Join(pack, "shell.php"), 300, dropperSuspect)

	got := tr.FlushDue(now.Add(dropperGraceWindow + time.Second))
	if len(got) != 3 {
		t.Fatalf("got %d findings, want the pack, the lone file and the suspect: %+v", len(got), got)
	}
	var grouped *dropperFinding
	singles := map[string]dropperVerdict{}
	for i := range got {
		if got[i].RemovedDir != "" {
			grouped = &got[i]
			continue
		}
		if len(got[i].Items) != 1 {
			t.Fatalf("ungrouped finding carries %d items", len(got[i].Items))
		}
		singles[got[i].Items[0].Cand.Path] = got[i].Items[0].Verdict
	}
	if grouped == nil || grouped.RemovedDir != pack || len(grouped.Items) != 4 {
		t.Fatalf("grouped finding = %+v, want the four files of %s", grouped, pack)
	}
	if singles[filepath.Join(other, "lone.php")] != dropperDemotedDirRemoved || singles[filepath.Join(pack, "shell.php")] != dropperSuspect {
		t.Fatalf("singles = %v, want the lone file and the suspect reported on their own", singles)
	}

	sev, msg, details, path := dropperAlertParams(*grouped)
	if sev != alert.Warning || path != pack {
		t.Errorf("severity, path = %v, %q; want Warning on %s", sev, path, pack)
	}
	if !strings.Contains(msg, "4 ") || !strings.Contains(msg, pack) {
		t.Errorf("message = %q, want the count and the directory", msg)
	}
	for _, name := range []string{"ro_RO.l10n.php", "continents-cities-ro_RO.l10n.php"} {
		if !strings.Contains(details, name) {
			t.Errorf("details = %q, want every file listed", details)
		}
	}
}

func TestEngineEmitsRemovedDirectoryGroupOnce(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	pack := "/home/alice/public_html/wp-content/upgrade/wordpress-7.0.4-ro_ro"
	group := func(names ...string) dropperFinding {
		f := dropperFinding{Docroot: "/home/alice/public_html", RemovedDir: pack}
		for i, name := range names {
			c := freshDropperCandidate(now)
			c.Path, c.Inode = filepath.Join(pack, name), uint64(100+i)
			f.Items = append(f.Items, dropperGone{Cand: c, Verdict: dropperDemotedDirRemoved})
		}
		return f
	}

	e, got := newTestEngine(time.Minute)
	e.ignorePath = func(p string) bool { return strings.HasSuffix(p, "ignored.php") }
	e.flushFinding(group("a.l10n.php", "b.l10n.php", "ignored.php"))
	if len(*got) != 1 {
		t.Fatalf("emitted %d alerts, want one for the directory: %+v", len(*got), *got)
	}
	if a := (*got)[0]; a.path != pack || a.sev != alert.Warning || !strings.Contains(a.msg, "2 ") || strings.Contains(a.details, "ignored.php") {
		t.Fatalf("alert = %+v, want a Warning on %s for the two unsuppressed files", a, pack)
	}

	e, got = newTestEngine(time.Minute)
	e.ignorePath = func(p string) bool { return strings.HasSuffix(p, "ignored.php") }
	e.flushFinding(group("a.l10n.php", "ignored.php"))
	if len(*got) != 1 || (*got)[0].path != filepath.Join(pack, "a.l10n.php") {
		t.Fatalf("alerts = %+v, want the one remaining file reported on its own", *got)
	}
}
