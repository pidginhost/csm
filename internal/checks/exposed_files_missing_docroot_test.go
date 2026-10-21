package checks

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// A domain the panel still maps after its document root was deleted serves
// nothing, so it is not a gap in the scan. Anything that could still hide a
// served file keeps the earlier findings.
func TestScanVhostsDocrootAbsence(t *testing.T) {
	cases := []struct {
		name       string
		setup      func(t *testing.T, base string) string
		incomplete bool
	}{
		{
			name: "missing docroot",
			setup: func(t *testing.T, base string) string {
				return filepath.Join(base, "deleted.example.com")
			},
		},
		{
			name: "missing parent of docroot",
			setup: func(t *testing.T, base string) string {
				return filepath.Join(base, "gone", "public_html")
			},
		},
		{
			name: "dangling docroot symlink",
			setup: func(t *testing.T, base string) string {
				link := filepath.Join(base, "public_html")
				if err := os.Symlink(filepath.Join(base, "removed"), link); err != nil {
					t.Fatal(err)
				}
				return link
			},
			incomplete: true,
		},
		{
			name: "dangling ancestor symlink",
			setup: func(t *testing.T, base string) string {
				link := filepath.Join(base, "account")
				if err := os.Symlink(filepath.Join(base, "removed"), link); err != nil {
					t.Fatal(err)
				}
				return filepath.Join(link, "public_html")
			},
			incomplete: true,
		},
		{
			name: "missing docroot under existing symlink",
			setup: func(t *testing.T, base string) string {
				link := filepath.Join(base, "account")
				if err := os.Symlink(base, link); err != nil {
					t.Fatal(err)
				}
				return filepath.Join(link, "gone", "public_html")
			},
			incomplete: true,
		},
		{
			name: "docroot symlink loop",
			setup: func(t *testing.T, base string) string {
				a := filepath.Join(base, "a")
				b := filepath.Join(base, "b")
				if err := os.Symlink(b, a); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(a, b); err != nil {
					t.Fatal(err)
				}
				return a
			},
			incomplete: true,
		},
		{
			name: "docroot is a file",
			setup: func(t *testing.T, base string) string {
				path := filepath.Join(base, "public_html")
				mustWrite(t, path, "not a directory")
				return path
			},
			incomplete: true,
		},
		{
			name: "docroot below a file",
			setup: func(t *testing.T, base string) string {
				parent := filepath.Join(base, "site")
				mustWrite(t, parent, "not a directory")
				return filepath.Join(parent, "public_html")
			},
			incomplete: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			docroot := tc.setup(t, t.TempDir())
			withFakeProbe(t, &fakeProbe{byPath: map[string]probeResult{}})
			ctx, collector := withIncompleteCheckCollector(context.Background())

			findings := scanVhostsForExposure(ctx, []vhost{{
				domain: "example.com", user: "alice", typ: "sub", docroot: docroot, ip: "192.0.2.10",
			}}, nil)

			if len(findings) != 0 {
				t.Fatalf("findings = %+v, want none", findings)
			}
			if got := collector.contains("exposed_files"); got != tc.incomplete {
				t.Fatalf("exposed_files incomplete = %v, want %v", got, tc.incomplete)
			}
		})
	}
}

// A deleted document root must not hide exposures in the docroots that still
// exist, and must not cost them their completeness.
func TestScanVhostsMissingDocrootKeepsOtherFindings(t *testing.T) {
	base := t.TempDir()
	live := filepath.Join(base, "alice", "public_html")
	mustWrite(t, filepath.Join(live, "backup.sql"), "-- dump\n")
	withFakeProbe(t, &fakeProbe{byPath: map[string]probeResult{
		"/backup.sql": {status: 200, contentType: "text/x-sql", reachable: true},
	}})
	ctx, collector := withIncompleteCheckCollector(context.Background())

	findings := scanVhostsForExposure(ctx, []vhost{
		{domain: "gone.example.com", user: "alice", typ: "sub", docroot: filepath.Join(base, "alice", "gone.example.com"), ip: "192.0.2.10"},
		{domain: "example.com", user: "alice", typ: "main", docroot: live, ip: "192.0.2.10"},
	}, nil)

	if len(findings) != 1 || findings[0].Check != "web_exposed_db_dump" {
		t.Fatalf("findings = %+v, want the live docroot's dump only", findings)
	}
	if collector.contains("exposed_files") {
		t.Fatal("a deleted mapped docroot must not mark exposed_files incomplete")
	}
}

// Only the document root itself may be absent. A subdirectory that vanishes
// between its listing and its read may have moved, taking its files with it.
func TestWalkExposureCandidatesVanishedSubdirIsAGap(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "uploads")
	mustWrite(t, filepath.Join(sub, "backup.sql"), "-- dump\n")
	withMockOS(t, &mockOS{readDir: func(name string) ([]os.DirEntry, error) {
		if name == sub {
			return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
		}
		return os.ReadDir(name)
	}})

	_, complete := walkExposureCandidates(context.Background(), root, 3)
	if complete {
		t.Fatal("a subdirectory that vanished mid-walk must leave the walk incomplete")
	}
}

func TestWalkExposureCandidatesRootReadErrors(t *testing.T) {
	for _, readErr := range []error{fs.ErrNotExist, fs.ErrPermission, syscall.ELOOP, syscall.ENOTDIR} {
		t.Run(readErr.Error(), func(t *testing.T) {
			root := t.TempDir()
			withMockOS(t, &mockOS{
				readDir: func(name string) ([]os.DirEntry, error) {
					return nil, &fs.PathError{Op: "readdir", Path: name, Err: readErr}
				},
				open: os.Open,
			})
			paths, complete := walkExposureCandidates(context.Background(), root, 3)
			if len(paths) != 0 || complete {
				t.Fatalf("walk = (%v, %v), want empty incomplete result for a root that exists", paths, complete)
			}
		})
	}
}

func TestWalkExposureCandidatesCancelledRootAbsence(t *testing.T) {
	root := filepath.Join(t.TempDir(), "gone")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			cancel()
			return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
		},
		open: os.Open,
	})
	if _, complete := walkExposureCandidates(ctx, root, 3); complete {
		t.Fatal("cancellation during the root read must leave the walk incomplete")
	}
}

func TestScanVhostsLiveSymlinkDocroot(t *testing.T) {
	base := t.TempDir()
	live := filepath.Join(base, "site")
	mustWrite(t, filepath.Join(live, "backup.sql"), "-- dump\n")
	link := filepath.Join(base, "public_html")
	if err := os.Symlink(live, link); err != nil {
		t.Fatal(err)
	}
	withFakeProbe(t, &fakeProbe{byPath: map[string]probeResult{
		"/backup.sql": {status: 200, contentType: "text/x-sql", reachable: true},
	}})
	ctx, collector := withIncompleteCheckCollector(context.Background())
	findings := scanVhostsForExposure(ctx, []vhost{{
		domain: "example.com", user: "alice", typ: "main", docroot: link, ip: "192.0.2.10",
	}}, nil)
	if len(findings) != 1 || findings[0].Check != "web_exposed_db_dump" || findings[0].FilePath != filepath.Join(link, "backup.sql") {
		t.Fatalf("findings = %+v, want the symlinked docroot's dump", findings)
	}
	if collector.contains("exposed_files") {
		t.Fatal("a readable symlinked docroot must still complete its scan")
	}
}

func TestExposedFilesRootAbsencePurgeAndThrottle(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		t.Run(fmt.Sprintf("symlink=%v", symlink), func(t *testing.T) {
			base := t.TempDir()
			root := filepath.Join(base, "gone")
			if symlink {
				if err := os.Symlink(filepath.Join(base, "missing"), root); err != nil {
					t.Fatal(err)
				}
			}
			mapReads := 0
			withMockOS(t, &mockOS{
				readFile: func(name string) ([]byte, error) {
					if name != userdataDomainsPath {
						return nil, fs.ErrNotExist
					}
					mapReads++
					return []byte(fmt.Sprintf("example.com: alice==root==main==example.com==%s==192.0.2.10:80==192.0.2.10:443", root)), nil
				},
				readDir: os.ReadDir,
				open:    os.Open,
			})
			st, err := state.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = st.Close() }()
			prior := alert.Finding{Check: "web_exposed_db_dump", FilePath: filepath.Join(root, "backup.sql"), Message: "prior exposure", Severity: alert.Critical}
			st.SetLatestFindings([]alert.Finding{prior})
			for i, tier := range []string{"deep", "reduced"} {
				findings, purge := runParallel(&config.Config{}, st, []namedCheck{{"exposed_files", CheckExposedFiles}}, tier, true)
				StoreLatestScanFindings(st, purge, findings)
				if got := slices.Contains(purge, prior.Check); got != (!symlink && i == 0) {
					t.Fatalf("cycle %d purge=%v, want exposure purge only on the first confirmed absence", i, purge)
				}
				if got := slices.ContainsFunc(st.LatestFindings(), func(f alert.Finding) bool { return f.Key() == prior.Key() }); got != symlink {
					t.Fatalf("cycle %d retained prior exposure=%v, want %v", i, got, symlink)
				}
			}
			wantReads := 1
			if symlink {
				wantReads = 2
			}
			if mapReads != wantReads {
				t.Fatalf("map reads=%d, want %d: only confirmed absence starts the throttle", mapReads, wantReads)
			}
		})
	}
}
