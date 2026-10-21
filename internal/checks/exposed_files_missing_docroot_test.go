package checks

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
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
