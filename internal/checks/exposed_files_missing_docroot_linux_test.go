//go:build linux

package checks

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// A worker with a different cwd can serve a process-relative link that looks
// absent to the scanner. The scan must not retire its earlier findings.
func TestExposureDocrootProcessRelativeSymlink(t *testing.T) {
	if root := os.Getenv("CSM_TEST_EXPOSURE_DOCROOT"); root != "" {
		info, err := os.Stat(filepath.Join(root, "backup.sql"))
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("worker cannot serve the dump: info=%v err=%v", info, err)
		}
		return
	}

	for _, ancestor := range []bool{false, true} {
		name := "docroot"
		if ancestor {
			name = "ancestor"
		}
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			scanner := filepath.Join(base, "scanner")
			if err := os.Mkdir(scanner, 0o755); err != nil {
				t.Fatal(err)
			}
			t.Chdir(scanner)
			worker := filepath.Join(base, "worker")
			mustWrite(t, filepath.Join(worker, "site", "backup.sql"), "-- dump\n")
			root := filepath.Join(base, "public_html")
			target := "/proc/self/cwd/site"
			if ancestor {
				target = "/proc/self/cwd"
			}
			if err := os.Symlink(target, root); err != nil {
				t.Fatal(err)
			}
			if ancestor {
				root = filepath.Join(root, "site")
			}
			if _, err := os.ReadDir(root); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("scanner ReadDir error = %v, want ENOENT", err)
			}

			cmd := exec.Command(os.Args[0], "-test.run=^TestExposureDocrootProcessRelativeSymlink$")
			cmd.Dir = worker
			cmd.Env = append(os.Environ(), "CSM_TEST_EXPOSURE_DOCROOT="+root)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("worker lookup: %v\n%s", err, output)
			}

			ctx, collector := withIncompleteCheckCollector(context.Background())
			findings := scanVhostsForExposure(ctx, []vhost{{
				domain: "example.com", user: "alice", typ: "main", docroot: root, ip: "192.0.2.10",
			}}, nil)
			if len(findings) != 0 {
				t.Fatalf("findings = %+v, want none", findings)
			}
			if !collector.contains("exposed_files") {
				t.Fatal("a root that is accessible to the worker must keep earlier exposure findings")
			}
		})
	}
}
