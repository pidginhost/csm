package checks

import (
	"context"
	"crypto/md5" // #nosec G501 -- wordpress.org publishes MD5 digests for core files
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

const wpCoreLineEndingsOfficial = "<?php\n/**\n * Synthetic core file.\n */\nfunction synthetic_core() {\n\treturn 1;\n}\n"

func wpCoreMD5(content string) string {
	sum := md5.Sum([]byte(content)) // #nosec G401 -- compared with the MD5 digests wordpress.org publishes
	return hex.EncodeToString(sum[:])
}

func withCRLF(content string) string { return strings.ReplaceAll(content, "\n", "\r\n") }

func wpCoreLineEndingsReport(rels ...string) string {
	var b strings.Builder
	for _, rel := range rels {
		b.WriteString("Warning: File doesn't verify against checksum: " + rel + "\n")
	}
	b.WriteString("Error: WordPress installation doesn't verify against checksums.\n")
	return b.String()
}

func writeWPCoreFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	mkdirTest(t, filepath.Dir(filepath.Join(dir, rel)))
	writeTestFile(t, filepath.Join(dir, rel), []byte(content))
}

// wpCoreLineEndingsFixture lays out installs on one release whose
// wp-includes/plugin.php holds content, serves their files from disk and
// answers wp-cli with output.
func wpCoreLineEndingsFixture(t *testing.T, installs int, content, output string) (*store.DB, []string) {
	t.Helper()
	db := setupPluginStore(t)
	roots, fs := wpCoreQueueFixtures(t, installs)
	fs.readFile = os.ReadFile
	dirs := make([]string, len(roots))
	for i, root := range roots {
		dirs[i] = filepath.Dir(root)
		writeWPCoreFile(t, dirs[i], "wp-includes/version.php", "<?php\n$wp_version = '6.5.2';\n")
		writeWPCoreFile(t, dirs[i], "wp-includes/plugin.php", content)
	}
	refused := refusedCommand(t)
	withMockCmd(t, &mockCmd{runContext: func(_ context.Context, name string, _ ...string) ([]byte, error) {
		if name == "wp" {
			return []byte(output), refused
		}
		return nil, nil
	}})
	return db, dirs
}

func stubWPCoreChecksums(t *testing.T, checksums map[string]string, err error) *atomic.Int32 {
	t.Helper()
	var calls atomic.Int32
	old := fetchWPCoreChecksums
	fetchWPCoreChecksums = func(version, locale string) ([]byte, map[string]string, error) {
		calls.Add(1)
		if version != "6.5.2" || locale != "en_US" {
			t.Errorf("checksums requested for %s/%s, want the release version.php names", version, locale)
		}
		return nil, checksums, err
	}
	t.Cleanup(func() { fetchWPCoreChecksums = old })
	return &calls
}

func wpCoreCoverageState(t *testing.T, db *store.DB, dir string) string {
	t.Helper()
	rows, err := db.WPVerification("core")
	if err != nil {
		t.Fatal(err)
	}
	return rows[dir].State
}

// An FTP client in ASCII mode rewrites every LF as CRLF. The code is the
// release's code, so the install is as verified as one wp-cli passes.
func TestCheckWPCoreIgnoresLineEndingOnlyCoreFile(t *testing.T) {
	db, dirs := wpCoreLineEndingsFixture(t, 1, withCRLF(wpCoreLineEndingsOfficial), wpCoreLineEndingsReport("wp-includes/plugin.php"))
	stubWPCoreChecksums(t, map[string]string{"wp-includes/plugin.php": wpCoreMD5(wpCoreLineEndingsOfficial)}, nil)

	if got := coreIntegrityFindings(CheckWPCore(withWPInstallCache(context.Background()), nil, nil)); len(got) != 0 {
		t.Fatalf("a core file that differs only in line endings was reported: %+v", got)
	}
	if state := wpCoreCoverageState(t, db, dirs[0]); state != "verified" {
		t.Errorf("coverage state = %q, want verified", state)
	}
	if size := GlobalCMSCache().Size(); size != 0 {
		t.Errorf("line-ending-only install added %d files to the realtime hash cache", size)
	}
}

// A matching prefix is not enough when wp-cli did not complete the integrity
// check. The modified-file finding stays until the whole result is trustworthy.
func TestCheckWPCoreLineEndingsRequireCompletedVerification(t *testing.T) {
	output := "Warning: File doesn't verify against checksum: wp-includes/plugin.php\n" +
		"Error: Failed to get core checksums: service unavailable\n"
	db, dirs := wpCoreLineEndingsFixture(t, 1, withCRLF(wpCoreLineEndingsOfficial), output)
	stubWPCoreChecksums(t, map[string]string{"wp-includes/plugin.php": wpCoreMD5(wpCoreLineEndingsOfficial)}, nil)

	got := coreIntegrityFindings(CheckWPCore(withWPInstallCache(context.Background()), nil, nil))
	if len(got) != 1 || got[0].FilePath != filepath.Join(dirs[0], "wp-includes", "plugin.php") {
		t.Fatalf("incomplete verification suppressed the modified-file finding: %+v", got)
	}
	if state := wpCoreCoverageState(t, db, dirs[0]); state != "unverified" {
		t.Errorf("coverage state = %q, want unverified", state)
	}
}

// Every way of failing to prove the file is the release's code keeps the
// finding exactly as wp-cli reported it.
func TestCheckWPCoreReportsCoreFileBeyondLineEndings(t *testing.T) {
	official := map[string]string{"wp-includes/plugin.php": wpCoreMD5(wpCoreLineEndingsOfficial)}
	// Its CRLF copy fills the read limit exactly, so code appended after it
	// sits where only the truncation check can see it.
	large := strings.Repeat("xy\n", wpCoreLineEndingsMaxBytes/4)
	for _, tc := range []struct {
		name, content string
		checksums     map[string]string
		fetchErr      error
	}{
		{"crlf_with_added_line", withCRLF(wpCoreLineEndingsOfficial + "function synthetic_added() {}\n"), official, nil},
		{"cr_away_from_lf", withCRLF(strings.Replace(wpCoreLineEndingsOfficial, "return 1", "return\r 1", 1)), official, nil},
		{"double_cr_before_lf", strings.ReplaceAll(withCRLF(wpCoreLineEndingsOfficial), "\r\n", "\r\r\n"), official, nil},
		{"lf_changed", wpCoreLineEndingsOfficial + "function synthetic_added() {}\n", official, nil},
		{"lf_matching_release", wpCoreLineEndingsOfficial, official, nil},
		{"fetch_failed", withCRLF(wpCoreLineEndingsOfficial), official, errors.New("HTTP 503")},
		{"path_not_in_release", withCRLF(wpCoreLineEndingsOfficial), map[string]string{"wp-includes/load.php": wpCoreMD5(wpCoreLineEndingsOfficial)}, nil},
		{"appended_past_read_limit", withCRLF(large) + "function synthetic_added() {}\r\n", map[string]string{"wp-includes/plugin.php": wpCoreMD5(large)}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, dirs := wpCoreLineEndingsFixture(t, 1, tc.content, wpCoreLineEndingsReport("wp-includes/plugin.php"))
			stubWPCoreChecksums(t, tc.checksums, tc.fetchErr)

			got := coreIntegrityFindings(CheckWPCore(withWPInstallCache(context.Background()), nil, nil))
			if len(got) != 1 {
				t.Fatalf("findings = %d, want 1: %+v", len(got), got)
			}
			if got[0].Severity != alert.Critical || got[0].FilePath != filepath.Join(dirs[0], "wp-includes", "plugin.php") {
				t.Errorf("finding = %+v, want Critical for the flagged file", got[0])
			}
			if state := wpCoreCoverageState(t, db, dirs[0]); state != "modified" {
				t.Errorf("coverage state = %q, want modified", state)
			}
		})
	}
}

// A line-ending copy needs no finding of its own, but the install still has
// another difference, so it is not counted as verified.
func TestCheckWPCoreLineEndingsWithOtherProblemStayModified(t *testing.T) {
	output := "Warning: File should not exist: wp-includes/leftover.php\n" + wpCoreLineEndingsReport("wp-includes/plugin.php")
	db, dirs := wpCoreLineEndingsFixture(t, 1, withCRLF(wpCoreLineEndingsOfficial), output)
	stubWPCoreChecksums(t, map[string]string{"wp-includes/plugin.php": wpCoreMD5(wpCoreLineEndingsOfficial)}, nil)

	got := coreIntegrityFindings(CheckWPCore(withWPInstallCache(context.Background()), nil, nil))
	if len(got) != 1 || got[0].FilePath != "" {
		t.Fatalf("findings = %+v, want only the collapsed extra-file finding", got)
	}
	if state := wpCoreCoverageState(t, db, dirs[0]); state != "modified" {
		t.Errorf("coverage state = %q, want modified", state)
	}
}

// Installs on one release share its checksums, and a release that cannot be
// fetched is not asked again for every flagged file.
func TestCheckWPCoreFetchesEachReleaseOnce(t *testing.T) {
	for _, tc := range []struct {
		name     string
		fetchErr error
		findings int
	}{
		{"fetched", nil, 0},
		{"failed", errors.New("HTTP 503"), 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wpCoreLineEndingsFixture(t, 2, withCRLF(wpCoreLineEndingsOfficial), wpCoreLineEndingsReport("wp-includes/plugin.php"))
			calls := stubWPCoreChecksums(t, map[string]string{"wp-includes/plugin.php": wpCoreMD5(wpCoreLineEndingsOfficial)}, tc.fetchErr)

			if got := coreIntegrityFindings(CheckWPCore(withWPInstallCache(context.Background()), nil, nil)); len(got) != tc.findings {
				t.Fatalf("findings = %d, want %d: %+v", len(got), tc.findings, got)
			}
			if n := calls.Load(); n != 1 {
				t.Errorf("checksum fetches = %d, want 1 for two installs on one release", n)
			}
		})
	}
}

// The report and version file live in an account-controlled tree. Neither a
// symlinked report path nor a symlinked version directory can redirect the
// privileged comparison outside the opened installation.
func TestWPCoreLineEndingsRefuseSymlinkedPaths(t *testing.T) {
	withMockOS(t, realOS{})
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, install, outside string) string
	}{
		{
			name: "final_core_file",
			setup: func(t *testing.T, install, outside string) string {
				writeWPCoreFile(t, install, "wp-includes/version.php", "<?php\n$wp_version = '6.5.2';\n")
				writeWPCoreFile(t, outside, "plugin.php", withCRLF(wpCoreLineEndingsOfficial))
				if err := os.Symlink(filepath.Join(outside, "plugin.php"), filepath.Join(install, "wp-includes", "plugin.php")); err != nil {
					t.Fatal(err)
				}
				return "wp-includes/plugin.php"
			},
		},
		{
			name: "core_file_parent",
			setup: func(t *testing.T, install, outside string) string {
				writeWPCoreFile(t, install, "wp-includes/version.php", "<?php\n$wp_version = '6.5.2';\n")
				writeWPCoreFile(t, outside, "plugin.php", withCRLF(wpCoreLineEndingsOfficial))
				if err := os.Symlink(outside, filepath.Join(install, "wp-admin")); err != nil {
					t.Fatal(err)
				}
				return "wp-admin/plugin.php"
			},
		},
		{
			name: "version_file_parent",
			setup: func(t *testing.T, install, outside string) string {
				writeWPCoreFile(t, install, "wp-login.php", withCRLF(wpCoreLineEndingsOfficial))
				writeWPCoreFile(t, outside, "version.php", "<?php\n$wp_version = '6.5.2';\n")
				if err := os.Symlink(outside, filepath.Join(install, "wp-includes")); err != nil {
					t.Fatal(err)
				}
				return "wp-login.php"
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			install := filepath.Join(base, "install")
			outside := filepath.Join(base, "outside")
			mkdirTest(t, install)
			mkdirTest(t, outside)
			rel := tc.setup(t, install, outside)
			stubWPCoreChecksums(t, map[string]string{rel: wpCoreMD5(wpCoreLineEndingsOfficial)}, nil)

			var releases wpCoreReleaseChecksums
			files, only := releases.lineEndingOnly(install, []byte(wpCoreLineEndingsReport(rel)))
			if only || files[rel] {
				t.Fatalf("symlinked %s was accepted as an in-install core file", rel)
			}
		})
	}
}

func wpCoreLineEndingsVerifyInstall(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	withWPVerifyAllowedRoots(t, tmp)
	dir := makeWPInstall(t, tmp, "alice")
	writeWPCoreFile(t, dir, "wp-includes/version.php", "<?php\n$wp_version = '6.5.2';\n")
	writeWPCoreFile(t, dir, "wp-includes/plugin.php", withCRLF(wpCoreLineEndingsOfficial))
	writeWPCoreFile(t, dir, "wp-includes/load.php", wpCoreLineEndingsOfficial+"function synthetic_added() {}\n")
	stubWPCoreChecksums(t, map[string]string{
		"wp-includes/plugin.php": wpCoreMD5(wpCoreLineEndingsOfficial),
		"wp-includes/load.php":   wpCoreMD5(wpCoreLineEndingsOfficial),
	}, nil)
	return dir
}

func TestVerifyWPCoreResolvesWhenOnlyLineEndingsDiffer(t *testing.T) {
	dir := wpCoreLineEndingsVerifyInstall(t)
	wpCoreVerifyMock(t, []byte(wpCoreLineEndingsReport("wp-includes/plugin.php")), refusedCommand(t))

	res := VerifyFinding("wp_core_integrity", "WordPress core file modified for alice", "Path: "+dir)
	if !res.Checked || !res.Resolved || !strings.Contains(res.Detail, "line endings") {
		t.Fatalf("line-ending-only differences must resolve and say so, got %+v", res)
	}
}

func TestVerifyWPCoreLineEndingsDoNotResolveOtherwise(t *testing.T) {
	for _, tc := range []struct {
		name, output string
		checked      bool
	}{
		{"modified_file_remains", wpCoreLineEndingsReport("wp-includes/plugin.php", "wp-includes/load.php"), true},
		{"run_incomplete", "Warning: File doesn't verify against checksum: wp-includes/plugin.php\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := wpCoreLineEndingsVerifyInstall(t)
			wpCoreVerifyMock(t, []byte(tc.output), refusedCommand(t))

			res := VerifyFinding("wp_core_integrity", "WordPress core file modified for alice", "Path: "+dir)
			if res.Resolved || res.Checked != tc.checked {
				t.Fatalf("got %+v, want unresolved with Checked=%v", res, tc.checked)
			}
		})
	}
}
