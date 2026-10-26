package checks

import (
	"context"
	"crypto/md5" // #nosec G501 -- wordpress.org publishes MD5 digests for core files
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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

// Some releases ship a file with CRLF endings; a copy that went through an LF
// conversion differs only in the other direction.
func TestCheckWPCoreIgnoresLFCopyOfCRLFRelease(t *testing.T) {
	db, dirs := wpCoreLineEndingsFixture(t, 1, wpCoreLineEndingsOfficial, wpCoreLineEndingsReport("wp-includes/plugin.php"))
	stubWPCoreChecksums(t, map[string]string{"wp-includes/plugin.php": wpCoreMD5(withCRLF(wpCoreLineEndingsOfficial))}, nil)

	if got := coreIntegrityFindings(CheckWPCore(withWPInstallCache(context.Background()), nil, nil)); len(got) != 0 {
		t.Fatalf("an LF copy of a CRLF release file was reported: %+v", got)
	}
	if state := wpCoreCoverageState(t, db, dirs[0]); state != "verified" {
		t.Errorf("coverage state = %q, want verified", state)
	}
}

// A file with any CR left in it is not a clean LF conversion, so only the
// CRLF-to-LF comparison applies to it.
func TestCheckWPCoreReportsMixedEndingsAgainstCRLFRelease(t *testing.T) {
	live := strings.Replace(withCRLF(wpCoreLineEndingsOfficial), "\r\n", "\n", 1)
	wpCoreLineEndingsFixture(t, 1, live, wpCoreLineEndingsReport("wp-includes/plugin.php"))
	stubWPCoreChecksums(t, map[string]string{"wp-includes/plugin.php": wpCoreMD5(withCRLF(wpCoreLineEndingsOfficial))}, nil)

	if got := coreIntegrityFindings(CheckWPCore(withWPInstallCache(context.Background()), nil, nil)); len(got) != 1 {
		t.Fatalf("findings = %+v, want the mixed-ending file reported", got)
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

// wp-cli lists a core file missing from the install on its own line. That is
// a known shape: the line-ending copy still needs no finding, while the
// missing file keeps the install from counting as verified.
func TestCheckWPCoreLineEndingsWithMissingCoreFileStayModified(t *testing.T) {
	output := "Warning: File doesn't exist: wp-admin/css/install-rtl.css\n" + wpCoreLineEndingsReport("wp-includes/plugin.php")
	db, dirs := wpCoreLineEndingsFixture(t, 1, withCRLF(wpCoreLineEndingsOfficial), output)
	stubWPCoreChecksums(t, map[string]string{"wp-includes/plugin.php": wpCoreMD5(wpCoreLineEndingsOfficial)}, nil)

	got := coreIntegrityFindings(CheckWPCore(withWPInstallCache(context.Background()), nil, nil))
	if len(got) != 0 {
		t.Fatalf("findings = %+v, want none for the line-ending copy", got)
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

type wpCoreLineEndingsLogLine struct {
	msg  string
	args []any
}

func (l wpCoreLineEndingsLogLine) String() string {
	return fmt.Sprint(append([]any{l.msg}, l.args...)...)
}

func captureWPCoreLineEndingsLog(t *testing.T) *[]wpCoreLineEndingsLogLine {
	t.Helper()
	var lines []wpCoreLineEndingsLogLine
	old := logWPCoreLineEndings
	logWPCoreLineEndings = func(msg string, args ...any) {
		lines = append(lines, wpCoreLineEndingsLogLine{msg: msg, args: args})
	}
	t.Cleanup(func() { logWPCoreLineEndings = old })
	return &lines
}

// A file the check could not prove stays reported with nothing to say why, so
// each one leaves a log line naming the file and the reason.
func TestWPCoreLineEndingsLogWhyFileStaysReported(t *testing.T) {
	withMockOS(t, realOS{})
	const rel = "wp-includes/plugin.php"
	const secretish = "PHP Warning: synthetic-db-password-in-output"
	official := map[string]string{rel: wpCoreMD5(wpCoreLineEndingsOfficial)}
	for _, tc := range []struct {
		name, content, output string
		checksums             map[string]string
		fetchErr              error
		want                  string
	}{
		{"beyond_line_endings", withCRLF(wpCoreLineEndingsOfficial + "function synthetic_added() {}\n"), wpCoreLineEndingsReport(rel), official, nil, "differs beyond line endings"},
		{"fetch_failed", withCRLF(wpCoreLineEndingsOfficial), wpCoreLineEndingsReport(rel), official, errors.New("HTTP 503"), "HTTP 503"},
		{"not_in_release", withCRLF(wpCoreLineEndingsOfficial), wpCoreLineEndingsReport(rel), map[string]string{"wp-includes/load.php": wpCoreMD5(wpCoreLineEndingsOfficial)}, nil, "not in the release checksums"},
		{"too_large", withCRLF(strings.Repeat("xy\n", wpCoreLineEndingsMaxBytes/3)), wpCoreLineEndingsReport(rel), official, nil, "larger than the read limit"},
		{"unrecognized_output", withCRLF(wpCoreLineEndingsOfficial), secretish + "\n" + wpCoreLineEndingsReport(rel), official, nil, "unrecognized"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			install := t.TempDir()
			writeWPCoreFile(t, install, "wp-includes/version.php", "<?php\n$wp_version = '6.5.2';\n")
			writeWPCoreFile(t, install, rel, tc.content)
			stubWPCoreChecksums(t, tc.checksums, tc.fetchErr)
			logged := captureWPCoreLineEndingsLog(t)

			var releases wpCoreReleaseChecksums
			if files, _ := releases.lineEndingOnly(install, []byte(tc.output)); files[rel] {
				t.Fatalf("%s was accepted as line endings only", rel)
			}
			if len(*logged) != 1 {
				t.Fatalf("logged %d lines, want 1: %v", len(*logged), *logged)
			}
			line := (*logged)[0].String()
			if !strings.Contains(line, install) || !strings.Contains(line, tc.want) {
				t.Errorf("log %q does not name the install and %q", line, tc.want)
			}
			if strings.Contains(line, "synthetic-db-password") {
				t.Errorf("log %q copied raw wp-cli output", line)
			}
		})
	}
}

func TestWPCoreLineEndingsProvenFileLogsNothing(t *testing.T) {
	withMockOS(t, realOS{})
	const rel = "wp-includes/plugin.php"
	install := t.TempDir()
	writeWPCoreFile(t, install, "wp-includes/version.php", "<?php\n$wp_version = '6.5.2';\n")
	writeWPCoreFile(t, install, rel, withCRLF(wpCoreLineEndingsOfficial))
	stubWPCoreChecksums(t, map[string]string{rel: wpCoreMD5(wpCoreLineEndingsOfficial)}, nil)
	logged := captureWPCoreLineEndingsLog(t)

	var releases wpCoreReleaseChecksums
	if files, only := releases.lineEndingOnly(install, []byte(wpCoreLineEndingsReport(rel))); !only || !files[rel] {
		t.Fatalf("line-ending copy not accepted: files=%v only=%v", files, only)
	}
	if len(*logged) != 0 {
		t.Errorf("proven file logged %v", *logged)
	}
}

// The verification parser accepts mismatch text inside other output. Logging
// must not treat that extracted text as a filename without release evidence.
func TestWPCoreLineEndingsLogDoesNotCopyUnlistedOutput(t *testing.T) {
	withMockOS(t, realOS{})
	const rel = "wp-includes/plugin.php"
	const privateOutput = "synthetic-private-output"
	for _, tc := range []struct{ name, line string }{
		{"embedded_current", "PHP Warning: doesn't verify against checksum: " + privateOutput},
		{"embedded_legacy", "PHP Warning: " + privateOutput + " doesn't verify against checksum."},
		{"trailing_output", "Warning: File doesn't verify against checksum: " + rel + " " + privateOutput},
	} {
		t.Run(tc.name, func(t *testing.T) {
			install := t.TempDir()
			writeWPCoreFile(t, install, "wp-includes/version.php", "<?php\n$wp_version = '6.5.2';\n")
			writeWPCoreFile(t, install, rel, withCRLF(wpCoreLineEndingsOfficial))
			stubWPCoreChecksums(t, map[string]string{rel: wpCoreMD5(wpCoreLineEndingsOfficial)}, nil)
			logged := captureWPCoreLineEndingsLog(t)

			var releases wpCoreReleaseChecksums
			files, only := releases.lineEndingOnly(install, []byte("\n"+tc.line+"\n"+wpCoreLineEndingsReport(rel)))
			if only || len(files) != 1 || !files[rel] {
				t.Fatalf("verification decisions changed: files=%v only=%v", files, only)
			}
			if len(*logged) != 1 {
				t.Fatalf("logged %d lines, want 1", len(*logged))
			}
			entry := (*logged)[0]
			if strings.Contains(entry.String(), privateOutput) {
				t.Error("log copied untrusted command output")
			}
			fields := make(map[string]any)
			for i := 0; i < len(entry.args); i += 2 {
				fields[entry.args[i].(string)] = entry.args[i+1]
			}
			if fields["line"] != 2 || fields["release"] != "6.5.2/en_US" || fields["path"] != strconv.QuoteToASCII(install) {
				t.Errorf("log does not identify the report line and release: %v", fields)
			}
			if _, ok := fields["file"]; ok {
				t.Error("log includes a filename not confirmed by the release")
			}
		})
	}
}

func TestWPCoreLineEndingsLogDoesNotCopyInvalidRelease(t *testing.T) {
	withMockOS(t, realOS{})
	const privateValue = "synthetic-private-value"
	for _, tc := range []struct{ name, content string }{
		{"version", "<?php\n$wp_version = '" + privateValue + "';\n"},
		{"locale", "<?php\n$wp_version = '6.5.2';\n$wp_local_package = '" + privateValue + "';\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			install := t.TempDir()
			writeWPCoreFile(t, install, "wp-includes/version.php", tc.content)
			calls := stubWPCoreChecksums(t, nil, nil)
			logged := captureWPCoreLineEndingsLog(t)

			var releases wpCoreReleaseChecksums
			files, only := releases.lineEndingOnly(install, []byte(wpCoreLineEndingsReport("wp-includes/plugin.php")))
			if only || len(files) != 0 || calls.Load() != 0 {
				t.Fatalf("invalid release reached verification: files=%v only=%v fetches=%d", files, only, calls.Load())
			}
			if len(*logged) != 1 {
				t.Fatalf("logged %d lines, want 1", len(*logged))
			}
			line := (*logged)[0].String()
			if strings.Contains(line, privateValue) {
				t.Error("log copied invalid release content")
			}
			if !strings.Contains(line, "invalid release metadata") {
				t.Errorf("log does not explain the parse failure: %s", line)
			}
		})
	}
}

// Tenant directory names must not create extra records or terminal controls
// in the default text logger, including when an OS error repeats the path.
func TestWPCoreLineEndingsLogQuotesControlCharacters(t *testing.T) {
	withMockOS(t, realOS{})
	const rel = "wp-includes/plugin.php"
	for _, failure := range []string{"unrecognized_output", "unlisted_file", "version_read", "core_read", "modified_file"} {
		t.Run(failure, func(t *testing.T) {
			install := filepath.Join(t.TempDir(), "install\nforged\t\x1b[31m")
			mkdirTest(t, install)
			if failure != "version_read" {
				writeWPCoreFile(t, install, "wp-includes/version.php", "<?php\n$wp_version = '6.5.2';\n")
			}
			if failure != "core_read" {
				writeWPCoreFile(t, install, rel, withCRLF(wpCoreLineEndingsOfficial+"function synthetic_added() {}\n"))
			}
			checksums := map[string]string{rel: wpCoreMD5(wpCoreLineEndingsOfficial)}
			if failure == "unlisted_file" {
				checksums = nil
			}
			stubWPCoreChecksums(t, checksums, nil)
			logged := captureWPCoreLineEndingsLog(t)
			output := wpCoreLineEndingsReport(rel)
			if failure == "unrecognized_output" {
				output = "PHP Warning: synthetic diagnostic\n" + output
			}

			var releases wpCoreReleaseChecksums
			files, only := releases.lineEndingOnly(install, []byte(output))
			if only || len(files) != 0 {
				t.Fatalf("failed verification was accepted: files=%v only=%v", files, only)
			}
			if len(*logged) != 1 {
				t.Fatalf("logged %d lines, want 1", len(*logged))
			}
			line := (*logged)[0].String()
			if strings.ContainsAny(line, "\r\n\t\x1b") {
				t.Error("log contains unescaped control characters")
			}
			if !strings.Contains(line, strconv.QuoteToASCII(install)) {
				t.Error("log does not identify the quoted install path")
			}
		})
	}
}
