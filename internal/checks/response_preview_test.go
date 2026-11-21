package checks

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// previewHeaderDigests returns the before and after digests named in the
// first file header pair of a preview.
func previewHeaderDigests(t *testing.T, preview string) (before, after string) {
	t.Helper()
	lines := strings.Split(preview, "\n")
	for i := 0; i+1 < len(lines); i++ {
		if strings.HasPrefix(lines[i], "--- ") && strings.HasPrefix(lines[i+1], "+++ ") {
			_, before, _ = strings.Cut(lines[i], "\tsha256:")
			_, after, _ = strings.Cut(lines[i+1], "\tsha256:")
			return before, after
		}
	}
	t.Fatalf("no unified diff headers in preview:\n%s", preview)
	return "", ""
}

// File content and names are tenant-controlled. A preview printed to an
// operator's terminal must not carry escape sequences, carriage returns, bidi
// overrides or invalid UTF-8 that could rewrite or hide what the operator reads.
func TestRenderChangeDiffEscapesTerminalControls(t *testing.T) {
	path := "/home/u/public_html/\x1b[2J\n+++ forged.htaccess"
	before := []byte("keep\n")
	after := []byte("keep\nadd \x1b]0;title\x07 \r hidden \u202e evil \xff\n")

	diff, err := renderChangeDiff(path, before, after)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !utf8.ValidString(diff) {
		t.Fatalf("preview carries invalid UTF-8: %q", diff)
	}
	for _, r := range diff {
		if r != '\n' && r != '\t' && !unicode.IsPrint(r) {
			t.Fatalf("preview carries unescaped %U: %q", r, diff)
		}
	}
	for _, want := range []string{
		"--- /home/u/public_html/\\x1b[2J\\n+++ forged.htaccess\t",
		"\n+add \\x1b]0;title\\a \\r hidden \\u202e evil \\xff\n",
	} {
		if !strings.Contains(diff, want) {
			t.Errorf("preview missing %q:\n%s", want, diff)
		}
	}
}

func TestRenderChangeDiffRefusesBinaryContent(t *testing.T) {
	for name, tc := range map[string][2][]byte{
		"before": {[]byte("a\x00b\n"), []byte("a\n")},
		"after":  {[]byte("a\n"), []byte("a\x00b\n")},
	} {
		if _, err := renderChangeDiff("/home/u/x", tc[0], tc[1]); !errors.Is(err, errPreviewBinary) {
			t.Errorf("%s: err = %v, want the binary refusal", name, err)
		}
	}
}

func TestRenderChangeDiffNamesBothDigests(t *testing.T) {
	before := []byte("one\ntwo\nthree\n")
	after := []byte("one\nthree\n")
	diff, err := renderChangeDiff("/home/u/x.php", before, after)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	gotBefore, gotAfter := previewHeaderDigests(t, diff)
	if gotBefore != sha256Hex(before) || gotAfter != sha256Hex(after) {
		t.Errorf("header digests = %s, %s; want %s, %s", gotBefore, gotAfter, sha256Hex(before), sha256Hex(after))
	}
	if !strings.Contains(diff, "\n-two\n") || strings.Contains(diff, "\n-one\n") {
		t.Errorf("diff does not remove exactly the changed line:\n%s", diff)
	}
}

// assertNothingWritten checks that a preview left the file, the backup
// directory and the action log as they were.
func assertNothingWritten(t *testing.T, sink *recordingSink, path, content, backupDir string) {
	t.Helper()
	if got := readFile(t, path); got != content {
		t.Errorf("preview changed %s: %q", path, got)
	}
	if entries, err := os.ReadDir(backupDir); err == nil && len(entries) != 0 {
		t.Errorf("preview wrote %d backup entries", len(entries))
	}
	if len(sink.records) != 0 {
		t.Errorf("preview recorded %d actions", len(sink.records))
	}
}

// assertAppliedMatchesPreview checks the one action record the clean wrote
// against the digests the preview named.
func assertAppliedMatchesPreview(t *testing.T, sink *recordingSink, path, preview string) {
	t.Helper()
	if len(sink.records) != 1 {
		t.Fatalf("clean recorded %d actions, want 1", len(sink.records))
	}
	rec := sink.records[0]
	before, after := previewHeaderDigests(t, preview)
	if rec.Before == nil || rec.Before.Digest != before {
		t.Errorf("recorded before = %+v, preview named %s", rec.Before, before)
	}
	if rec.After == nil || rec.After.Digest != after {
		t.Errorf("recorded after = %+v, preview named %s", rec.After, after)
	}
	if got := sha256Hex([]byte(readFile(t, path))); got != after {
		t.Errorf("written content digest %s, preview named %s", got, after)
	}
}

// A preview shows the bytes the clean then writes: the digests in its headers
// are the ones the applied action records.
func TestPreviewCleanInfectedFileMatchesTheAppliedAction(t *testing.T) {
	sink := withActionSink(t)
	qdir := mustEvalSymlinks(t, t.TempDir())
	withQuarantineDirT(t, qdir)
	const infected = "<?php\n@include(\"/tmp/x\");\necho 'site';\n"
	path := mustEvalSymlinks(t, writeTempPHP(t, infected))

	diff, err := PreviewCleanInfectedFile(path)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if !strings.Contains(diff, "\n-@include(\"/tmp/x\");\n") || !strings.Contains(diff, "\n echo 'site';\n") {
		t.Fatalf("preview does not show the removal in context:\n%s", diff)
	}
	assertNothingWritten(t, sink, path, infected, qdir)

	if res := CleanInfectedFile(path); !res.Cleaned {
		t.Fatalf("clean: %+v", res)
	}
	assertAppliedMatchesPreview(t, sink, path, diff)
}

// An injection padded with NUL bytes is still cleaned, but its change cannot
// be shown. The preview fails and changes nothing.
func TestPreviewCleanInfectedFileFailsOnBinaryContent(t *testing.T) {
	sink := withActionSink(t)
	qdir := mustEvalSymlinks(t, t.TempDir())
	withQuarantineDirT(t, qdir)
	const infected = "<?php\n\x00\x0b@include(\"/tmp/x\");\necho 'site';\n"
	path := mustEvalSymlinks(t, writeTempPHP(t, infected))

	if diff, err := PreviewCleanInfectedFile(path); !errors.Is(err, errPreviewBinary) {
		t.Fatalf("preview = %q, %v; want the binary refusal", diff, err)
	}
	assertNothingWritten(t, sink, path, infected, qdir)
}

func TestPreviewCleanInfectedFileReportsTheCleanersRefusal(t *testing.T) {
	sink := withActionSink(t)
	qdir := mustEvalSymlinks(t, t.TempDir())
	withQuarantineDirT(t, qdir)
	const clean = "<?php\necho 'site';\n"
	path := mustEvalSymlinks(t, writeTempPHP(t, clean))

	if _, err := PreviewCleanInfectedFile(path); err == nil || !strings.Contains(err.Error(), "no known injection patterns") {
		t.Fatalf("preview err = %v, want the cleaner's refusal", err)
	}
	assertNothingWritten(t, sink, path, clean, qdir)
}

func TestPreviewCleanHtaccessFileMatchesTheAppliedAction(t *testing.T) {
	sink := withActionSink(t)
	root := vpTestEnv(t)
	const body = "# keep\nErrorDocument 404 https://phish.example.tk/oops.html\n# end\n"
	path := writeHtaccess(t, root, "site", body)

	diff, err := PreviewCleanHtaccessFile(path)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if !strings.Contains(diff, "\n-ErrorDocument 404 https://phish.example.tk/oops.html\n") {
		t.Fatalf("preview does not show the removed directive:\n%s", diff)
	}
	assertNothingWritten(t, sink, path, body, htaccessBackupDirRoot)

	if res := CleanHtaccessFile(path); !res.Success {
		t.Fatalf("clean: %+v", res)
	}
	assertAppliedMatchesPreview(t, sink, path, diff)
}

func TestPreviewCleanHtaccessFileFailsOnBinaryContent(t *testing.T) {
	sink := withActionSink(t)
	root := vpTestEnv(t)
	const body = "# \x00\nErrorDocument 404 https://phish.example.tk/oops.html\n"
	path := writeHtaccess(t, root, "site", body)

	if diff, err := PreviewCleanHtaccessFile(path); !errors.Is(err, errPreviewBinary) {
		t.Fatalf("preview = %q, %v; want the binary refusal", diff, err)
	}
	assertNothingWritten(t, sink, path, body, htaccessBackupDirRoot)
}

func readRollbackMeta(t *testing.T) QuarantineMeta {
	t.Helper()
	entries, err := os.ReadDir(htaccessBackupDirRoot)
	if err != nil {
		t.Fatalf("read backup dir: %v", err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".meta") {
			var meta QuarantineMeta
			if err := json.Unmarshal([]byte(readFile(t, filepath.Join(htaccessBackupDirRoot, entry.Name()))), &meta); err != nil {
				t.Fatalf("decode rollback metadata: %v", err)
			}
			return meta
		}
	}
	t.Fatal("no rollback metadata")
	return QuarantineMeta{}
}

func TestVirtualPatchPreviewShowsTheDenyBlockItWrites(t *testing.T) {
	root := vpTestEnv(t)
	dir := filepath.Join(root, "dom")
	exposed := filepath.Join(dir, "config.php.old")
	mustWrite(t, exposed, "<?php $db='x';\n")
	const existing = "# user rules\nOptions -Indexes\n"
	htaccess := filepath.Join(dir, ".htaccess")
	mustWrite(t, htaccess, existing)
	findings := []alert.Finding{vpFinding("web_exposed_config_leak", exposed)}

	preview := VirtualPatchExposedFindings(&config.Config{}, findings, false)
	if len(preview) != 1 || !strings.HasPrefix(preview[0].Message, "VIRTUAL-PATCH (preview)") {
		t.Fatalf("preview actions = %+v", preview)
	}
	details := preview[0].Details
	for _, line := range strings.Split(strings.TrimSuffix(string(buildDenyBlock("config.php.old", false)), "\n"), "\n") {
		if !strings.Contains(details, "\n+"+line+"\n") {
			t.Fatalf("preview does not add %q:\n%s", line, details)
		}
	}
	if !strings.Contains(details, "\n Options -Indexes\n") {
		t.Fatalf("preview does not show the existing rules as context:\n%s", details)
	}
	if readFile(t, htaccess) != existing {
		t.Fatal("preview changed .htaccess")
	}
	if _, err := os.Stat(htaccessBackupDirRoot); !os.IsNotExist(err) {
		t.Fatalf("preview created rollback state: %v", err)
	}

	act := VirtualPatchExposedFindings(&config.Config{}, findings, true)
	if len(act) != 1 || !strings.HasPrefix(act[0].Message, "VIRTUAL-PATCH: denied") {
		t.Fatalf("apply actions = %+v", act)
	}
	before, after := previewHeaderDigests(t, details)
	if before != sha256Hex([]byte(existing)) {
		t.Errorf("preview before digest %s, want the original .htaccess", before)
	}
	if got := sha256Hex([]byte(readFile(t, htaccess))); got != after {
		t.Errorf("written .htaccess digest %s, preview named %s", got, after)
	}
	if meta := readRollbackMeta(t); meta.ExpectedCurrentSHA256 != "sha256:"+after {
		t.Errorf("rollback expects %s, preview named sha256:%s", meta.ExpectedCurrentSHA256, after)
	}

	if again := VirtualPatchExposedFindings(&config.Config{}, findings, false); len(again) != 0 {
		t.Fatalf("preview of an applied patch = %+v, want nothing", again)
	}
}

func TestVirtualPatchPreviewFailsWhenTheChangeCannotBeShown(t *testing.T) {
	root := vpTestEnv(t)
	dir := filepath.Join(root, "dom")
	exposed := filepath.Join(dir, "config.php.old")
	mustWrite(t, exposed, "<?php $db='x';\n")
	const existing = "# \x00\nOptions -Indexes\n"
	htaccess := filepath.Join(dir, ".htaccess")
	mustWrite(t, htaccess, existing)

	preview := VirtualPatchExposedFindings(&config.Config{}, []alert.Finding{vpFinding("web_exposed_config_leak", exposed)}, false)
	if len(preview) != 1 || !strings.HasPrefix(preview[0].Message, "VIRTUAL-PATCH preview failed:") {
		t.Fatalf("preview actions = %+v", preview)
	}
	if !strings.Contains(preview[0].Details, errPreviewBinary.Error()) {
		t.Fatalf("failure does not say why: %q", preview[0].Details)
	}
	if readFile(t, htaccess) != existing {
		t.Fatal("failed preview changed .htaccess")
	}
	if _, err := os.Stat(htaccessBackupDirRoot); !os.IsNotExist(err) {
		t.Fatalf("failed preview created rollback state: %v", err)
	}
}

func TestVirtualPatchPreviewShowsTheDurableParentDeny(t *testing.T) {
	root := vpTestEnv(t)
	archive, pluginHtaccess := ai1wmSite(t, root)
	parent := filepath.Join(root, "site", "wp-content", ".htaccess")

	preview := VirtualPatchExposedFindings(&config.Config{}, []alert.Finding{vpFinding("web_exposed_backup_archive", archive)}, false)
	if len(preview) != 1 || !strings.HasPrefix(preview[0].Message, "VIRTUAL-PATCH (preview)") {
		t.Fatalf("preview actions = %+v", preview)
	}
	details := preview[0].Details
	for _, want := range []string{
		"--- " + pluginHtaccess + "\tsha256:",
		"\n+" + vpBeginDir + "\n",
		"--- " + parent + "\tsha256:",
		"\n+" + vpBeginParent + " .wpress\n",
	} {
		if !strings.Contains(details, want) {
			t.Errorf("preview missing %q:\n%s", want, details)
		}
	}
	if readFile(t, pluginHtaccess) != ai1wmPluginHtaccess {
		t.Error("preview changed the plugin .htaccess")
	}
	if _, err := os.Stat(parent); !os.IsNotExist(err) {
		t.Errorf("preview created the parent .htaccess: %v", err)
	}
}

// Apply writes the plugin-directory deny even when the parent cannot take
// its durable deny, and says so. The preview reports the same partial result.
func TestVirtualPatchPreviewReportsAParentItCannotWrite(t *testing.T) {
	root := vpTestEnv(t)
	archive, pluginHtaccess := ai1wmSite(t, root)
	parent := filepath.Join(root, "site", "wp-content", ".htaccess")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatal(err)
	}

	preview := VirtualPatchExposedFindings(&config.Config{}, []alert.Finding{vpFinding("web_exposed_backup_archive", archive)}, false)
	if len(preview) != 1 || !strings.HasPrefix(preview[0].Message, "VIRTUAL-PATCH (preview)") {
		t.Fatalf("preview actions = %+v", preview)
	}
	details := preview[0].Details
	if !strings.Contains(details, "--- "+pluginHtaccess+"\tsha256:") {
		t.Errorf("preview misses the plugin-directory deny:\n%s", details)
	}
	if !strings.Contains(details, parent+" would not be written:") {
		t.Errorf("preview hides the parent failure:\n%s", details)
	}
}

func dbCleanPreview(t *testing.T, account, stored string) DBCleanResult {
	t.Helper()
	wpCfg := "<?php\ndefine( 'DB_NAME', '" + account + "db' );\ndefine( 'DB_USER', 'u' );\ndefine( 'DB_PASSWORD', 'p' );\ndefine( 'DB_HOST', 'localhost' );\n$table_prefix = 'wp_';\n"
	withMockOS(t, wpConfigFixture(t, account, wpCfg))
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, env ...string) ([]byte, error) {
			if name != "mysql" {
				return nil, nil
			}
			for _, a := range args {
				if strings.Contains(a, "SELECT option_value") {
					return []byte(stored + "\n"), nil
				}
				if strings.Contains(a, "UPDATE") || strings.Contains(a, "INSERT") {
					t.Errorf("preview ran a write: %s", a)
				}
			}
			return nil, nil
		},
	})
	return DBCleanOption(account, "widget_text", true)
}

func TestDBCleanOptionPreviewShowsTheCleanedValue(t *testing.T) {
	result := dbCleanPreview(t, "diffuser", `before <script src="https://evil.top/x.js"></script> after`)
	if !result.Success {
		t.Fatalf("preview failed: %+v", result)
	}
	details := result.Diff
	for _, want := range []string{
		"\n-before <script src=\"https://evil.top/x.js\"></script> after\n",
		"\n+before  after\n",
	} {
		if !strings.Contains(details, want) {
			t.Errorf("preview missing %q:\n%s", want, details)
		}
	}
}

func TestDBCleanOptionPreviewFailsOnBinaryContent(t *testing.T) {
	result := dbCleanPreview(t, "binuser", `<script src="https://evil.top/x.js"></script>\0`)
	if result.Success || !strings.Contains(result.Message, errPreviewBinary.Error()) {
		t.Fatalf("preview = %+v, want the binary refusal", result)
	}
}

func TestVirtualPatchPreviewChainsSharedFileChanges(t *testing.T) {
	root := vpTestEnv(t)
	dir := filepath.Join(root, "site")
	findings := []alert.Finding{
		vpFinding("web_exposed_db_dump", filepath.Join(dir, "first.sql")),
		vpFinding("web_exposed_db_dump", filepath.Join(dir, "second.sql")),
	}
	for _, f := range findings {
		mustWrite(t, f.FilePath, "fixture")
	}
	actions := VirtualPatchExposedFindings(nil, findings, false)
	if len(actions) != 2 {
		t.Fatalf("got %d actions", len(actions))
	}
	_, first := previewHeaderDigests(t, actions[0].Details)
	second, final := previewHeaderDigests(t, actions[1].Details)
	if first != second {
		t.Error("second patch does not start from first patch")
	}
	htaccess := filepath.Join(dir, ".htaccess")
	if _, err := os.Stat(htaccess); !os.IsNotExist(err) {
		t.Fatalf("preview wrote access file: %v", err)
	}
	if got := VirtualPatchExposedFindings(nil, findings, true); len(got) != 2 {
		t.Fatalf("apply: %+v", got)
	}
	if sha256Hex([]byte(readFile(t, htaccess))) != final {
		t.Error("final preview differs from applied file")
	}
}

func TestVirtualPatchPreviewDeduplicatesDirectoryDeny(t *testing.T) {
	root := vpTestEnv(t)
	first, _ := ai1wmSite(t, root)
	second := filepath.Join(filepath.Dir(first), "second.wpress")
	mustWrite(t, second, "fixture")
	findings := []alert.Finding{vpFinding("web_exposed_backup_archive", first), vpFinding("web_exposed_backup_archive", second)}
	if got := VirtualPatchExposedFindings(nil, findings, false); len(got) != 1 {
		t.Fatalf("got %d actions for the same deny rules", len(got))
	}
}

func TestAutoPatchPreviewExcludesTenantDirectives(t *testing.T) {
	root := vpTestEnv(t)
	dir := filepath.Join(root, "site\nextra")
	file := filepath.Join(dir, "archive.sql")
	mustWrite(t, file, "fixture")
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.VirtualPatchExposedFiles = config.VirtualPatchAuto
	for _, ending := range []string{"", "\n"} {
		body := "# operator-only comment" + ending
		mustWrite(t, filepath.Join(dir, ".htaccess"), body)
		got := AutoVirtualPatchExposedFiles(cfg, []alert.Finding{vpFinding("web_exposed_db_dump", file)})
		if len(got) != 1 {
			t.Fatalf("got %d findings", len(got))
		}
		if strings.Contains(got[0].Message, "\n") || strings.Contains(got[0].Details, "operator-only") {
			t.Error("alert includes tenant text outside the rule")
		}
		before, after := previewHeaderDigests(t, got[0].Details)
		if before != sha256Hex([]byte(body)) || after != sha256Hex(patchedHtaccessContent([]byte(body), true, buildDenyBlock("archive.sql", false))) || !strings.Contains(got[0].Details, "\n+Require all denied\n") {
			t.Error("alert does not identify the planned change")
		}
	}
}

func TestPreviewDBResultEscapesFields(t *testing.T) {
	got := FormatDBCleanResult(DBCleanResult{Message: "bad\rmessage", Database: "bad\nname", Details: []string{"URL: example\x1b[0m"}})
	if strings.ContainsAny(got, "\r\x1b") || strings.Contains(got, "bad\nname") {
		t.Fatalf("unsafe result: %q", got)
	}
}

func TestPatchPreviewRefusesSwappedParent(t *testing.T) {
	root := vpTestEnv(t)
	dir := filepath.Join(root, "site")
	target := filepath.Join(dir, "archive.sql")
	mustWrite(t, target, "fixture")
	other := filepath.Join(root, "other")
	mustWrite(t, filepath.Join(other, ".htaccess"), "# private context\n")
	old := fixAfterPathResolved
	t.Cleanup(func() { fixAfterPathResolved = old })
	fixAfterPathResolved = func(string) {
		if err := os.Rename(dir, dir+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(other, dir); err != nil {
			t.Fatal(err)
		}
	}
	got := VirtualPatchExposedFindings(nil, []alert.Finding{vpFinding("web_exposed_db_dump", target)}, false)
	if len(got) != 1 || !strings.Contains(got[0].Message, "preview failed") || strings.Contains(got[0].Details, "private context") {
		t.Fatal("preview followed a replaced directory")
	}
}

func TestPreviewDiffBoundsLineAllocations(t *testing.T) {
	body := []byte(strings.Repeat("\n", 1<<18))
	if diff, err := renderChangeDiff("input", body, append(body, 'x')); err == nil || diff != "" {
		t.Fatal("expected a bounded preview refusal")
	}
}

func TestCleanReadRefusesGrowthAfterOpen(t *testing.T) {
	path := mustEvalSymlinks(t, writeTempPHP(t, "<?php"))
	target, err := openCleanTarget(path)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	old := cleanMaxFileSize
	cleanMaxFileSize = target.Info.Size()
	t.Cleanup(func() { cleanMaxFileSize = old })
	if err := os.Truncate(path, cleanMaxFileSize+1); err != nil {
		t.Fatal(err)
	}
	if data, err := target.readForClean(); len(data) != 0 || !errors.Is(err, errFileResponseRefused) {
		t.Fatalf("read returned %d bytes, %v", len(data), err)
	}
}

func TestDBCleanOptionStopsOnWriteFailure(t *testing.T) {
	for _, failure := range []string{"INSERT", "UPDATE"} {
		t.Run(failure, func(t *testing.T) {
			const account = "fixture"
			const row = "before <script src=\"https://evil.top/x.js\"></script> after"
			withMockOS(t, wpConfigFixture(t, account, "<?php\ndefine('DB_NAME','fixture_db');\n$table_prefix='wp_';\n"))
			var writes []string
			withMockCmd(t, &mockCmd{runWithEnv: func(name string, args []string, _ ...string) ([]byte, error) {
				for _, a := range args {
					if strings.HasPrefix(a, "SELECT option_value") {
						return []byte(row + "\n"), nil
					}
					for _, kind := range []string{"INSERT", "UPDATE"} {
						if strings.HasPrefix(a, kind) {
							writes = append(writes, kind)
							if failure == kind {
								return nil, errors.New("write failed")
							}
						}
					}
				}
				return nil, nil
			}})
			got := DBCleanOption(account, "widget_text", false)
			want := "INSERT"
			if failure == "UPDATE" {
				want = "INSERT UPDATE"
			}
			if got.Success || strings.Join(writes, " ") != want {
				t.Fatalf("writes %v, success %v, message %s", writes, got.Success, got.Message)
			}
		})
	}
}

func TestDBPreviewPrintsDiffAtStartOfLine(t *testing.T) {
	r := dbCleanPreview(t, "diffuser", `before <script src="https://evil.top/x.js"></script> after`)
	out := FormatDBCleanResult(r)
	if !r.Success || !strings.Contains(out, "\n--- widget_text\tsha256:") || !strings.Contains(out, "\n+before  after\n") {
		t.Fatal("formatted preview is not a unified diff")
	}
}

func TestVirtualPatchReportsFailureWhenOnlyMissingRuleIsRefused(t *testing.T) {
	root := vpTestEnv(t)
	archive, primary := ai1wmSite(t, root)
	mustWrite(t, primary, string(buildDenyBlock(filepath.Base(archive), true)))
	parent := filepath.Join(filepath.Dir(filepath.Dir(primary)), ".htaccess")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	actions := VirtualPatchExposedFindings(nil, []alert.Finding{vpFinding("web_exposed_backup_archive", archive)}, false)
	if len(actions) != 1 || !strings.Contains(actions[0].Message, "preview failed:") || !strings.Contains(actions[0].Details, parent) {
		t.Error("preview did not report the refused rule")
	}
}

func TestCleanPreviewRefusesOverlongInputBeforeParsing(t *testing.T) {
	body := strings.Repeat("\n", maxPreviewLines+1)
	path := mustEvalSymlinks(t, writeTempPHP(t, body))
	if _, err := PreviewCleanInfectedFile(path); !errors.Is(err, errPreviewTooLarge) {
		t.Fatalf("wrong refusal for overlong input: %v", err)
	}
}
