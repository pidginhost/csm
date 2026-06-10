package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withQuarantineDirT redirects quarantineDir for any test (linux or
// macOS). Distinct from withQuarantineDir (linux test file) to avoid
// duplicate symbol errors.
func withQuarantineDirT(t *testing.T, dir string) {
	t.Helper()
	old := quarantineDir
	quarantineDir = dir
	t.Cleanup(func() { quarantineDir = old })
}

func writeTempPHP(t *testing.T, content string) string {
	t.Helper()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "victim.php")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCleanInfectedFileMissingFileReturnsError(t *testing.T) {
	withQuarantineDirT(t, t.TempDir())
	res := CleanInfectedFile("/nonexistent/path/file.php")
	if res.Cleaned || !strings.Contains(res.Error, "cannot read file") {
		t.Errorf("expected read error, got %+v", res)
	}
}

// X5 regression: an attacker who controls the parent directory can swap
// the path for a symlink between detection and CleanInfectedFile's read.
// The cleaner must refuse the open instead of following the link, so
// neither the read of the link target nor the cleaned-content writeback
// ever touches a root-readable / root-writable file outside the user's
// home.
func TestCleanInfectedFileRefusesSymlinkSwap(t *testing.T) {
	qDir := t.TempDir()
	withQuarantineDirT(t, qDir)

	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.php")
	secret := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(secret, []byte("SHADOW-DATA"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, victim); err != nil {
		t.Skipf("symlink not supported on this fs: %v", err)
	}

	res := CleanInfectedFile(victim)
	if res.Cleaned {
		t.Errorf("symlink target must not be cleaned, got %+v", res)
	}
	if res.Error == "" {
		t.Errorf("expected error refusing symlink, got %+v", res)
	}

	// Secret content must not appear in any backup file.
	if res.BackupPath != "" {
		if data, err := os.ReadFile(res.BackupPath); err == nil {
			if strings.Contains(string(data), "SHADOW-DATA") {
				t.Errorf("symlink target leaked into backup %s", res.BackupPath)
			}
		}
	}
	if err := filepath.Walk(qDir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(p, ".meta") {
			return nil
		}
		data, rerr := os.ReadFile(p)
		if rerr == nil && strings.Contains(string(data), "SHADOW-DATA") {
			t.Errorf("symlink target leaked into quarantine file %s", p)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// Secret must remain unmodified.
	if data, err := os.ReadFile(secret); err != nil || string(data) != "SHADOW-DATA" {
		t.Errorf("secret tampered with: data=%q err=%v", string(data), err)
	}
}

// X5: CleanInfectedFile must refuse non-regular targets (directories,
// fifos, device nodes). The detector only flags regular files, so a
// non-regular shape at clean time means the path was swapped.
func TestCleanInfectedFileRefusesDirectory(t *testing.T) {
	withQuarantineDirT(t, t.TempDir())
	dir := t.TempDir()
	res := CleanInfectedFile(dir)
	if res.Cleaned {
		t.Errorf("directory must not be cleaned, got %+v", res)
	}
	if res.Error == "" {
		t.Errorf("expected error refusing non-regular target")
	}
}

func TestCleanInfectedFileRefusesSymlinkedParent(t *testing.T) {
	withQuarantineDirT(t, t.TempDir())

	root := t.TempDir()
	outside := filepath.Join(root, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	outsideFile := filepath.Join(outside, "victim.php")
	original := "<?php\n@include(\"/tmp/payload.txt\");\necho 'outside';\n"
	if err := os.WriteFile(outsideFile, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	linkParent := filepath.Join(root, "site")
	if err := os.Symlink(outside, linkParent); err != nil {
		t.Skipf("symlink not supported on this fs: %v", err)
	}

	res := CleanInfectedFile(filepath.Join(linkParent, "victim.php"))
	if res.Cleaned {
		t.Fatalf("symlinked parent must not be cleaned, got %+v", res)
	}
	if res.Error == "" {
		t.Fatalf("expected refusal for symlinked parent")
	}
	got, err := os.ReadFile(outsideFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original {
		t.Fatalf("outside file was modified through symlinked parent:\n%s", got)
	}
}

func TestCleanInfectedFilePreservesSpecialModeBits(t *testing.T) {
	withQuarantineDirT(t, t.TempDir())
	path := writeTempPHP(t, "<?php\n@include(\"/tmp/payload.txt\");\necho 'app';\n")
	mode := os.FileMode(0o755) | os.ModeSticky
	if err := os.Chmod(path, mode); err != nil {
		t.Skipf("special mode bit not supported on this fs: %v", err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode()&os.ModeSticky == 0 {
		t.Skip("filesystem did not preserve sticky bit on regular file")
	}

	res := CleanInfectedFile(path)
	if !res.Cleaned {
		t.Fatalf("expected cleaned, got %+v", res)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode()&os.ModeSticky == 0 {
		t.Fatalf("sticky bit was not preserved: mode=%v", after.Mode())
	}
	if after.Mode().Perm() != 0o755 {
		t.Fatalf("permissions = %v, want 0755", after.Mode().Perm())
	}
}

func TestWriteCleanedFileAtomicRefusesTargetSwap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "victim.php")
	original := "<?php\n@include(\"/tmp/payload.txt\");\necho 'app';\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	target, err := openCleanTarget(path)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	if removeErr := os.Remove(path); removeErr != nil {
		t.Fatal(removeErr)
	}
	replacement := "<?php\necho 'replacement';\n"
	if writeErr := os.WriteFile(path, []byte(replacement), 0o644); writeErr != nil {
		t.Fatal(writeErr)
	}

	if cleanErr := writeCleanedFileAtomic(target, []byte("<?php\necho 'app';\n")); cleanErr == nil {
		t.Fatal("expected refusal after target inode swap")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != replacement {
		t.Fatalf("replacement was overwritten: %q", got)
	}
}

func TestCleanInfectedFileNoInjectionsReturnsError(t *testing.T) {
	withQuarantineDirT(t, t.TempDir())
	path := writeTempPHP(t, "<?php\n// clean code\necho 'hello world';\n")

	res := CleanInfectedFile(path)
	if res.Cleaned {
		t.Errorf("clean file should not report Cleaned=true, got %+v", res)
	}
	if !strings.Contains(res.Error, "no known injection patterns") {
		t.Errorf("expected 'no known injection patterns' error, got %+v", res)
	}
	// Backup should have been written even though clean failed.
	if res.BackupPath == "" {
		t.Error("backup path should be populated even when no patterns found")
	}
	if _, err := os.Stat(res.BackupPath); err != nil {
		t.Errorf("backup file should exist: %v", err)
	}
}

func TestCleanInfectedFileRemovesIncludeInjection(t *testing.T) {
	withQuarantineDirT(t, t.TempDir())
	content := "<?php\n@include(\"/tmp/payload.txt\");\necho 'app';\n"
	path := writeTempPHP(t, content)

	res := CleanInfectedFile(path)
	if !res.Cleaned {
		t.Fatalf("expected cleaned, got %+v", res)
	}
	if len(res.Removals) == 0 {
		t.Error("expected at least one removal")
	}
	cleaned, _ := os.ReadFile(path)
	if strings.Contains(string(cleaned), "@include") {
		t.Errorf("@include should be stripped:\n%s", cleaned)
	}
	if !strings.Contains(string(cleaned), "echo 'app'") {
		t.Errorf("legitimate code should be preserved:\n%s", cleaned)
	}
}

func TestCleanInfectedFileRemovesAppendInjectionAfterCloseTag(t *testing.T) {
	withQuarantineDirT(t, t.TempDir())
	// Legitimate file ending with ?>, then a second <?php block appended.
	// removeAppendInjection scans content after the LAST ?> — so we must NOT
	// have a second ?> after the malicious payload.
	content := "<?php\necho 'legit content here';\n?>\n<?php @system($_GET['c']);\n"
	path := writeTempPHP(t, content)

	res := CleanInfectedFile(path)
	if !res.Cleaned {
		t.Fatalf("expected cleaned, got %+v", res)
	}
	cleaned, _ := os.ReadFile(path)
	cs := string(cleaned)
	if strings.Contains(cs, "@system") {
		t.Errorf("appended @system should be stripped:\n%s", cs)
	}
	if !strings.Contains(cs, "legit content here") {
		t.Errorf("legitimate code should be preserved:\n%s", cs)
	}
}

func TestCleanInfectedFileRemovesChrChain(t *testing.T) {
	withQuarantineDirT(t, t.TempDir())
	// chr() chain on standalone line — at least 5 chr() calls concatenated.
	chrLine := strings.Repeat("chr(115).", 6) + "chr(116);"
	// Pad with junk so the line passes the >80-char gate via removeMultiLayerBase64
	// path (chrChain regex itself has no length gate but the function does).
	content := "<?php\n" +
		"// legit header comment that should survive cleaning operations safely\n" +
		"$x = " + chrLine + " // long padding to ensure >80 char detection threshold met\n" +
		"echo 'app body';\n"
	path := writeTempPHP(t, content)

	res := CleanInfectedFile(path)
	if !res.Cleaned {
		t.Fatalf("expected cleaned, got %+v", res)
	}
	cleaned, _ := os.ReadFile(path)
	cs := string(cleaned)
	if strings.Contains(cs, "chr(115).chr(115)") {
		t.Errorf("chr() chain should be stripped:\n%s", cs)
	}
	if !strings.Contains(cs, "echo 'app body'") {
		t.Errorf("legitimate code preserved:\n%s", cs)
	}
}

func TestCleanInfectedFileRemovesSplitChrChainStatement(t *testing.T) {
	withQuarantineDirT(t, t.TempDir())
	content := "<?php\n" +
		"$fn =\n" +
		"chr(115)\n" +
		".chr(121)\n" +
		".chr(115)\n" +
		".chr(116)\n" +
		".chr(101)\n" +
		".chr(109)\n" +
		";\n" +
		"echo 'app body';\n"
	path := writeTempPHP(t, content)

	res := CleanInfectedFile(path)
	if !res.Cleaned {
		t.Fatalf("expected cleaned, got %+v", res)
	}
	cleaned, _ := os.ReadFile(path)
	cs := string(cleaned)
	if strings.Contains(cs, "$fn =") || strings.Contains(cs, "chr(115)") {
		t.Errorf("split chr() statement should be stripped:\n%s", cs)
	}
	if !strings.Contains(cs, "echo 'app body'") {
		t.Errorf("legitimate code should be preserved:\n%s", cs)
	}
}

func TestCleanInfectedFileBackupHasMetaSidecar(t *testing.T) {
	qdir := t.TempDir()
	withQuarantineDirT(t, qdir)
	path := writeTempPHP(t, "<?php\n@include(\"/tmp/x\");\n")

	res := CleanInfectedFile(path)
	if !res.Cleaned {
		t.Fatalf("expected cleaned, got %+v", res)
	}
	if _, err := os.Stat(res.BackupPath + ".meta"); err != nil {
		t.Errorf(".meta sidecar should exist next to backup: %v", err)
	}
}

func TestShouldCleanInsteadOfQuarantine(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/home/u/public_html/wp-includes/post.php", true},
		{"/home/u/public_html/wp-admin/options.php", true},
		{"/home/u/public_html/wp-content/plugins/foo/foo.php", true},
		{"/home/u/public_html/wp-content/themes/twenty/index.php", true},
		// Webshell name in a plugin dir → still quarantine (don't preserve).
		{"/home/u/public_html/wp-content/plugins/foo/c99.php", false},
		// Standalone files outside WP → quarantine.
		{"/home/u/public_html/dropper.php", false},
		{"/tmp/evil.php", false},
	}
	for _, c := range cases {
		if got := ShouldCleanInsteadOfQuarantine(c.path); got != c.want {
			t.Errorf("ShouldCleanInsteadOfQuarantine(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestFormatCleanResult(t *testing.T) {
	cases := []struct {
		name    string
		in      CleanResult
		mustHas []string
	}{
		{
			name:    "error",
			in:      CleanResult{Path: "/x/y.php", Error: "boom"},
			mustHas: []string{"FAILED", "/x/y.php", "boom"},
		},
		{
			name:    "noop",
			in:      CleanResult{Path: "/x/y.php"},
			mustHas: []string{"No changes made", "/x/y.php"},
		},
		{
			name: "cleaned",
			in: CleanResult{
				Path: "/x/y.php", Cleaned: true,
				BackupPath: "/q/y.php",
				Removals:   []string{"removed @include injection: @include(\"/tmp/x\")"},
			},
			mustHas: []string{"CLEANED", "/x/y.php", "Backup:", "/q/y.php", "removed @include"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := FormatCleanResult(c.in)
			for _, s := range c.mustHas {
				if !strings.Contains(got, s) {
					t.Errorf("output missing %q:\n%s", s, got)
				}
			}
		})
	}
}

func TestShannonEntropyBoundaries(t *testing.T) {
	if got := shannonEntropy(""); got != 0 {
		t.Errorf("empty string entropy should be 0, got %v", got)
	}
	if got := shannonEntropy("aaaa"); got != 0 {
		t.Errorf("uniform string entropy should be 0, got %v", got)
	}
	// Random-ish content should have entropy > 2.
	if got := shannonEntropy("abcdefghijklmnop"); got < 2 {
		t.Errorf("varied string entropy should be > 2, got %v", got)
	}
}

// An attacker drops a file whose scanned windows match a malware signature,
// then pads it to many gigabytes. CleanInfectedFile runs as root and
// previously did io.ReadAll on the whole file, then strings.Split + multiple
// regex passes, multiplying that into an OOM that kills the daemon. The size
// guard must refuse to read an oversized file so auto-response falls back to
// quarantine-by-rename, which never reads content.
func TestCleanInfectedFileRefusesOversizedFile(t *testing.T) {
	withQuarantineDirT(t, t.TempDir())

	old := cleanMaxFileSize
	cleanMaxFileSize = 1024
	t.Cleanup(func() { cleanMaxFileSize = old })

	tmp := t.TempDir()
	path := filepath.Join(tmp, "big.php")
	payload := []byte("<?php @include(base64_decode('aaaa')); ")
	payload = append(payload, make([]byte, int(cleanMaxFileSize)+1)...)
	if err := os.WriteFile(path, payload, 0644); err != nil {
		t.Fatal(err)
	}

	res := CleanInfectedFile(path)
	if res.Cleaned {
		t.Fatalf("oversized file must not be cleaned, got %+v", res)
	}
	if !strings.Contains(res.Error, "too large") {
		t.Fatalf("expected too-large error, got %q", res.Error)
	}
	// Must not have read the file into a backup: no backup written.
	if res.BackupPath != "" {
		t.Fatalf("oversized file must not be backed up, got %q", res.BackupPath)
	}
}

func TestCleanInfectedFileAcceptsFileUnderSizeLimit(t *testing.T) {
	withQuarantineDirT(t, t.TempDir())

	old := cleanMaxFileSize
	cleanMaxFileSize = 4096
	t.Cleanup(func() { cleanMaxFileSize = old })

	// A legitimate-sized file under the cap with an @include injection
	// must still clean, proving the guard is a ceiling, not a blanket
	// refusal.
	path := writeTempPHP(t, "<?php\n@include('/tmp/x');\necho 'hi';\n")
	res := CleanInfectedFile(path)
	if res.Error != "" {
		t.Fatalf("file under cap must clean, got error %q", res.Error)
	}
}

func TestContainsLongEncodedString(t *testing.T) {
	if containsLongEncodedString("short", 100) {
		t.Error("short string should not match minLength=100")
	}
	long := strings.Repeat("Ab12+/", 30)
	if !containsLongEncodedString(long, 100) {
		t.Errorf("180-char base64-like string should match minLength=100")
	}
}
