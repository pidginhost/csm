package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

type fullScanFileInfo struct {
	mode os.FileMode
}

func (i fullScanFileInfo) Name() string       { return "special" }
func (i fullScanFileInfo) Size() int64        { return 0 }
func (i fullScanFileInfo) Mode() os.FileMode  { return i.mode }
func (i fullScanFileInfo) ModTime() time.Time { return time.Time{} }
func (i fullScanFileInfo) IsDir() bool        { return i.mode.IsDir() }
func (i fullScanFileInfo) Sys() any           { return nil }

type fullScanLstatOS struct {
	OS
	info os.FileInfo
}

func (f fullScanLstatOS) Lstat(string) (os.FileInfo, error) { return f.info, nil }

// `csm scan --full --quarantine` runs unattended, so it gets the same bar the
// scheduled auto-response applies: only a Critical finding (two converging
// indicators) may move a file. A single-indicator High is a review item.
func TestQuarantineFindingFile_RequiresCritical(t *testing.T) {
	root, _ := redirectQuarantineForFullScan(t)
	src := filepath.Join(root, "maybe.php")
	if err := os.WriteFile(src, []byte("<?php echo base64_decode($x);"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, eligible := QuarantineFindingFile(alert.Finding{Severity: alert.High, Check: "suspicious_php_content", FilePath: src})
	if eligible {
		t.Fatal("a High single-indicator finding must be left for review, not quarantined")
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("file must be untouched: %v", err)
	}
}

// A directory finding names a whole tree; moving it unattended takes a site
// offline on one heuristic. That stays an operator decision.
func TestQuarantineFindingFile_RefusesDirectories(t *testing.T) {
	root, _ := redirectQuarantineForFullScan(t)
	dir := filepath.Join(root, "paypal-partners")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<form>"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, eligible := QuarantineFindingFile(alert.Finding{Severity: alert.Critical, Check: "phishing_directory", FilePath: dir})
	if eligible {
		t.Fatal("a directory must be left for review, not moved")
	}
	if _, err := os.Stat(filepath.Join(dir, "index.html")); err != nil {
		t.Fatalf("directory must be untouched: %v", err)
	}
}

func TestQuarantineFindingFile_SkipsSymlinks(t *testing.T) {
	root, _ := redirectQuarantineForFullScan(t)
	target := filepath.Join(root, "real.php")
	if err := os.WriteFile(target, []byte("<?php echo 1;"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "shell.php")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	_, eligible := QuarantineFindingFile(alert.Finding{Severity: alert.Critical, Check: "webshell", FilePath: link})
	if eligible {
		t.Fatal("a symlink must be left for review")
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("symlink must be untouched: %v", err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("symlink target must be untouched: %v", err)
	}
}

// A plugin or theme file that carries an injection is cleaned in place, as
// the scheduled path does; moving the file breaks the site while the injected
// line is the only thing that had to go.
func TestQuarantineFindingFile_CleansPluginFileInsteadOfMoving(t *testing.T) {
	root, qdir := redirectQuarantineForFullScan(t)
	pluginDir := filepath.Join(root, "public_html", "wp-content", "plugins", "akismet")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(pluginDir, "akismet.php")
	body := "<?php\n@include(\"/tmp/.x.php\");\n/* Plugin Name: Akismet */\necho 'ok';\n"
	if err := os.WriteFile(src, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	result, eligible := QuarantineFindingFile(alert.Finding{Severity: alert.Critical, Check: "obfuscated_php", FilePath: src})
	if !eligible || !result.Success {
		t.Fatalf("plugin file must be cleaned in place, got eligible=%v result=%+v", eligible, result)
	}
	if result.RemediationStatus != "cleaned" {
		t.Fatalf("plugin remediation status = %q, want cleaned", result.RemediationStatus)
	}
	after, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("plugin file must still exist after cleaning: %v", err)
	}
	if strings.Contains(string(after), "@include") {
		t.Fatalf("injection still present after clean:\n%s", after)
	}
	if !strings.Contains(string(after), "Plugin Name") {
		t.Fatalf("legitimate plugin content lost:\n%s", after)
	}
	entries, _ := os.ReadDir(qdir)
	for _, e := range entries {
		if !e.IsDir() && e.Name() != "pre_clean" {
			t.Fatalf("plugin file was moved into quarantine instead of cleaned: %s", e.Name())
		}
	}
}

// A WordPress file is never moved merely because surgical cleaning could not
// complete. Taking a plugin or core file out of the site is exactly the outage
// this branch is meant to avoid; a failed clean stays in place for review.
func TestQuarantineFindingFile_DoesNotMoveWordPressFileWhenCleaningFails(t *testing.T) {
	root, _ := redirectQuarantineForFullScan(t)
	pluginDir := filepath.Join(root, "public_html", "wp-content", "plugins", "example")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(pluginDir, "example.php")
	if err := os.WriteFile(src, []byte("<?php\n@include('/tmp/.x.php');\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	oldStore := storeQuarantineBackup
	storeQuarantineBackup = func(string, []byte, QuarantineMeta, os.FileMode) error { return os.ErrPermission }
	t.Cleanup(func() { storeQuarantineBackup = oldStore })

	result, eligible := QuarantineFindingFile(alert.Finding{
		Severity: alert.Critical,
		Check:    "obfuscated_php",
		FilePath: src,
	})
	if !eligible || result.Success || result.Error == "" {
		t.Fatalf("failed clean = eligible %v, result %+v; want an attempted but failed remediation", eligible, result)
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("WordPress file moved after cleaning failed: %v", err)
	}
}

// Full-scan findings are file findings. A FIFO, device, or socket must be
// rejected at the Lstat gate instead of reaching a path open that may block or
// act on a non-file object.
func TestQuarantineFindingFile_RefusesNonRegularObjects(t *testing.T) {
	root, _ := redirectQuarantineForFullScan(t)
	path := filepath.Join(root, "looks-like-php.php")
	if err := os.WriteFile(path, []byte("placeholder"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldOS := osFS
	osFS = fullScanLstatOS{OS: oldOS, info: fullScanFileInfo{mode: os.ModeNamedPipe | 0o600}}
	t.Cleanup(func() { osFS = oldOS })

	_, eligible := QuarantineFindingFile(alert.Finding{
		Severity: alert.Critical,
		Check:    "webshell",
		FilePath: path,
	})
	if eligible {
		t.Fatal("a non-regular filesystem object must be left for review")
	}
}
