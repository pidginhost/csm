//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// The previous checkPHPContent code suppressed webshell_content_realtime
// whenever the literal string "wp_filesystem" appeared anywhere in the file.
// That exclusion was forgeable: an attacker could paste the token into any
// webshell to silence the alert. These tests lock in two invariants:
//
//   1. The shell-func-plus-request-input-on-same-line signal fires regardless
//      of unrelated content elsewhere in the file. The token cannot buy
//      suppression.
//   2. Legitimate WP_Filesystem code does not call the platform shell funcs
//      we scan for (system/exec/shell_exec/passthru/popen). Its absence of
//      a same-line hit is what keeps it quiet, not a content-based allowlist.

func TestCheckPHPContent_WebshellWithWPFilesystemCommentStillFires(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shell.php")
	// The bypass token sits inline as a comment. A real webshell can do this
	// trivially; the rule must not treat the token as a trust signal.
	body := []byte(`<?php system($_POST['c']); /* wp_filesystem */ ?>`)
	if err := os.WriteFile(path, body, 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkPHPContent(int(f.Fd()), path, "pi")

	select {
	case a := <-ch:
		if a.Check != "webshell_content_realtime" || a.Severity != alert.Critical {
			t.Errorf("got %+v, want Critical webshell_content_realtime", a)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected webshell_content_realtime despite wp_filesystem token")
	}
}

func TestCheckPHPContent_LegitimateWPFilesystemPutContentsStaysQuiet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legit.php")
	// Real WP_Filesystem usage: writes content via put_contents, takes a
	// path from $_POST on the same line. Does NOT invoke any of the shell
	// funcs the rule watches, so the same-line narrowing stays silent.
	body := []byte(`<?php
global $wp_filesystem;
if ( empty( $wp_filesystem ) ) {
	WP_Filesystem();
}
$wp_filesystem->put_contents( $_POST['target'], $_POST['body'], FS_CHMOD_FILE );
?>`)
	if err := os.WriteFile(path, body, 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkPHPContent(int(f.Fd()), path, "pi")

	select {
	case a := <-ch:
		if a.Check == "webshell_content_realtime" {
			t.Errorf("legitimate WP_Filesystem put_contents should not fire webshell alert: %+v", a)
		}
	case <-time.After(150 * time.Millisecond):
		// No alert - correct behaviour.
	}
}
