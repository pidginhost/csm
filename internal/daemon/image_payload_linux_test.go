//go:build linux

package daemon

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// A PNG carrying a PHP payload was written into a plugin asset directory and
// realtime never looked at it: the fast path admitted PHP, HTML, ZIP and CGI
// names only, so every image write was closed before analysis.
func TestIsInterestingAdmitsImagesUnderAccountRoots(t *testing.T) {
	fm := &FileMonitor{
		accountRootPatterns: []string{"/home/*"},
		docRootPatterns:     []string{"/home/*/public_html"},
	}
	for _, path := range []string{
		"/home/victim/public_html/wp-content/plugins/demo/assets/lib/images/light_square/btn.png",
		"/home/victim/public_html/wp-content/uploads/2026/09/photo.JPEG",
		"/home/victim/public_html/favicon.ico",
		"/home/victim/public_html/assets/logo.webp",
	} {
		if !fm.isInteresting(path) {
			t.Errorf("image under an account root is not interesting: %s", path)
		}
	}
	for _, path := range []string{
		"/usr/share/icons/hicolor/48x48/apps/app.png",
		"/var/lib/cpanel/themes/logo.png",
	} {
		if fm.isInteresting(path) {
			t.Errorf("image outside hosted trees is interesting: %s", path)
		}
	}
}

func runImagePayloadCheck(t *testing.T, name string, body []byte) (alert.Finding, bool) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "public_html", "wp-content", "plugins", "demo", "assets", name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)
	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkImagePayload(fd, path, "pi")
	select {
	case got := <-ch:
		return got, true
	case <-time.After(200 * time.Millisecond):
		return alert.Finding{}, false
	}
}

func TestCheckImagePayloadFlagsPHPAppendedToAValidPNG(t *testing.T) {
	got, fired := runImagePayloadCheck(t, "light_square.png", append(testPNG(t), []byte(remoteFetchPayload)...))
	if !fired {
		t.Fatal("PHP appended to a valid PNG produced no finding")
	}
	if got.Check != "php_in_image_realtime" || got.Severity != alert.Critical {
		t.Errorf("got check=%q sev=%v, want Critical php_in_image_realtime", got.Check, got.Severity)
	}
	if got.FilePath == "" || !strings.Contains(got.Details, "PNG") {
		t.Errorf("finding does not carry the payload path and container: path=%q details=%q", got.FilePath, got.Details)
	}
}

// Attackers pad the payload past any bounded head read. The tail window has
// to be examined too, and the container verdict still comes from the head.
func TestCheckImagePayloadFlagsPayloadPastTheHeadWindow(t *testing.T) {
	padded := append(testPNG(t), bytes.Repeat([]byte("A"), imagePayloadHeadBytes+4096)...)
	got, fired := runImagePayloadCheck(t, "spacer.png", append(padded, []byte(remoteFetchPayload)...))
	if !fired {
		t.Fatal("PHP appended past the head window produced no finding")
	}
	if got.Check != "php_in_image_realtime" {
		t.Errorf("got check=%q, want php_in_image_realtime", got.Check)
	}
}

// A webshell wearing an image name has no container at all. It is still PHP
// under a served tree and must not be waved through because the magic test
// failed.
func TestCheckImagePayloadFlagsPHPWearingAnImageName(t *testing.T) {
	got, fired := runImagePayloadCheck(t, "thumb.png", []byte("<?php system($_GET['cmd']); ?>"))
	if !fired {
		t.Fatal("PHP source under an image name produced no finding")
	}
	if got.Severity != alert.Critical {
		t.Errorf("got sev=%v, want Critical", got.Severity)
	}
}

func TestCheckImagePayloadStaysQuietOnOrdinaryImages(t *testing.T) {
	for name, body := range map[string][]byte{
		"clean.png":  testPNG(t),
		"clean.jpg":  testJPEG(t),
		"clean.gif":  testGIF(t),
		"screen.png": append(testPNG(t), []byte("tEXtDescription\x00Add <?php the_widget('demo'); ?> to your theme.")...),
	} {
		t.Run(name, func(t *testing.T) {
			if got, fired := runImagePayloadCheck(t, name, body); fired {
				t.Errorf("clean image produced %s: %s", got.Check, got.Details)
			}
		})
	}
}
