//go:build linux

package daemon

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/yara"
	"golang.org/x/sys/unix"
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
	padded := append(testPNG(t), bytes.Repeat([]byte("A"), imagePayloadHeadBytes+imagePayloadTailBytes+4096)...)
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

func TestCheckImagePayloadAcrossReadBoundary(t *testing.T) {
	for _, size := range []int{imagePayloadHeadBytes + imagePayloadTailBytes - 8, imagePayloadHeadBytes + imagePayloadTailBytes} {
		body := bytes.Repeat([]byte("A"), size)
		copy(body, testPNG(t))
		copy(body[imagePayloadHeadBytes-12:], "<?php /* padding */ system('id'); ?>")
		if _, fired := runImagePayloadCheck(t, "boundary.png", body); !fired {
			t.Errorf("payload spanning read boundary in %d-byte image was missed", size)
		}
	}
}

func TestAnalyzeImagePayloadInConfiguredRoots(t *testing.T) {
	for _, name := range []string{"logo.webp", ".config/logo.png", "temporary-root/logo.png"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, name)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append(testPNG(t), []byte(remoteFetchPayload)...), 0o644); err != nil {
				t.Fatal(err)
			}
			alerts := make(chan alert.Finding, 4)
			fd := openRawFd(t, path)
			if strings.HasPrefix(name, "temporary-root/") {
				// Keep the fixture in t.TempDir while exercising a root whose
				// event path encounters the generic temporary-file branch.
				root = "/var/tmp/image-site"
				path = filepath.Join(root, name)
			}
			fm := &FileMonitor{cfg: &config.Config{}, alertCh: alerts, docRootPatterns: []string{root}}
			if !fm.isInteresting(path) {
				t.Fatal("image in configured root was not admitted")
			}
			fm.analyzeFile(fileEvent{path: path, fd: fd})
			select {
			case got := <-alerts:
				if got.Check != "php_in_image_realtime" || got.FilePath != path {
					t.Fatalf("unexpected finding: %+v", got)
				}
			default:
				t.Fatal("admitted image did not reach content detection")
			}
		})
	}
}

func TestImageBurstUsesBoundedNotificationQueueAndRecoversDrops(t *testing.T) {
	root := t.TempDir()
	alerts := make(chan alert.Finding, 4)
	fm := &FileMonitor{
		cfg: &config.Config{}, alertCh: alerts,
		docRootPatterns: []string{root}, analyzerCh: make(chan fileEvent, 4),
		reconcileSig: make(chan struct{}, 1),
	}
	const writes = 32
	var payloadPath string
	for i := 0; i < writes; i++ {
		path := filepath.Join(root, strconv.Itoa(i)+".webp")
		body := []byte("RIFF\x18\x00\x00\x00WEBPVP8 ")
		if i == writes-1 {
			payloadPath = path
			body = append(body, []byte(remoteFetchPayload)...)
		}
		if err := os.WriteFile(path, body, 0o644); err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		fm.handleEvent(fd, 0, FAN_CLOSE_WRITE)
		if i >= cap(fm.analyzerCh) {
			if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != unix.EBADF {
				t.Fatalf("dropped image descriptor remains open: %v", err)
			}
		}
	}
	if len(fm.analyzerCh) != cap(fm.analyzerCh) || fm.droppedEvents != writes-int64(cap(fm.analyzerCh)) {
		t.Fatalf("burst escaped admission bounds: queued=%d dropped=%d", len(fm.analyzerCh), fm.droppedEvents)
	}
	if len(fm.reconcileDirs) != 1 || len(alerts) != 0 {
		t.Fatalf("admission scanned inline or failed to track recovery: dirs=%d alerts=%d", len(fm.reconcileDirs), len(alerts))
	}
	close(fm.analyzerCh)
	fm.wg.Add(1)
	fm.analyzerWorker()
	fm.reconcileDrops()
	select {
	case got := <-alerts:
		if got.Check != "php_in_image_realtime" || got.FilePath != payloadPath {
			t.Fatalf("wrong recovered finding: %+v", got)
		}
	default:
		t.Fatal("payload dropped during thumbnail burst was not recovered")
	}
	if len(alerts) != 0 || len(fm.reconcileDirs) != 0 {
		t.Fatal("recovery left duplicate findings or pending directories")
	}
}

func TestHandlerMappedImageRetainsPHPContentScan(t *testing.T) {
	previous := yara.Active()
	yara.SetActive(matchingFanotifyYARABackend{})
	t.Cleanup(func() { yara.SetActive(previous) })
	root := t.TempDir()
	path := filepath.Join(root, "handler.png")
	if err := os.WriteFile(path, []byte("<?php echo 'mapped PHP';"), 0o644); err != nil {
		t.Fatal(err)
	}
	alerts := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: alerts, docRootPatterns: []string{root}}
	fm.analyzeFile(fileEvent{path: path, fd: openRawFd(t, path), phpExecutable: true})
	select {
	case finding := <-alerts:
		if finding.Check != "yara_match_realtime" {
			t.Fatalf("unexpected finding: %+v", finding)
		}
	default:
		t.Fatal("handler-mapped image lost its existing PHP scan")
	}
}
