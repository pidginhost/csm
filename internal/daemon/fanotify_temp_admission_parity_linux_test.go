//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"golang.org/x/sys/unix"
)

// Compare findings through the reader and overflow recovery with direct
// analysis, so admission cannot silently bypass an earlier detector branch.
func TestTempRootAdmissionPreservesAnalyzerFindings(t *testing.T) {
	useRealtimeRules(t, realtimeHighRule)
	for _, root := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		t.Run(root, func(t *testing.T) {
			t.Setenv("TMPDIR", root)
			for _, tc := range []struct {
				name, body, check string
				mode              os.FileMode
				severity          alert.Severity
				cron, fifo, image bool
			}{
				{name: "cron/alice", body: "0 * * * * /tmp/x defunct-kernel\n", check: "suspicious_crontab", cron: true},
				{name: "worker", mode: 0o755, check: "executable_in_tmp_realtime"},
				{name: "pipe", mode: 0o755, check: "executable_in_tmp_realtime", fifo: true},
				{name: "payload.php", body: "<?php echo 'EVIL_MARKER_A'; ?>", check: "signature_match_realtime", severity: alert.High},
				{name: "payload.phps", body: "<?php echo 'EVIL_MARKER_A'; ?>", check: "signature_match_realtime", severity: alert.High},
				{name: ".ssh/payload.phtml", check: "php_in_sensitive_dir_realtime"},
				{name: ".cpanel/payload.php", check: "php_in_sensitive_dir_realtime"},
				{name: "mail/payload.php", check: "php_in_sensitive_dir_realtime"},
				{name: ".gnupg/payload.php", check: "php_in_sensitive_dir_realtime"},
				{name: ".cagefs/payload.php", check: "php_in_sensitive_dir_realtime"},
				{name: "wso.php", body: "<?php system($_GET['x']);", check: "webshell_realtime"},
				{name: "payload.HAXOR", check: "webshell_realtime"},
				{name: "payload.CGIX", check: "webshell_realtime"},
				{name: ".htaccess", body: "php_value auto_prepend_file /tmp/fixture.php\n", check: "htaccess_injection_realtime", severity: alert.High},
				{name: ".user.ini", body: "disable_functions = \n", check: "php_config_realtime"},
				{name: "php.ini", body: "disable_functions = \n", check: "php_config_realtime"},
				{name: ".config/worker", mode: 0o755, check: "executable_in_config_realtime"},
				{name: "picture.PNG", body: string(testPNG(t)) + remoteFetchPayload, check: "php_in_image_realtime", image: true},
				{name: ".config/picture.PNG", body: string(testPNG(t)) + remoteFetchPayload, check: "php_in_image_realtime", image: true},
			} {
				for _, staged := range []bool{false, true} {
					name := tc.name
					if staged {
						name = filepath.Join(filepath.Dir(name), ".temp.123."+filepath.Base(name))
					}
					t.Run(name, func(t *testing.T) {
						dir := t.TempDir()
						path := filepath.Join(dir, name)
						if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
							t.Fatal(err)
						}
						if tc.cron {
							withCronSpoolDir(t, filepath.Join(dir, "cron"))
						}
						mode := tc.mode
						if mode == 0 {
							mode = 0o600
						}
						if tc.fifo {
							if err := unix.Mkfifo(path, uint32(mode)); err != nil {
								t.Fatal(err)
							}
						} else if err := os.WriteFile(path, []byte(tc.body), mode); err != nil {
							t.Fatal(err)
						}
						if err := os.Chmod(path, mode); err != nil {
							t.Fatal(err)
						}
						// Holding both ends keeps the FIFO recovery open nonblocking;
						// its finding uses metadata and never reads the stream.
						fd, err := unix.Open(path, unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { _ = unix.Close(fd) })
						type findingKey struct {
							check    string
							severity alert.Severity
							path     string
						}
						var direct []findingKey
						for _, route := range []string{"direct", "reader", "reconcile"} {
							t.Run(route, func(t *testing.T) {
								findings := make(chan alert.Finding, 8)
								fm := &FileMonitor{cfg: &config.Config{}, alertCh: findings, analyzerCh: make(chan fileEvent, 1)}
								if tc.image {
									fm.docRootPatterns = []string{dir}
								}
								switch route {
								case "direct":
									fm.analyzeFile(fileEvent{path: path, fd: fd})
								case "reader":
									dup, err := unix.Dup(fd)
									if err != nil {
										t.Fatal(err)
									}
									fm.handleEvent(dup, 0, FAN_CLOSE_WRITE)
									select {
									case event := <-fm.analyzerCh:
										defer func() { _ = unix.Close(event.fd) }()
										if event.dropperOnly {
											t.Fatal("finding-producing event lost content analysis")
										}
										fm.analyzeFile(event)
									default:
										assertFDClosed(t, dup, "rejected temp event")
										t.Fatal("finding-producing event rejected before analysis")
									}
								case "reconcile":
									fm.recordDroppedDir(path)
									fm.reconcileDrops()
									if len(fm.reconcileDirs) != 0 || len(fm.analyzerCh) != 0 {
										t.Fatal("recovery left pending work")
									}
								}
								severity := tc.severity
								if severity == 0 {
									severity = alert.Critical
								}
								var got []findingKey
								matched := 0
								for len(findings) > 0 {
									f := <-findings
									key := findingKey{f.Check, f.Severity, f.FilePath}
									got = append(got, key)
									if key == (findingKey{tc.check, severity, path}) {
										matched++
									}
								}
								if matched != 1 {
									t.Fatalf("findings = %+v, want exactly one %s %s at %s", got, severity, tc.check, path)
								}
								if route == "direct" {
									direct = got
								} else if !reflect.DeepEqual(got, direct) {
									t.Fatalf("findings = %+v, direct analysis = %+v", got, direct)
								}
							})
						}
					})
				}
			}
		})
	}
}

func TestTempRootAdmissionPreservesDropperTracking(t *testing.T) {
	t.Setenv("TMPDIR", "/tmp")
	for _, tc := range []struct {
		name       string
		mode       os.FileMode
		handlerPHP bool
		suppressed bool
	}{
		{name: "worker", mode: 0o755},
		{name: "payload.dat", mode: 0o600, handlerPHP: true},
		{name: "suppressed.dat", mode: 0o600, handlerPHP: true, suppressed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, tc.name)
			if tc.handlerPHP {
				if err := os.WriteFile(filepath.Join(dir, ".htaccess"), []byte("AddHandler application/x-httpd-php .dat\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(path, []byte("<?php system($_GET['x']);"), tc.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			}
			fm := newDropperWiringTestMonitor(dir, time.Minute)
			fm.analyzerCh = make(chan fileEvent, 1)
			if tc.suppressed {
				fm.cfg.Suppressions.IgnorePaths = []string{path}
			}
			fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			fm.handleEvent(fd, 4242, FAN_CREATE|FAN_CLOSE_WRITE)
			select {
			case event := <-fm.analyzerCh:
				defer func() { _ = unix.Close(event.fd) }()
				if event.dropperOnly || event.phpExecutable != tc.handlerPHP {
					t.Errorf("event flags: dropperOnly=%v phpExecutable=%v, want content analysis and phpExecutable=%v", event.dropperOnly, event.phpExecutable, tc.handlerPHP)
				}
				fm.analyzeFile(event)
			default:
				assertFDClosed(t, fd, "rejected dropper event")
				t.Fatal("dropper candidate rejected before analysis")
			}
			if tc.handlerPHP && len(fm.alertCh) != 0 {
				t.Fatal("dropper-only routing introduced a content finding for a temp file")
			}
			candidates := fm.dropper.tr.Due(time.Now().Add(2 * time.Minute))
			if len(candidates) != 1 || candidates[0].Path != path || !candidates[0].Created ||
				candidates[0].PHPExecutable != tc.handlerPHP || candidates[0].ContentSuspicious {
				t.Fatalf("tracked candidates = %+v, want the admitted dropper with its content verdict", candidates)
			}
		})
	}
}
