package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"golang.org/x/sys/unix"
)

func TestScanGroupWritablePHPDoesNotUseSymlinkPermissions(t *testing.T) {
	for _, name := range []string{"cache", "node_modules", "vendor"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, name)
			if err := os.Mkdir(dir, 0755); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(dir, "source.php")
			if err := os.WriteFile(target, []byte("<?php echo 1;"), 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(dir, "linked.php")); err != nil {
				t.Fatal(err)
			}
			var findings []alert.Finding
			scanGroupWritablePHP(root, 4, map[uint32]bool{fileGID(t, target): true}, &findings)
			if len(findings) != 0 {
				t.Fatalf("read-only PHP target must not inherit symlink write bits: %+v", findings)
			}
		})
	}
}

func TestScanForPhishingDoesNotFollowFileSymlinks(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "vendor", "SecureDocShare")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	for name, content := range map[string]string{
		"verify.html": officePhishHTML + strings.Repeat(" ", 3500),
		"go.php":      `<?php header("Location: " . $_GET['url']); ?>`,
	} {
		target := filepath.Join(outside, name)
		if err := os.WriteFile(target, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	ctx, collector := withIncompleteCheckCollector(context.Background())
	var findings []alert.Finding
	scanForPhishing(ctx, root, phishingScanMaxDepth, "alice", &config.Config{}, &findings)
	if len(findings) != 0 {
		t.Fatalf("file symlinks must not supply phishing evidence from outside the tree: %+v", findings)
	}
	if collector.contains("phishing") {
		t.Fatal("declining non-regular files must not block retiring stale findings")
	}
}

func TestScanForPhishingDoesNotBlockOnDependencyFIFO(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "node_modules", "form-example")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "login.html")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, collector := withIncompleteCheckCollector(context.Background())
	done := make(chan []alert.Finding, 1)
	go func() {
		var findings []alert.Finding
		scanForPhishing(ctx, root, phishingScanMaxDepth, "alice", &config.Config{}, &findings)
		done <- findings
	}()
	select {
	case findings := <-done:
		if len(findings) != 0 {
			t.Fatalf("a FIFO is not a phishing page: %+v", findings)
		}
		if collector.contains("phishing") {
			t.Fatal("declining a FIFO must not block retiring stale findings")
		}
	case <-time.After(time.Second):
		// Release a blocked reader before returning, so it cannot outlive the
		// fixture or race the next test's filesystem provider.
		fd, err := unix.Open(fifo, unix.O_WRONLY|unix.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := unix.Close(fd); err != nil {
			t.Fatal(err)
		}
		<-done
		t.Fatal("phishing scan blocked opening a dependency FIFO")
	}
}

func TestPhishingReadersDoNotBlockOnFIFO(t *testing.T) {
	readers := map[string]func(context.Context, string) bool{
		"html":        func(ctx context.Context, path string) bool { return analyzeHTMLForPhishing(ctx, path) != nil },
		"php":         func(ctx context.Context, path string) bool { return analyzePHPForPhishing(ctx, path) != nil },
		"quick":       quickPhishingCheck,
		"redirector":  func(ctx context.Context, path string) bool { return checkPHPRedirector(ctx, path) != "" },
		"iframe":      func(ctx context.Context, path string) bool { return checkIframePhishing(ctx, path) != "" },
		"credentials": func(ctx context.Context, path string) bool { return checkCredentialLog(ctx, path) != "" },
		"zip":         zipLooksLikeKit,
	}
	for name, read := range readers {
		t.Run(name, func(t *testing.T) {
			fifo := filepath.Join(t.TempDir(), "candidate")
			if err := unix.Mkfifo(fifo, 0600); err != nil {
				t.Fatal(err)
			}
			done := make(chan bool, 1)
			go func() { done <- read(context.Background(), fifo) }()
			select {
			case finding := <-done:
				if finding {
					t.Fatal("a FIFO is not phishing content")
				}
			case <-time.After(time.Second):
				fd, err := unix.Open(fifo, unix.O_WRONLY|unix.O_NONBLOCK, 0)
				if err != nil {
					t.Fatal(err)
				}
				if err := unix.Close(fd); err != nil {
					t.Fatal(err)
				}
				<-done
				t.Fatal("phishing reader blocked on a FIFO")
			}
		})
	}
}

func TestScanForPhishingDirectoryRespectsIgnoredHTML(t *testing.T) {
	for _, name := range []string{"vendor", "node_modules", ".git"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, name, "SecureDocShare")
			if err := os.MkdirAll(dir, 0755); err != nil {
				t.Fatal(err)
			}
			page := filepath.Join(dir, "verify.html")
			if err := os.WriteFile(page, []byte(officePhishHTML+strings.Repeat(" ", 3500)), 0600); err != nil {
				t.Fatal(err)
			}
			cfg := &config.Config{}
			cfg.Suppressions.IgnorePaths = []string{page}
			var findings []alert.Finding
			scanForPhishing(context.Background(), root, phishingScanMaxDepth, "alice", cfg, &findings)
			if len(findings) != 0 {
				t.Fatalf("ignored page must not supply directory evidence: %+v", findings)
			}
			auditCtx := ContextWithScanOptions(context.Background(), AccountScanOptions{RespectIgnores: false})
			scanForPhishing(auditCtx, root, phishingScanMaxDepth, "alice", cfg, &findings)
			if len(findings) != 2 {
				t.Fatalf("audit must report the ignored kit directory and page: %+v", findings)
			}
			if findings[0].Check != "phishing_directory" || findings[0].FilePath != dir ||
				findings[1].Check != "phishing_page" || findings[1].FilePath != page {
				t.Fatalf("audit findings must identify the kit directory and page: %+v", findings)
			}
		})
	}
}

func TestDependencyScansDoNotFollowDirectorySymlinks(t *testing.T) {
	for _, name := range []string{"vendor", "node_modules", ".git"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, name)
			if err := os.Mkdir(dir, 0755); err != nil {
				t.Fatal(err)
			}
			outside := t.TempDir()
			for _, base := range []string{dir, outside} {
				if err := os.WriteFile(filepath.Join(base, "verify.html"), []byte(officePhishHTML+strings.Repeat(" ", 3500)), 0600); err != nil {
					t.Fatal(err)
				}
				php := filepath.Join(base, "writable.php")
				if err := os.WriteFile(php, []byte("<?php echo 1;"), 0664); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(php, 0664); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(root, filepath.Join(dir, "cycle")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(dir, "outside")); err != nil {
				t.Fatal(err)
			}
			var findings []alert.Finding
			scanForPhishing(context.Background(), root, phishingScanMaxDepth, "alice", &config.Config{}, &findings)
			if len(findings) != 1 || findings[0].Check != "phishing_page" || findings[0].FilePath != filepath.Join(dir, "verify.html") {
				t.Fatalf("phishing scan must report only the in-tree page: %+v", findings)
			}
			findings = nil
			php := filepath.Join(dir, "writable.php")
			scanGroupWritablePHP(root, 4, map[uint32]bool{fileGID(t, php): true}, &findings)
			if len(findings) != 1 || findings[0].Check != "group_writable_php" || !strings.HasSuffix(findings[0].Message, ": "+php) {
				t.Fatalf("permissions scan must report only the in-tree file: %+v", findings)
			}
		})
	}
}

func TestDependencyScansRespectDepthBudget(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "node_modules", "one", "two")
	outside := filepath.Join(inside, "three")
	if err := os.MkdirAll(outside, 0755); err != nil {
		t.Fatal(err)
	}
	for _, base := range []string{inside, outside} {
		if err := os.WriteFile(filepath.Join(base, "verify.html"), []byte(officePhishHTML+strings.Repeat(" ", 3500)), 0600); err != nil {
			t.Fatal(err)
		}
		php := filepath.Join(base, "writable.php")
		if err := os.WriteFile(php, []byte("<?php echo 1;"), 0664); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(php, 0664); err != nil {
			t.Fatal(err)
		}
	}
	var findings []alert.Finding
	scanForPhishing(context.Background(), root, 4, "alice", &config.Config{}, &findings)
	if len(findings) != 1 || findings[0].Check != "phishing_page" || findings[0].FilePath != filepath.Join(inside, "verify.html") {
		t.Fatalf("phishing scan crossed its depth budget: %+v", findings)
	}
	findings = nil
	php := filepath.Join(inside, "writable.php")
	scanGroupWritablePHP(root, 4, map[uint32]bool{fileGID(t, php): true}, &findings)
	if len(findings) != 1 || findings[0].Check != "group_writable_php" || !strings.HasSuffix(findings[0].Message, ": "+php) {
		t.Fatalf("permissions scan crossed its depth budget: %+v", findings)
	}
}

func TestScanForPhishingDirectoryRejectsEmailTitleBrand(t *testing.T) {
	for _, name := range []string{"vendor", "node_modules", ".git"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, name, "login-example")
			if err := os.MkdirAll(dir, 0755); err != nil {
				t.Fatal(err)
			}
			for _, address := range []string{"jane.doe@gmail.com", "jane@dropbox.example"} {
				body := `<html><head><title>Sign In - ` + address + `</title></head><body>
<form action="/session"><input type="email"><input type="password"></form></body></html>`
				page := filepath.Join(dir, "login.html")
				if err := os.WriteFile(page, []byte(body+strings.Repeat(" ", 3500)), 0600); err != nil {
					t.Fatal(err)
				}
				var findings []alert.Finding
				scanForPhishing(context.Background(), root, phishingScanMaxDepth, "alice", &config.Config{}, &findings)
				if len(findings) != 0 {
					t.Errorf("brand inside %q is not impersonation: %+v", address, findings)
				}
			}
		})
	}
}
