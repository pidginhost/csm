package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// The scheduled .htaccess scan stopped five levels below the document root.
// Uploads directories nest deeper than that (wp-content/uploads/2026/09/x is
// already five), which is exactly where droppers plant a handler-enabling
// .htaccess. The scan now walks as deep as the rolling content scan does.
func TestScanHtaccessReachesUploadNestedFiles(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "wp-content", "uploads", "2026", "09", "cache", "x")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, ".htaccess"), []byte("AddHandler application/x-httpd-php .jpg\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanHtaccess(context.Background(), root, htaccessScanMaxDepth, []string{"addhandler"}, nil, &config.Config{}, &findings)
	for _, f := range findings {
		if f.FilePath == filepath.Join(deep, ".htaccess") {
			return
		}
	}
	t.Fatalf("handler-enabling .htaccess six levels down was not scanned; findings=%+v", findings)
}
