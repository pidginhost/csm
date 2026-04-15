package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// --- hexVal ------------------------------------------------------------

func TestHexValAllBranches(t *testing.T) {
	cases := []struct {
		in   byte
		want int
	}{
		{'0', 0}, {'5', 5}, {'9', 9},
		{'a', 10}, {'c', 12}, {'f', 15},
		{'A', 10}, {'F', 15},
		// Out-of-range bytes return 0 (default branch).
		{'g', 0}, {'!', 0}, {' ', 0},
	}
	for _, c := range cases {
		if got := hexVal(c.in); got != c.want {
			t.Errorf("hexVal(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// --- hexToByte ---------------------------------------------------------

func TestHexToByteValidPair(t *testing.T) {
	if got := hexToByte("ff"); got != 0xff {
		t.Errorf("hexToByte(\"ff\") = %#x, want 0xff", got)
	}
	if got := hexToByte("0a"); got != 0x0a {
		t.Errorf("hexToByte(\"0a\") = %#x, want 0x0a", got)
	}
}

func TestHexToByteWrongLengthReturnsZero(t *testing.T) {
	if got := hexToByte("a"); got != 0 {
		t.Errorf("hexToByte(\"a\") = %#x, want 0", got)
	}
	if got := hexToByte("abc"); got != 0 {
		t.Errorf("hexToByte(\"abc\") = %#x, want 0", got)
	}
}

// --- scanHtaccess ------------------------------------------------------

func TestScanHtaccessRespectsContextCancel(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, ".htaccess"), []byte("foo"), 0644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var findings []alert.Finding
	scanHtaccess(ctx, tmp, 4, []string{"foo"}, nil, &config.Config{}, &findings)
	if len(findings) != 0 {
		t.Errorf("cancelled context should yield no findings, got %d", len(findings))
	}
}

func TestScanHtaccessRespectsMaxDepthZero(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, ".htaccess"), []byte("auto_prepend_file"), 0644); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanHtaccess(context.Background(), tmp, 0,
		[]string{"auto_prepend_file"}, nil, &config.Config{}, &findings)
	if len(findings) != 0 {
		t.Errorf("maxDepth=0 should yield no findings, got %d", len(findings))
	}
}

func TestScanHtaccessMissingDirIsSilent(t *testing.T) {
	var findings []alert.Finding
	scanHtaccess(context.Background(), "/no-such-dir-xyz", 4,
		[]string{"foo"}, nil, &config.Config{}, &findings)
	if len(findings) != 0 {
		t.Errorf("missing dir should yield no findings, got %d", len(findings))
	}
}

func TestScanHtaccessFlagsSuspiciousPattern(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, ".htaccess"),
		[]byte("php_value auto_prepend_file /tmp/x.php\n"), 0644); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanHtaccess(context.Background(), tmp, 4,
		[]string{"auto_prepend_file"}, nil, &config.Config{}, &findings)
	if len(findings) == 0 {
		t.Errorf("expected suspicious finding for auto_prepend_file directive")
	}
}

func TestScanHtaccessIgnoresCommentedSuspicious(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, ".htaccess"),
		[]byte("# auto_prepend_file is dangerous, not enabled here\n"), 0644); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanHtaccess(context.Background(), tmp, 4,
		[]string{"auto_prepend_file"}, nil, &config.Config{}, &findings)
	if len(findings) != 0 {
		t.Errorf("commented directive should NOT trigger finding, got %d", len(findings))
	}
}

func TestScanHtaccessSuppressedPathSkipped(t *testing.T) {
	tmp := t.TempDir()
	hta := filepath.Join(tmp, ".htaccess")
	if err := os.WriteFile(hta, []byte("auto_prepend_file /tmp/x.php\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Suppressions.IgnorePaths = []string{filepath.Join(tmp, "*")}

	var findings []alert.Finding
	scanHtaccess(context.Background(), tmp, 4,
		[]string{"auto_prepend_file"}, nil, cfg, &findings)
	if len(findings) != 0 {
		t.Errorf("suppressed path should yield no findings, got %d", len(findings))
	}
}

func TestScanHtaccessNonHtaccessFileIgnored(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "config.conf"),
		[]byte("auto_prepend_file /tmp/x.php\n"), 0644); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanHtaccess(context.Background(), tmp, 4,
		[]string{"auto_prepend_file"}, nil, &config.Config{}, &findings)
	if len(findings) != 0 {
		t.Errorf("non-.htaccess file should be ignored, got %d", len(findings))
	}
}
