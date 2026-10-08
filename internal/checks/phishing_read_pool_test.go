package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePhishingSample(t testing.TB, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Every candidate page used to get a fresh, zeroed read window of
// phishingReadSize bytes, even when the file was a few KB long.
func TestPhishingReadsReuseTheirWindow(t *testing.T) {
	for name, tc := range map[string]struct {
		file    string
		body    string
		analyze func(context.Context, string) *phishingResult
	}{
		"php":  {"lib.php", phpLibraryBody("Returns null when missing.", 2_000), analyzePHPForPhishing},
		"html": {"page.html", "<html><body><p>" + strings.Repeat("Opening hours and directions. ", 60) + "</p></body></html>", analyzeHTMLForPhishing},
	} {
		t.Run(name, func(t *testing.T) {
			path := writePhishingSample(t, tc.file, tc.body)
			res := testing.Benchmark(func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					tc.analyze(context.Background(), path)
				}
			})
			if got := res.AllocedBytesPerOp(); got >= phishingReadSize/2 {
				t.Fatalf("%d bytes allocated per file; the read window is not reused", got)
			}
		})
	}
}

// A reused window still holds the previous file's bytes past the new read.
// Only the bytes just read may be analysed.
func TestPhishingReadWindowDoesNotLeakPreviousFile(t *testing.T) {
	kitPad := strings.Repeat("\n<!-- padding -->", 500)
	for name, tc := range map[string]struct {
		kit, clean string
		analyze    func(context.Context, string) *phishingResult
	}{
		"php":  {dropboxPhishPHP + kitPad, "<?php\n", analyzePHPForPhishing},
		"html": {officePhishHTML + kitPad, "<html>\n", analyzeHTMLForPhishing},
	} {
		t.Run(name, func(t *testing.T) {
			kit := writePhishingSample(t, "kit-"+name, tc.kit)
			clean := writePhishingSample(t, "clean-"+name, tc.clean)
			// The race detector drops some pooled buffers; repeat so reuse
			// is all but certain.
			for i := 0; i < 8; i++ {
				if tc.analyze(context.Background(), kit) == nil {
					t.Fatal("kit fixture no longer detected")
				}
				if got := tc.analyze(context.Background(), clean); got != nil {
					t.Fatalf("clean file judged from the previous file's bytes: %+v", got)
				}
			}
		})
	}
}
