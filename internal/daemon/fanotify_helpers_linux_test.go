//go:build linux

package daemon

import (
	"os"
	"testing"
)

// These tests only compile on Linux where fanotify.go is active.

func TestIsPHPExtension(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"evil.php", true},
		{"trick.phtml", true},
		{"hack.pht", true},
		{"old.php5", true},
		{"safe.html", false},
		{"readme.txt", false},
		{"image.jpg", false},
	}
	for _, tt := range tests {
		if got := isPHPExtension(tt.name); got != tt.want {
			t.Errorf("isPHPExtension(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestIsCGIExtension(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"script.pl", true},
		{"handler.cgi", true},
		{"app.py", true},
		{"run.sh", true},
		{"gem.rb", true},
		{"safe.php", false},
	}
	for _, tt := range tests {
		if got := isCGIExtension(tt.name); got != tt.want {
			t.Errorf("isCGIExtension(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestMatchSuppression(t *testing.T) {
	tests := []struct {
		pattern, path string
		want          bool
	}{
		{"*.log", "/home/alice/error.log", true},
		{"*.php", "/home/alice/evil.php", true},
		{"/home/alice/*", "/home/alice/test.php", true},
		{"*/cache/*", "/home/alice/wp-content/cache/file.php", true},
		{"*.txt", "/home/alice/evil.php", false},
	}
	for _, tt := range tests {
		if got := matchSuppression(tt.pattern, tt.path); got != tt.want {
			t.Errorf("matchSuppression(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
		}
	}
}

func TestReadHead(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.txt"
	_ = os.WriteFile(path, []byte("hello world this is a long string"), 0644)

	got := readHead(path, 5)
	if string(got) != "hello" {
		t.Errorf("got %q, want hello", got)
	}
}

func TestReadHeadMissing(t *testing.T) {
	got := readHead("/nonexistent", 100)
	if got != nil {
		t.Errorf("missing file should return nil, got %v", got)
	}
}

func TestContainsFunc(t *testing.T) {
	if !containsFunc("echo base64_decode('x');", "base64_decode(") {
		t.Error("standalone call should match")
	}
	if containsFunc("my_base64_decode('x')", "base64_decode(") {
		t.Error("embedded call should not match")
	}
	if containsFunc("no such function", "base64_decode(") {
		t.Error("missing should not match")
	}
}

func TestLooksLikePluginUpdate(t *testing.T) {
	// Without actual filesystem, should return false
	if looksLikePluginUpdate("/home/alice/wp-content/uploads/evil.php") {
		t.Error("file without subdir should not be plugin update")
	}
}
