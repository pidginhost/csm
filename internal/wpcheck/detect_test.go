package wpcheck

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectWPRoot(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{"wp-includes subdir", "/home/user/public_html/wp-includes/Text/Diff/Engine/shell.php", "/home/user/public_html"},
		{"wp-includes direct", "/home/user/public_html/wp-includes/version.php", "/home/user/public_html"},
		{"wp-admin subdir", "/home/user/public_html/wp-admin/includes/class-wp-upgrader.php", "/home/user/public_html"},
		{"wp-admin direct", "/home/user/public_html/wp-admin/index.php", "/home/user/public_html"},
		{"root-level wp-login", "/home/user/public_html/wp-login.php", "/home/user/public_html"},
		{"root-level wp-config-sample", "/home/user/public_html/wp-config-sample.php", "/home/user/public_html"},
		{"root-level xmlrpc", "/home/user/public_html/xmlrpc.php", "/home/user/public_html"},
		{"root-level wp-cron", "/home/user/public_html/wp-cron.php", "/home/user/public_html"},
		{"plugin file", "/home/user/public_html/wp-content/plugins/akismet/akismet.php", ""},
		{"theme file", "/home/user/public_html/wp-content/themes/flavor/style.css", ""},
		{"upload file", "/home/user/public_html/wp-content/uploads/2026/04/photo.jpg", ""},
		{"non-wp file", "/home/user/public_html/app/config.php", ""},
		{"tmp file", "/tmp/evil.php", ""},
		{"subdomain wp-includes", "/home/user/blog.example.com/wp-includes/class-wp.php", "/home/user/blog.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectWPRoot(tt.path)
			if got != tt.expected {
				t.Errorf("DetectWPRoot(%q) = %q, want %q", tt.path, got, tt.expected)
			}
		})
	}
}

func TestDetectWPRootIndexPHP(t *testing.T) {
	dir := t.TempDir()
	wpIncludes := filepath.Join(dir, "wp-includes")
	if err := os.MkdirAll(wpIncludes, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wpIncludes, "version.php"), []byte("<?php $wp_version = '6.9.4';"), 0644); err != nil {
		t.Fatal(err)
	}

	indexPath := filepath.Join(dir, "index.php")
	got := DetectWPRoot(indexPath)
	if got != dir {
		t.Errorf("DetectWPRoot(%q) = %q, want %q", indexPath, got, dir)
	}

	os.RemoveAll(wpIncludes)
	got = DetectWPRoot(indexPath)
	if got != "" {
		t.Errorf("DetectWPRoot(%q) without version.php = %q, want empty", indexPath, got)
	}
}

func TestParseVersionFile(t *testing.T) {
	tests := []struct {
		name            string
		content         string
		expectedVersion string
		expectedLocale  string
		expectErr       bool
	}{
		{"standard en_US", "<?php\n$wp_version = '6.9.4';\n", "6.9.4", "en_US", false},
		{"with locale", "<?php\n$wp_version = '6.9.4';\n$wp_local_package = 'de_DE';\n", "6.9.4", "de_DE", false},
		{"beta version", "<?php\n$wp_version = '6.9.4-beta1';\n", "6.9.4-beta1", "en_US", false},
		{"RC with locale", "<?php\n$wp_version = '6.9.4-RC2';\n$wp_local_package = 'fr_FR';\n", "6.9.4-RC2", "fr_FR", false},
		{"real format", "<?php\n/**\n * @global string $wp_version\n */\n$wp_version = '6.9.4';\n\n$wp_db_version = 58975;\n", "6.9.4", "en_US", false},
		{"missing version", "<?php\n// nothing here\n", "", "", true},
		{"empty content", "", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, locale, err := ParseVersionContent([]byte(tt.content))
			if tt.expectErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if version != tt.expectedVersion {
				t.Errorf("version = %q, want %q", version, tt.expectedVersion)
			}
			if locale != tt.expectedLocale {
				t.Errorf("locale = %q, want %q", locale, tt.expectedLocale)
			}
		})
	}
}
