package wpcheck

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// wpRootLevelFiles are filenames that only exist at the WP installation root.
// index.php is excluded - it requires a secondary check (version.php must exist).
var wpRootLevelFiles = map[string]bool{
	"wp-activate.php":      true,
	"wp-blog-header.php":   true,
	"wp-comments-post.php": true,
	"wp-config-sample.php": true,
	"wp-cron.php":          true,
	"wp-links-opml.php":    true,
	"wp-load.php":          true,
	"wp-login.php":         true,
	"wp-mail.php":          true,
	"wp-settings.php":      true,
	"wp-signup.php":        true,
	"wp-trackback.php":     true,
	"xmlrpc.php":           true,
}

// DetectWPRoot returns the WordPress installation root directory for a file path,
// or empty string if the path is not inside a WP core location.
//
// Detection methods:
//   - Path contains /wp-includes/ or /wp-admin/ → root is everything before that segment
//   - Filename is a known root-level WP file → root is the parent directory
//   - Filename is index.php and version.php exists in wp-includes/ → root is the parent directory
func DetectWPRoot(path string) string {
	// Check for /wp-includes/ or /wp-admin/ in path
	for _, marker := range []string{"/wp-includes/", "/wp-admin/"} {
		if idx := strings.Index(path, marker); idx >= 0 {
			return path[:idx]
		}
	}

	// Check for direct wp-includes or wp-admin (file directly inside)
	dir := filepath.Dir(path)
	base := filepath.Base(dir)
	if base == "wp-includes" || base == "wp-admin" {
		return filepath.Dir(dir)
	}

	// Check for known root-level WP files
	name := filepath.Base(path)
	if wpRootLevelFiles[name] {
		return dir
	}

	// Special case: index.php requires version.php to confirm WP root
	if name == "index.php" {
		versionPath := filepath.Join(dir, "wp-includes", "version.php")
		if _, err := os.Stat(versionPath); err == nil {
			return dir
		}
	}

	return ""
}

// RelativePath computes the path of a file relative to the WP root.
// Returns empty string if the file is not under root.
func RelativePath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return ""
	}
	return rel
}

var (
	reVersion = regexp.MustCompile(`\$wp_version\s*=\s*'([^']+)'`)
	reLocale  = regexp.MustCompile(`\$wp_local_package\s*=\s*'([^']+)'`)

	// version.php is tenant-writable and its strings name a root-written
	// cache file and a query string, so both are held to the shapes
	// WordPress actually ships: "6.5", "6.5.2", "6.7-RC1", "6.8-alpha-59245"
	// and locales such as "en_US", "de_DE_formal", "ary".
	reValidVersion = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,3}(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?$`)
	reValidLocale  = regexp.MustCompile(`^[a-z]{2,3}(?:_[A-Za-z0-9]{2,10}){0,2}$`)
)

// ParseVersionContent extracts the WP version and locale from version.php content.
// Locale defaults to "en_US" if $wp_local_package is not present. A version or
// locale outside the shapes WordPress ships is an error: the install is then
// treated as unverifiable rather than letting tenant-chosen text reach the
// checksum cache path or the API query.
func ParseVersionContent(data []byte) (version, locale string, err error) {
	m := reVersion.FindSubmatch(data)
	if m == nil {
		return "", "", errors.New("wp_version not found in version.php")
	}
	version = string(m[1])
	if !reValidVersion.MatchString(version) {
		return "", "", fmt.Errorf("wp_version %q in version.php is not a WordPress version string", version)
	}

	locale = "en_US"
	if lm := reLocale.FindSubmatch(data); lm != nil {
		locale = string(lm[1])
	}
	if !reValidLocale.MatchString(locale) {
		return "", "", fmt.Errorf("wp_local_package %q in version.php is not a WordPress locale", locale)
	}
	return version, locale, nil
}

// ReadVersionFile reads and parses {root}/wp-includes/version.php.
func ReadVersionFile(root string) (version, locale string, err error) {
	// #nosec G304 -- path derived from a WordPress install root discovered
	// by the scanner under configured /home/*/public_html paths.
	data, err := os.ReadFile(filepath.Join(root, "wp-includes", "version.php"))
	if err != nil {
		return "", "", err
	}
	return ParseVersionContent(data)
}
