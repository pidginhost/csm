package checks

import (
	"archive/zip"
	"path"
	"strings"
)

// archiveEntryScanLimit bounds how many entries are read from a candidate
// archive. A site backup announces itself in the first handful of entries, so
// a cap keeps a hostile or pathological archive from stalling the scan.
const archiveEntryScanLimit = 4096

// siteConfigBasenames are CMS configuration files that only ever appear inside
// a copy of a live site, never inside a plugin, theme, or ordinary download.
var siteConfigBasenames = map[string]bool{
	"wp-config.php":       true,
	"configuration.php":   true, // Joomla
	"settings.php":        true, // Drupal
	"config/database.php": true,
}

// docrootDirNames are hosting conventions for the web root. An archive whose
// entries sit under one is a copy of a served directory tree.
var docrootDirNames = map[string]bool{
	"wwwroot":     true,
	"public_html": true,
	"htdocs":      true,
	"httpdocs":    true,
}

// archiveHoldsSiteBackup reports whether a web-reachable archive contains a
// copy of a site, judged by its entry list rather than its file name.
//
// The name-based classifier requires a backup token, so an archive named after
// the domain it holds is classified as nothing and never virtual-patched --
// which is how a 64MB archive containing wwwroot/wp-config.php stayed publicly
// downloadable. Only zip is inspected: its central directory is cheap to read,
// while a tar.gz would have to be decompressed to enumerate.
func archiveHoldsSiteBackup(p string) bool {
	if !strings.HasSuffix(strings.ToLower(p), ".zip") {
		return false
	}
	zr, err := zip.OpenReader(p)
	if err != nil {
		return false
	}
	defer func() { _ = zr.Close() }()

	for i, f := range zr.File {
		if i >= archiveEntryScanLimit {
			break
		}
		name := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(f.Name)), "./")
		if name == "" {
			continue
		}
		if siteConfigBasenames[path.Base(name)] {
			return true
		}
		// A dump sitting at the archive root is the archive's payload. The same
		// file nested under a plugin directory is that plugin's schema, so
		// depth is what separates a backup from an installer.
		if !strings.Contains(strings.Trim(name, "/"), "/") && hasDBDumpSuffix(name) {
			return true
		}
		if head, _, ok := strings.Cut(name, "/"); ok && docrootDirNames[head] {
			return true
		}
	}
	return false
}
