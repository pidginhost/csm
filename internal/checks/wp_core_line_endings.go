package checks

import (
	"bytes"
	"crypto/md5" // #nosec G501 -- wordpress.org publishes MD5 digests for core files
	"encoding/hex"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pidginhost/csm/internal/wpcheck"
)

// An FTP client in ASCII mode rewrites every LF in an uploaded core file as
// CRLF. wp-cli then reports the file as modified although its code is the
// release's code. Only that one rewrite is undone before comparing; any other
// difference, or anything that cannot be checked, leaves the report standing.

// wpCoreLineEndingsMaxBytes bounds the read of a flagged file. Shipped core
// files are a few megabytes at most; a larger one is not shown to match.
const wpCoreLineEndingsMaxBytes = 8 << 20

// wpVersionFileMaxBytes bounds the read of version.php, which is about a
// kilobyte in every release.
const wpVersionFileMaxBytes = 64 << 10

var fetchWPCoreChecksums = wpcheck.FetchChecksums

// wpCoreReleaseChecksums holds the official checksums of each release for one
// run, so installs on the same release cost one request and a release that
// could not be fetched is not asked again for every file.
type wpCoreReleaseChecksums struct {
	mu       sync.Mutex
	releases map[string]*wpCoreRelease
}

type wpCoreRelease struct {
	once      sync.Once
	checksums map[string]string
	err       error
}

func (c *wpCoreReleaseChecksums) lookup(version, locale string) (map[string]string, error) {
	key := version + "/" + locale
	c.mu.Lock()
	if c.releases == nil {
		c.releases = make(map[string]*wpCoreRelease)
	}
	release := c.releases[key]
	if release == nil {
		release = &wpCoreRelease{}
		c.releases[key] = release
	}
	c.mu.Unlock()
	release.once.Do(func() { _, release.checksums, release.err = fetchWPCoreChecksums(version, locale) })
	return release.checksums, release.err
}

// lineEndingOnly returns the core files in a wp-cli report that differ from
// the install's release only in line endings, and whether nothing else was
// reported.
func (c *wpCoreReleaseChecksums) lineEndingOnly(wpPath string, out []byte) (files map[string]bool, only bool) {
	files = make(map[string]bool)
	only = true
	for _, line := range strings.Split(string(out), "\n") {
		if rel := wpChecksumModifiedCoreFile(line); rel != "" && c.differsOnlyInLineEndings(wpPath, rel) {
			files[rel] = true
		} else if trimmed := strings.TrimSpace(line); trimmed != "" && !strings.EqualFold(trimmed, wpChecksumFailureSummary) {
			only = false
		}
	}
	return files, only && len(files) > 0
}

func (c *wpCoreReleaseChecksums) differsOnlyInLineEndings(wpPath, rel string) bool {
	path := wpCoreFilePathWithin(wpPath, rel)
	if path == "" {
		return false
	}
	data, truncated, err := readRegularFileHead(path, wpCoreLineEndingsMaxBytes)
	if err != nil || truncated || !bytes.Contains(data, []byte("\r\n")) {
		return false
	}
	versionFile, truncated, err := readRegularFileHead(filepath.Join(wpPath, "wp-includes", "version.php"), wpVersionFileMaxBytes)
	if err != nil || truncated {
		return false
	}
	version, locale, err := wpcheck.ParseVersionContent(versionFile)
	if err != nil {
		return false
	}
	checksums, err := c.lookup(version, locale)
	want, listed := checksums[rel]
	if err != nil || !listed {
		return false
	}
	// #nosec G401 -- compared with the MD5 digests wordpress.org publishes
	sum := md5.Sum(bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n")))
	return hex.EncodeToString(sum[:]) == want
}
