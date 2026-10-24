package checks

import (
	"bytes"
	"crypto/md5" // #nosec G501 -- wordpress.org publishes MD5 digests for core files
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pidginhost/csm/internal/safepath"
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

// lineEndingOnly returns the core files in a wp-cli report that differ from the
// install's release only in line endings, and whether nothing else was
// reported. Unrecognized output proves neither claim. A caller may resolve or
// suppress findings only after wpCoreVerificationCompleted accepts the report.
func (c *wpCoreReleaseChecksums) lineEndingOnly(wpPath string, out []byte) (files map[string]bool, only bool) {
	files = make(map[string]bool)
	only = true
	var modified []string
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.EqualFold(trimmed, wpChecksumFailureSummary) {
			continue
		}
		if rel := wpChecksumModifiedFilePath(line); rel != "" {
			if coreRel := wpChecksumModifiedCoreFile(line); coreRel != "" {
				modified = append(modified, coreRel)
			} else {
				only = false
			}
			continue
		}
		if strings.Contains(line, "should not exist") || strings.Contains(line, "should exist") {
			only = false
			continue
		}
		return files, false
	}
	if len(modified) == 0 {
		return files, false
	}

	versionFile, truncated, err := readWPCoreFileHead(wpPath, filepath.Join("wp-includes", "version.php"), wpVersionFileMaxBytes)
	if err != nil || truncated {
		return files, false
	}
	version, locale, err := wpcheck.ParseVersionContent(versionFile)
	if err != nil {
		return files, false
	}
	checksums, err := c.lookup(version, locale)
	if err != nil {
		return files, false
	}
	for _, rel := range modified {
		want, listed := checksums[rel]
		if !listed || !wpCoreFileDiffersOnlyInLineEndings(wpPath, rel, want) {
			only = false
			continue
		}
		files[rel] = true
	}
	return files, only && len(files) > 0
}

func wpCoreFileDiffersOnlyInLineEndings(wpPath, rel, want string) bool {
	data, truncated, err := readWPCoreFileHead(wpPath, rel, wpCoreLineEndingsMaxBytes)
	if err != nil || truncated || !bytes.Contains(data, []byte("\r\n")) {
		return false
	}
	// #nosec G401 -- compared with the MD5 digests wordpress.org publishes
	sum := md5.Sum(bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n")))
	return hex.EncodeToString(sum[:]) == want
}

// readWPCoreFileHead keeps every account-controlled component beneath the
// opened install. Production walks by directory descriptor and refuses links;
// injected test filesystems retain the package's bounded-reader behavior.
func readWPCoreFileHead(wpPath, rel string, limit int64) (data []byte, truncated bool, err error) {
	path := wpCoreFilePathWithin(wpPath, rel)
	if path == "" {
		return nil, false, os.ErrPermission
	}
	if _, production := osFS.(realOS); !production {
		return readRegularFileHead(path, limit)
	}

	target, err := safepath.OpenTarget(wpPath, filepath.Clean(rel), false)
	if err != nil {
		return nil, false, err
	}
	defer target.Close()
	file, err := target.Parent.OpenFile(target.Name, os.O_RDONLY, 0)
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return nil, false, err
	}
	if !before.Mode().IsRegular() {
		return nil, false, errNonRegularFile
	}
	data, err = io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, false, err
	}
	after, err := file.Stat()
	if err != nil || !sameFileSnapshot(before, after) {
		return nil, false, errFileChanged
	}
	current, err := target.Parent.Stat(target.Name)
	if err != nil || !sameFileSnapshot(after, current) {
		return nil, false, errFileChanged
	}
	if err := target.Check(); err != nil {
		return nil, false, errFileChanged
	}
	if int64(len(data)) > limit {
		return data[:limit], true, nil
	}
	return data, false, nil
}
