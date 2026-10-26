package checks

import (
	"bytes"
	"crypto/md5" // #nosec G501 -- wordpress.org publishes MD5 digests for core files
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/safepath"
	"github.com/pidginhost/csm/internal/wpcheck"
)

// An FTP client in ASCII mode rewrites the line endings of an uploaded core
// file: LF becomes CRLF, or the reverse on the way back. wp-cli then reports
// the file as modified although its code is the release's code. Only that one
// rewrite is undone before comparing; any other difference, or anything that
// cannot be checked, leaves the report standing.

// wpCoreLineEndingsMaxBytes bounds the read of a flagged file. Shipped core
// files are a few megabytes at most; a larger one is not shown to match.
const wpCoreLineEndingsMaxBytes = 8 << 20

// wpVersionFileMaxBytes bounds the read of version.php, which is about a
// kilobyte in every release.
const wpVersionFileMaxBytes = 64 << 10

var fetchWPCoreChecksums = wpcheck.FetchChecksums

// logWPCoreLineEndings names why a flagged file stays reported; the finding
// alone cannot say whether the file differs or the check could not run.
// The text logger does not escape fields, so paths and errors must be quoted.
var logWPCoreLineEndings = csmlog.Info

var (
	errWPCoreBeyondLineEndings = errors.New("differs beyond line endings")
	errWPCoreFileTooLarge      = errors.New("larger than the read limit")
	errWPCoreNotInRelease      = errors.New("not in the release checksums")
)

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
	type modifiedFile struct {
		rel  string
		line int
	}
	var modified []modifiedFile
	for i, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.EqualFold(trimmed, wpChecksumFailureSummary) {
			continue
		}
		if rel := wpChecksumModifiedFilePath(line); rel != "" {
			if coreRel := wpChecksumModifiedCoreFile(line); coreRel != "" {
				modified = append(modified, modifiedFile{rel: coreRel, line: i + 1})
			} else {
				only = false
			}
			continue
		}
		// Extra and missing core files are known differences the scan reports
		// or tolerates elsewhere; they only keep the install from verifying.
		if strings.Contains(line, "should not exist") || strings.Contains(line, "should exist") || strings.Contains(line, "File doesn't exist: ") {
			only = false
			continue
		}
		// Only the line number: PHP output can carry secrets.
		logWPCoreLineEndings("WordPress core line-ending check stopped at unrecognized wp-cli output", "path", strconv.QuoteToASCII(wpPath), "line", i+1)
		return files, false
	}
	if len(modified) == 0 {
		return files, false
	}

	release, checksums, err := c.installChecksums(wpPath)
	if err != nil {
		logWPCoreLineEndings("WordPress core line-ending check has no release checksums", "path", strconv.QuoteToASCII(wpPath), "release", release, "err", strconv.QuoteToASCII(err.Error()))
		return files, false
	}
	for _, file := range modified {
		rel := file.rel
		want, listed := checksums[rel]
		if !listed {
			// The parser also accepts mismatch text embedded in PHP output.
			// Only release-listed names are safe to copy into the log.
			logWPCoreLineEndings("WordPress core line-ending check cannot identify reported file", "path", strconv.QuoteToASCII(wpPath), "line", file.line, "release", release, "err", errWPCoreNotInRelease)
			only = false
			continue
		}
		if err := wpCoreFileDiffersOnlyInLineEndings(wpPath, rel, want); err != nil {
			logWPCoreLineEndings("WordPress core file not proven to differ only in line endings", "path", strconv.QuoteToASCII(wpPath), "file", strconv.QuoteToASCII(rel), "release", release, "err", strconv.QuoteToASCII(err.Error()))
			only = false
			continue
		}
		files[rel] = true
	}
	return files, only && len(files) > 0
}

// installChecksums returns the official checksums of the release the install
// names in version.php, and that release as version/locale.
func (c *wpCoreReleaseChecksums) installChecksums(wpPath string) (release string, checksums map[string]string, err error) {
	versionFile, err := readWPCoreFile(wpPath, filepath.Join("wp-includes", "version.php"), wpVersionFileMaxBytes)
	if err != nil {
		return "", nil, fmt.Errorf("reading version.php: %w", err)
	}
	version, locale, err := wpcheck.ParseVersionContent(versionFile)
	if err != nil {
		// Parse errors can quote tenant-controlled file contents.
		return "", nil, errors.New("invalid release metadata in version.php")
	}
	checksums, err = c.lookup(version, locale)
	return version + "/" + locale, checksums, err
}

// wpCoreFileDiffersOnlyInLineEndings returns nil when one whole-file line
// ending conversion turns the file into the release's file.
func wpCoreFileDiffersOnlyInLineEndings(wpPath, rel, want string) error {
	data, err := readWPCoreFile(wpPath, rel, wpCoreLineEndingsMaxBytes)
	if err != nil {
		return err
	}
	// Either direction of one whole-file conversion: CRLF copies of an LF
	// release, and LF copies of a release that ships CRLF. A file that still
	// holds a stray CR is not a clean LF conversion.
	var normalized []byte
	switch {
	case bytes.Contains(data, []byte("\r\n")):
		normalized = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	case bytes.Contains(data, []byte("\n")) && !bytes.Contains(data, []byte("\r")):
		normalized = bytes.ReplaceAll(data, []byte("\n"), []byte("\r\n"))
	default:
		return errWPCoreBeyondLineEndings
	}
	// #nosec G401 -- compared with the MD5 digests wordpress.org publishes
	sum := md5.Sum(normalized)
	if got := hex.EncodeToString(sum[:]); got != want {
		return fmt.Errorf("%w: converted md5 %s, release md5 %s", errWPCoreBeyondLineEndings, got, want)
	}
	return nil
}

// readWPCoreFile reads a whole core file; one past the limit is an error.
func readWPCoreFile(wpPath, rel string, limit int64) ([]byte, error) {
	data, truncated, err := readWPCoreFileHead(wpPath, rel, limit)
	if err == nil && truncated {
		err = errWPCoreFileTooLarge
	}
	return data, err
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
