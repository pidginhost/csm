package wpcheck

import (
	"crypto/md5" // #nosec G501 -- wordpress.org publishes MD5 digests for core files
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// PackageKind names the WordPress package family a path belongs to.
type PackageKind int

const (
	KindNone PackageKind = iota
	KindCore
	KindPlugin
	KindTheme
)

// Verdict is the outcome of locating a file inside a WordPress package and,
// when wordpress.org publishes checksums for that package version, comparing
// the file against them. The first four values describe the package; the
// last three are comparison results.
type Verdict int

const (
	// VerdictUnknown: the path is not inside a recognised package.
	VerdictUnknown Verdict = iota
	// VerdictNoVersion: the package is recognised but its version header is
	// not readable. During an unpack the header file may simply not exist
	// yet, so a caller should describe the path again later.
	VerdictNoVersion
	// VerdictPending: the checksums for this package version are being
	// fetched. A digest taken now can be verified once they arrive.
	VerdictPending
	// VerdictUnavailable: wordpress.org has no checksums for this package
	// version. Themes, premium plugins and private forks land here.
	VerdictUnavailable
	// VerdictReady: the checksums are cached and Verify can compare a digest.
	VerdictReady
	VerdictVerified
	// VerdictMismatch: the digest differs from the official file, or the
	// official package has no file at this relative path.
	VerdictMismatch
	// VerdictUnverifiable: checksums are cached but the file could not be
	// hashed (over the size cap, or not a regular file).
	VerdictUnverifiable
)

func (v Verdict) String() string {
	switch v {
	case VerdictUnknown:
		return "unknown"
	case VerdictNoVersion:
		return "no-version"
	case VerdictPending:
		return "pending"
	case VerdictUnavailable:
		return "unavailable"
	case VerdictReady:
		return "ready"
	case VerdictVerified:
		return "verified"
	case VerdictMismatch:
		return "mismatch"
	case VerdictUnverifiable:
		return "unverifiable"
	}
	return "verdict(" + strconv.Itoa(int(v)) + ")"
}

// Verification identifies one file inside a WordPress package. Root is the
// package root on disk, Rel the path below it as the checksum manifest keys
// it. Digest holds the hex digest of the file content in the algorithm
// wordpress.org publishes for the kind: SHA-256 for plugins, MD5 for core.
type Verification struct {
	Verdict Verdict
	Kind    PackageKind
	Root    string
	Slug    string
	Version string
	Locale  string
	Rel     string
	Digest  string
}

var reThemeVersionHeader = regexp.MustCompile(`(?im)^[ \t/*#@]*Version:[ \t]*([^\s]+)`)
var reThemeNameHeader = regexp.MustCompile(`(?im)^[ \t/*#@]*Theme Name:[ \t]*[^ \t\r\n]`)

// Describe locates path inside a WordPress core, plugin or theme tree and
// reports whether official checksums for that package version are cached,
// being fetched, or do not exist. It reads package headers only, never the
// file at path, and starts a background fetch on a cache miss.
func (c *Cache) Describe(path string) Verification {
	core := c.describeCore(path)
	if core.Verdict != VerdictUnknown && core.Verdict != VerdictNoVersion {
		return core
	}
	if plugin := c.describePlugin(path); plugin.Verdict != VerdictUnknown {
		return plugin
	}
	if theme := describeTheme(path); theme.Verdict != VerdictUnknown {
		return theme
	}
	return core
}

func (c *Cache) describeCore(path string) Verification {
	root := DetectWPRoot(path)
	if root == "" {
		return Verification{Verdict: VerdictUnknown}
	}
	rel := RelativePath(root, path)
	if rel == "" {
		return Verification{Verdict: VerdictUnknown}
	}
	v := Verification{Kind: KindCore, Root: root, Rel: rel}

	if rel == filepath.Join("wp-includes", "version.php") {
		c.invalidateRoot(root)
	}
	version, locale, ok := c.getRoot(root)
	if !ok {
		var err error
		version, locale, err = ReadVersionFile(root)
		if err != nil {
			v.Verdict = VerdictNoVersion
			return v
		}
		c.setRoot(root, version, locale)
	}
	v.Version, v.Locale = version, locale
	if c.hasChecksums(version, locale) {
		v.Verdict = VerdictReady
		return v
	}
	c.startBackgroundFetch(version, locale)
	v.Verdict = VerdictPending
	return v
}

func (c *Cache) describePlugin(path string) Verification {
	root, slug := DetectPluginRoot(path)
	// A core package unpacks into a directory named wordpress; it is never a
	// plugin, and describeCore has already classified it.
	if root == "" || slug == "wordpress" {
		return Verification{Verdict: VerdictUnknown}
	}
	rel := RelativePath(root, path)
	if rel == "" {
		return Verification{Verdict: VerdictUnknown}
	}
	v := Verification{Kind: KindPlugin, Root: root, Slug: slug, Rel: rel}

	version, err := ReadPluginVersion(root, slug)
	if err != nil || version == "" {
		// The same staged layout carries themes. A style.css with a theme
		// header settles the kind, and a theme has no checksum source.
		if theme := describeThemeRoot(root, slug, rel); theme.Verdict != VerdictUnknown {
			return theme
		}
		v.Verdict = VerdictNoVersion
		return v
	}
	v.Version = version
	switch {
	case c.hasPluginChecksums(slug, version):
		v.Verdict = VerdictReady
	case c.isPluginNotFound(slug, version):
		v.Verdict = VerdictUnavailable
	default:
		c.startBackgroundPluginFetch(slug, version)
		v.Verdict = VerdictPending
	}
	return v
}

// describeTheme handles the installed theme layout. Staged themes share the
// staged plugin layout and are recognised from describePlugin.
func describeTheme(path string) Verification {
	const themesSegment = "/wp-content/themes/"
	idx := strings.Index(path, themesSegment)
	if idx < 0 {
		return Verification{Verdict: VerdictUnknown}
	}
	slug, rel, ok := strings.Cut(path[idx+len(themesSegment):], "/")
	if !ok || rel == "" || !safePluginPathComponent(slug) {
		return Verification{Verdict: VerdictUnknown}
	}
	return describeThemeRoot(path[:idx+len(themesSegment)]+slug, slug, rel)
}

func describeThemeRoot(root, slug, rel string) Verification {
	// #nosec G304 -- root is derived from a scanner-received path under a
	// recognised theme or update-staging layout; the read is header-bounded.
	f, err := os.Open(filepath.Join(root, "style.css"))
	if err != nil {
		return Verification{Verdict: VerdictUnknown}
	}
	defer func() { _ = f.Close() }()
	buf, err := io.ReadAll(io.LimitReader(f, pluginHeaderReadLimit))
	if err != nil || !reThemeNameHeader.Match(buf) {
		return Verification{Verdict: VerdictUnknown}
	}
	v := Verification{Verdict: VerdictUnavailable, Kind: KindTheme, Root: root, Slug: slug, Rel: rel}
	if m := reThemeVersionHeader.FindSubmatch(buf); m != nil {
		v.Version = string(m[1])
	}
	return v
}

// Digest hashes the complete content behind fd with the algorithm
// wordpress.org publishes for kind. It returns "" when the file cannot be
// hashed whole, so a partial read can never verify as stock.
func (c *Cache) Digest(kind PackageKind, fd int) string {
	switch kind {
	case KindPlugin, KindCore:
	default:
		return ""
	}
	data := readCompleteFileForHash(fd)
	if data == nil {
		return ""
	}
	if kind == KindPlugin {
		sum := sha256.Sum256(data)
		return hex.EncodeToString(sum[:])
	}
	// #nosec G401 -- MD5 is required here: wordpress.org ships MD5 digests
	// as the canonical integrity reference for core files. We compare
	// against their published values, not derive authority from the hash.
	sum := md5.Sum(data)
	return hex.EncodeToString(sum[:])
}

// Verify compares v.Digest against the official checksum for v. A
// description taken while the fetch was still running resolves here once
// the checksums are cached, so callers can hash at event time and compare
// later without holding the file open.
func (c *Cache) Verify(v Verification) Verdict {
	switch v.Kind {
	case KindPlugin:
		return c.verifyPlugin(v)
	case KindCore:
		return c.verifyCore(v)
	}
	return v.Verdict
}

func (c *Cache) verifyPlugin(v Verification) Verdict {
	if v.Version == "" {
		return VerdictNoVersion
	}
	if !c.hasPluginChecksums(v.Slug, v.Version) {
		if c.isPluginNotFound(v.Slug, v.Version) {
			return VerdictUnavailable
		}
		c.startBackgroundPluginFetch(v.Slug, v.Version)
		return VerdictPending
	}
	if v.Digest == "" {
		return VerdictUnverifiable
	}
	expected, ok := c.lookupPluginChecksum(v.Slug, v.Version, v.Rel)
	if !ok {
		return VerdictMismatch
	}
	if hexDigestEqual(v.Digest, expected) {
		return VerdictVerified
	}
	return VerdictMismatch
}

func (c *Cache) verifyCore(v Verification) Verdict {
	if v.Version == "" {
		return VerdictNoVersion
	}
	if !c.hasChecksums(v.Version, v.Locale) {
		c.startBackgroundFetch(v.Version, v.Locale)
		return VerdictPending
	}
	if v.Digest == "" {
		return VerdictUnverifiable
	}
	if expected, ok := c.lookupChecksum(v.Version, v.Locale, v.Rel); ok && hexDigestEqual(v.Digest, expected) {
		return VerdictVerified
	}
	// A core update rewrites version.php part-way through. A file that fails
	// against the version cached for this root may be stock for the version
	// the root now declares.
	c.invalidateRoot(v.Root)
	version, locale, err := ReadVersionFile(v.Root)
	if err != nil || (version == v.Version && locale == v.Locale) {
		return VerdictMismatch
	}
	c.setRoot(v.Root, version, locale)
	if !c.hasChecksums(version, locale) {
		c.startBackgroundFetch(version, locale)
		return VerdictPending
	}
	if expected, ok := c.lookupChecksum(version, locale, v.Rel); ok && hexDigestEqual(v.Digest, expected) {
		return VerdictVerified
	}
	return VerdictMismatch
}

// VerifyFile describes path, hashes fd when the package kind has a checksum
// source, and resolves the comparison when the checksums are already cached.
func (c *Cache) VerifyFile(fd int, path string) Verification {
	v := c.Describe(path)
	switch v.Verdict {
	case VerdictNoVersion, VerdictPending, VerdictReady:
		v.Digest = c.Digest(v.Kind, fd)
	}
	if v.Verdict == VerdictReady {
		v.Verdict = c.Verify(v)
	}
	return v
}

func hexDigestEqual(digest, expected string) bool {
	raw, err := hex.DecodeString(digest)
	if err != nil {
		return false
	}
	return constantTimeHexDigestEqual(raw, expected)
}

// resolve hashes fd when the checksums for v are cached and returns the
// comparison, or v's own verdict when there is nothing to compare against.
func (c *Cache) resolve(fd int, v Verification) Verdict {
	if v.Verdict != VerdictReady {
		return v.Verdict
	}
	v.Digest = c.Digest(v.Kind, fd)
	return c.Verify(v)
}

// IsVerifiedCoreFile reports whether path is an unmodified file of the
// WordPress core version its install declares.
func (c *Cache) IsVerifiedCoreFile(fd int, path string) bool {
	return c.resolve(fd, c.describeCore(path)) == VerdictVerified
}

// IsVerifiedPluginFile reports whether path is an unmodified file of the
// wordpress.org release its plugin header declares, installed or staged.
func (c *Cache) IsVerifiedPluginFile(fd int, path string) bool {
	v := c.describePlugin(path)
	return v.Kind == KindPlugin && c.resolve(fd, v) == VerdictVerified
}
