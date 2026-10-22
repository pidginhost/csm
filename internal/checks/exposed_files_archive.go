package checks

import (
	"archive/zip"
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"syscall"

	"github.com/pidginhost/csm/internal/zipdir"
)

const (
	// The central directory is the only part of a zip this check reads. A byte
	// bound covers entry count, names, comments, and extra fields together while
	// allowing substantially more than the old 4096-entry cutoff.
	archiveDirectoryScanByteLimit = 16 << 20

	zipDirectoryHeaderLen = zipdir.HeaderLen
	zipDirectoryEndLen    = zipdir.EndLen
	zipDirectory64EndLen  = zipdir.End64Len
	zipDirectory64LocLen  = zipdir.End64LocatorLen

	// A site backup names its document root at or just below the archive
	// root. Past that a configuration file needs corroboration.
	shallowSiteConfigDepth = 2

	zipDirectoryHeaderSignature = zipdir.HeaderSignature
	zipDirectoryEndSignature    = zipdir.EndSignature
	zipDirectory64EndSignature  = zipdir.End64Signature
	zipDirectory64LocSignature  = zipdir.End64LocatorSign
)

var errArchiveFormat = zipdir.ErrFormat

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
func archiveHoldsSiteBackup(p string) bool {
	holds, _ := archiveSiteBackupStatus(context.Background(), p)
	return holds
}

// archiveSiteBackupStatus also reports whether the result is complete. A
// resource-limited or interrupted inspection must retain an earlier finding.
// Malformed zip data is a complete negative result: a file merely ending in
// .zip must not hold the whole exposed-files check incomplete forever.
func archiveSiteBackupStatus(ctx context.Context, p string) (holds, complete bool) {
	if !strings.HasSuffix(strings.ToLower(p), ".zip") {
		return false, true
	}

	info, err := osFS.Lstat(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, true
		}
		return false, false
	}
	if !info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
		return false, true
	}

	var f *os.File
	if _, productionFS := osFS.(realOS); productionFS {
		// The account controls this path. A nonblocking open plus the descriptor
		// type check allows web-served regular symlinks without letting a FIFO
		// swapped in after the directory walk strand the scan.
		// #nosec G304 -- read-only document-root candidate; flags reject unsafe types.
		f, err = os.OpenFile(p, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	} else {
		f, err = osFS.Open(p)
	}
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ELOOP) {
			return false, true
		}
		return false, false
	}
	defer func() { _ = f.Close() }()

	openedInfo, err := f.Stat()
	if err != nil {
		return false, false
	}
	if !openedInfo.Mode().IsRegular() {
		return false, true
	}

	dir, err := zipdir.Read(f, openedInfo.Size(), archiveDirectoryScanByteLimit)
	if err != nil {
		if errors.Is(err, errArchiveFormat) {
			return false, true
		}
		return false, false
	}
	holds, err = scanZipDirectory(ctx, f, dir)
	if err != nil {
		if errors.Is(err, errArchiveFormat) {
			return false, true
		}
		return holds, false
	}
	return holds, true
}

func scanZipDirectory(ctx context.Context, f *os.File, dir zipdir.Directory) (bool, error) {
	reader := bufio.NewReader(io.NewSectionReader(f, dir.Offset, dir.Size))
	var header [zipDirectoryHeaderLen]byte
	var records uint64
	holdsSite := false
	// A wp-config.php nested past the shallow bound only counts alongside a
	// WordPress runtime file, so both are accumulated across the whole
	// directory rather than decided per entry.
	deepConfig := false
	wpRuntime := false
	// A nested Joomla configuration.php counts only when its own directory
	// also holds a Joomla entry point, so both are keyed by directory.
	joomlaConfigDirs := map[string]bool{}
	joomlaRuntimeDirs := map[string]bool{}
	for {
		if records%256 == 0 {
			if err := ctx.Err(); err != nil {
				return holdsSite, err
			}
		}
		signature, err := reader.Peek(4)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return holdsSite, err
		}
		if binary.LittleEndian.Uint32(signature) != zipDirectoryHeaderSignature {
			break
		}
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			return holdsSite, archiveDirectoryReadError(err)
		}
		nameLen := int(binary.LittleEndian.Uint16(header[28:30]))
		extraLen := int64(binary.LittleEndian.Uint16(header[30:32]))
		commentLen := int64(binary.LittleEndian.Uint16(header[32:34]))
		name := make([]byte, nameLen)
		if _, err := io.ReadFull(reader, name); err != nil {
			return holdsSite, archiveDirectoryReadError(err)
		}
		if _, err := io.CopyN(io.Discard, reader, extraLen+commentLen); err != nil {
			return holdsSite, archiveDirectoryReadError(err)
		}
		if entry := string(name); archiveEntrySignalsSiteBackup(entry) {
			holdsSite = true
		} else {
			if archiveEntryIsDeepWPConfig(entry) {
				deepConfig = true
			}
			if archiveEntryIsWPRuntime(entry) {
				wpRuntime = true
			}
			// Names alone cannot distinguish PHP files from directories or
			// symlinks. Interpret central-directory attributes without opening
			// or decompressing any entry payload.
			entryHeader := zip.FileHeader{
				Name:           strings.ReplaceAll(entry, `\`, "/"),
				CreatorVersion: binary.LittleEndian.Uint16(header[4:6]),
				ExternalAttrs:  binary.LittleEndian.Uint32(header[38:42]),
			}
			if entryHeader.Mode().IsRegular() {
				if d, ok := archiveNestedJoomlaConfigDir(entry); ok {
					joomlaConfigDirs[d] = true
					holdsSite = holdsSite || joomlaRuntimeDirs[d]
				}
				if d, ok := archiveJoomlaRuntimeDir(entry); ok {
					joomlaRuntimeDirs[d] = true
					holdsSite = holdsSite || joomlaConfigDirs[d]
				}
			}
		}
		records++
	}
	if records != dir.Records {
		return false, errArchiveFormat
	}
	return holdsSite || (deepConfig && wpRuntime), nil
}

func archiveDirectoryReadError(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return errArchiveFormat
	}
	return err
}

// archiveEntryPath normalises a raw zip entry name and rejects the shapes that
// must never be read as a marker: absolute, drive-qualified, and traversal
// names. It returns nil for anything unusable.
func archiveEntryPath(rawName string) []string {
	return archiveEntryPathPreservingCase(strings.ToLower(strings.TrimSpace(rawName)))
}

// Directory identity must retain case and whitespace when pairing entries:
// archives from Linux can contain distinct directories differing only by either.
func archiveEntryPathPreservingCase(rawName string) []string {
	name := strings.ReplaceAll(rawName, `\`, "/")
	if name == "" || strings.HasPrefix(name, "/") ||
		(len(name) >= 3 && ((name[0] >= 'a' && name[0] <= 'z') || (name[0] >= 'A' && name[0] <= 'Z')) && name[1] == ':' && name[2] == '/') {
		return nil
	}
	name = path.Clean(name)
	if name == "." || name == ".." || strings.HasPrefix(name, "../") {
		return nil
	}
	parts := strings.Split(strings.Trim(name, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		return nil
	}
	return parts
}

func archiveEntrySignalsSiteBackup(rawName string) bool {
	parts := archiveEntryPath(rawName)
	if len(parts) == 0 {
		return false
	}

	for _, part := range parts[:len(parts)-1] {
		if docrootDirNames[part] {
			return true
		}
	}
	if len(parts) == 1 && hasDBDumpSuffix(parts[0]) {
		return true
	}

	switch parts[len(parts)-1] {
	case "wp-config.php":
		// A configuration file this close to the archive root is the archive's
		// own subject. Deeper ones are ambiguous -- plugins ship fixtures at
		// arbitrary depth -- so those are paired with a runtime marker instead,
		// via archiveEntryIsDeepWPConfig.
		return len(parts) <= shallowSiteConfigDepth
	case "configuration.php":
		return len(parts) == 1
	case "settings.php":
		return hasArchivePathSuffix(parts, "sites", "default", "settings.php")
	default:
		return false
	}
}

// archiveEntryIsDeepWPConfig reports a wp-config.php nested past the depth the
// shallow rule accepts on its own.
func archiveEntryIsDeepWPConfig(rawName string) bool {
	parts := archiveEntryPath(rawName)
	return len(parts) > shallowSiteConfigDepth && parts[len(parts)-1] == "wp-config.php"
}

// archiveEntryIsWPRuntime reports a file only a WordPress installation carries.
// A plugin or theme bundle shipping a configuration fixture has none of these,
// which is what separates a nested backup from a nested fixture.
func archiveEntryIsWPRuntime(rawName string) bool {
	parts := archiveEntryPath(rawName)
	if len(parts) == 0 {
		return false
	}
	switch parts[len(parts)-1] {
	case "wp-load.php", "wp-settings.php", "wp-blog-header.php":
		return true
	}
	for _, part := range parts[:len(parts)-1] {
		if part == "wp-includes" {
			return true
		}
	}
	return false
}

// archiveNestedJoomlaConfigDir returns the directory of a configuration.php
// below the archive root. A root-level one already counts on its own.
func archiveNestedJoomlaConfigDir(rawName string) (string, bool) {
	parts := archiveEntryPathPreservingCase(rawName)
	if len(parts) < 2 || !strings.EqualFold(parts[len(parts)-1], "configuration.php") {
		return "", false
	}
	return strings.Join(parts[:len(parts)-1], "/"), true
}

// archiveJoomlaRuntimeDir returns the site directory of a Joomla core entry
// point. Every Joomla release carries these and no extension package does.
func archiveJoomlaRuntimeDir(rawName string) (string, bool) {
	parts := archiveEntryPathPreservingCase(rawName)
	if len(parts) < 2 {
		return "", false
	}
	parent, file := strings.ToLower(parts[len(parts)-2]), strings.ToLower(parts[len(parts)-1])
	if (parent == "includes" && file == "defines.php") ||
		(parent == "administrator" && file == "index.php") {
		return strings.Join(parts[:len(parts)-2], "/"), true
	}
	return "", false
}

func hasArchivePathSuffix(parts []string, suffix ...string) bool {
	if len(parts) < len(suffix) {
		return false
	}
	start := len(parts) - len(suffix)
	for i := range suffix {
		if parts[start+i] != suffix[i] {
			return false
		}
	}
	return true
}
