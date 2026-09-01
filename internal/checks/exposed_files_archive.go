package checks

import (
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
)

const (
	// The central directory is the only part of a zip this check reads. A byte
	// bound covers entry count, names, comments, and extra fields together while
	// allowing substantially more than the old 4096-entry cutoff.
	archiveDirectoryScanByteLimit = 16 << 20

	zipDirectoryHeaderLen = 46
	zipDirectoryEndLen    = 22
	zipDirectory64EndLen  = 56
	zipDirectory64LocLen  = 20
	zipMaxCommentLen      = 1<<16 - 1

	// A site backup names its document root at or just below the archive
	// root. Past that a configuration file needs corroboration.
	shallowSiteConfigDepth = 2

	zipDirectoryHeaderSignature = 0x02014b50
	zipDirectoryEndSignature    = 0x06054b50
	zipDirectory64EndSignature  = 0x06064b50
	zipDirectory64LocSignature  = 0x07064b50
)

var (
	errArchiveFormat    = errors.New("invalid zip central directory")
	errArchiveScanLimit = errors.New("zip central directory exceeds scan limit")
)

// docrootDirNames are hosting conventions for the web root. An archive whose
// entries sit under one is a copy of a served directory tree.
var docrootDirNames = map[string]bool{
	"wwwroot":     true,
	"public_html": true,
	"htdocs":      true,
	"httpdocs":    true,
}

type zipDirectory struct {
	offset  int64
	size    int64
	records uint64
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

	dir, err := readZipDirectory(f, openedInfo.Size())
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

func readZipDirectory(f *os.File, size int64) (zipDirectory, error) {
	if size < zipDirectoryEndLen {
		return zipDirectory{}, errArchiveFormat
	}
	tailLen := int64(zipDirectoryEndLen + zipMaxCommentLen)
	if tailLen > size {
		tailLen = size
	}
	tail := make([]byte, int(tailLen))
	if err := readAtFull(f, tail, size-tailLen); err != nil {
		return zipDirectory{}, err
	}

	endIndex := findZipDirectoryEnd(tail)
	if endIndex < 0 {
		return zipDirectory{}, errArchiveFormat
	}
	endOffset := size - tailLen + int64(endIndex)
	end := tail[endIndex : endIndex+zipDirectoryEndLen]
	if binary.LittleEndian.Uint16(end[4:6]) != 0 ||
		binary.LittleEndian.Uint16(end[6:8]) != 0 {
		return zipDirectory{}, errArchiveFormat
	}
	recordsThisDisk := uint64(binary.LittleEndian.Uint16(end[8:10]))
	records := uint64(binary.LittleEndian.Uint16(end[10:12]))
	directorySize := uint64(binary.LittleEndian.Uint32(end[12:16]))
	directoryOffset := uint64(binary.LittleEndian.Uint32(end[16:20]))
	if recordsThisDisk != records {
		return zipDirectory{}, errArchiveFormat
	}

	directoryEndOffset := endOffset
	if records == 0xffff || directorySize == 0xffffffff || directoryOffset == 0xffffffff {
		var err error
		directoryEndOffset, records, directorySize, directoryOffset, err = readZip64Directory(f, endOffset)
		if err != nil {
			return zipDirectory{}, err
		}
	}
	if directorySize > archiveDirectoryScanByteLimit {
		return zipDirectory{}, errArchiveScanLimit
	}
	directorySize64, sizeOK := archiveOffset(directorySize)
	directoryOffset64, offsetOK := archiveOffset(directoryOffset)
	if !sizeOK || !offsetOK || directoryEndOffset < 0 ||
		directorySize64 > directoryEndOffset || directoryOffset64 > directoryEndOffset {
		return zipDirectory{}, errArchiveFormat
	}
	if records > directorySize/zipDirectoryHeaderLen {
		return zipDirectory{}, errArchiveFormat
	}

	return zipDirectory{
		offset:  directoryEndOffset - directorySize64,
		size:    directorySize64,
		records: records,
	}, nil
}

func findZipDirectoryEnd(tail []byte) int {
	for i := len(tail) - zipDirectoryEndLen; i >= 0; i-- {
		if binary.LittleEndian.Uint32(tail[i:i+4]) != zipDirectoryEndSignature {
			continue
		}
		commentLen := int(binary.LittleEndian.Uint16(tail[i+20 : i+22]))
		if i+zipDirectoryEndLen+commentLen == len(tail) {
			return i
		}
	}
	return -1
}

func readZip64Directory(f *os.File, endOffset int64) (end int64, records, size, offset uint64, err error) {
	locatorOffset := endOffset - zipDirectory64LocLen
	if locatorOffset < 0 {
		return 0, 0, 0, 0, errArchiveFormat
	}
	var locator [zipDirectory64LocLen]byte
	if err := readAtFull(f, locator[:], locatorOffset); err != nil {
		return 0, 0, 0, 0, err
	}
	if binary.LittleEndian.Uint32(locator[0:4]) != zipDirectory64LocSignature ||
		binary.LittleEndian.Uint32(locator[4:8]) != 0 ||
		binary.LittleEndian.Uint32(locator[16:20]) != 1 {
		return 0, 0, 0, 0, errArchiveFormat
	}
	zip64Offset := binary.LittleEndian.Uint64(locator[8:16])
	zip64Offset64, ok := archiveOffset(zip64Offset)
	if !ok || zip64Offset64 > locatorOffset {
		return 0, 0, 0, 0, errArchiveFormat
	}
	var record [zipDirectory64EndLen]byte
	if err := readAtFull(f, record[:], zip64Offset64); err != nil {
		return 0, 0, 0, 0, err
	}
	if binary.LittleEndian.Uint32(record[0:4]) != zipDirectory64EndSignature ||
		binary.LittleEndian.Uint64(record[4:12]) < zipDirectory64EndLen-12 ||
		binary.LittleEndian.Uint32(record[16:20]) != 0 ||
		binary.LittleEndian.Uint32(record[20:24]) != 0 {
		return 0, 0, 0, 0, errArchiveFormat
	}
	recordsThisDisk := binary.LittleEndian.Uint64(record[24:32])
	records = binary.LittleEndian.Uint64(record[32:40])
	if recordsThisDisk != records {
		return 0, 0, 0, 0, errArchiveFormat
	}
	return zip64Offset64, records,
		binary.LittleEndian.Uint64(record[40:48]),
		binary.LittleEndian.Uint64(record[48:56]), nil
}

func archiveOffset(value uint64) (int64, bool) {
	if value > 1<<63-1 {
		return 0, false
	}
	return int64(value), true // #nosec G115 -- the MaxInt64 bound is checked above.
}

func readAtFull(f *os.File, dst []byte, offset int64) error {
	n, err := f.ReadAt(dst, offset)
	if n != len(dst) {
		if errors.Is(err, io.EOF) {
			return errArchiveFormat
		}
		if err != nil {
			return err
		}
		return errArchiveFormat
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func scanZipDirectory(ctx context.Context, f *os.File, dir zipDirectory) (bool, error) {
	reader := bufio.NewReader(io.NewSectionReader(f, dir.offset, dir.size))
	var header [zipDirectoryHeaderLen]byte
	var records uint64
	holdsSite := false
	// A wp-config.php nested past the shallow bound only counts alongside a
	// WordPress runtime file, so both are accumulated across the whole
	// directory rather than decided per entry.
	deepConfig := false
	wpRuntime := false
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
		}
		records++
	}
	if records != dir.records {
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
	name := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(rawName, `\`, "/")))
	if name == "" || strings.HasPrefix(name, "/") ||
		(len(name) >= 3 && name[0] >= 'a' && name[0] <= 'z' && name[1] == ':' && name[2] == '/') {
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
