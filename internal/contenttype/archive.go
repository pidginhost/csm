// Package contenttype classifies file content shared by the malware scanners.
package contenttype

import (
	"bytes"
	"path/filepath"
	"strings"
)

var compressedArchiveMagics = [][]byte{
	{'P', 'K', 0x03, 0x04},                       // ZIP local file header
	{'P', 'K', 0x05, 0x06},                       // ZIP empty archive
	{'P', 'K', 0x07, 0x08},                       // ZIP spanned data descriptor
	{0x1f, 0x8b},                                 // gzip
	{'B', 'Z', 'h'},                              // bzip2
	{0xfd, '7', 'z', 'X', 'Z', 0x00},             // xz
	{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c},           // 7z
	{'R', 'a', 'r', '!', 0x1a, 0x07, 0x00},       // RAR 4.x
	{'R', 'a', 'r', '!', 0x1a, 0x07, 0x01, 0x00}, // RAR 5.x
}

// IsCompressedArchive reports whether data starts with a supported compressed
// archive signature. Tar and PHAR are intentionally excluded because their raw
// content is executable or otherwise meaningful to the signature engines.
func IsCompressedArchive(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	for _, magic := range compressedArchiveMagics {
		if bytes.HasPrefix(data, magic) {
			return true
		}
	}
	return false
}

// archiveExtensions are the names under which a compressed container is
// stored on a web host: plain archives plus the zip-based document, package
// and extension formats. Lowercase, leading dot.
var archiveExtensions = map[string]struct{}{
	".zip": {}, ".zipx": {}, ".jar": {}, ".war": {}, ".ear": {}, ".apk": {},
	".docx": {}, ".xlsx": {}, ".pptx": {}, ".odt": {}, ".ods": {}, ".odp": {},
	".epub": {}, ".whl": {}, ".egg": {}, ".crx": {}, ".xpi": {}, ".ipa": {},
	".nupkg": {}, ".vsix": {},
	".gz": {}, ".tgz": {}, ".svgz": {},
	".bz2": {}, ".tbz": {}, ".tbz2": {},
	".xz": {}, ".txz": {},
	".7z":  {},
	".rar": {},
}

// IsArchiveExt reports whether ext (leading dot, any case) names a compressed
// container format.
func IsArchiveExt(ext string) bool {
	_, ok := archiveExtensions[strings.ToLower(ext)]
	return ok
}

// IsArchiveFile reports whether both the name and the leading bytes identify a
// compressed container. Bytes alone are not enough: PHP echoes whatever
// precedes its open tag and runs the rest, so any interpreted file can start
// with archive magic and still execute. Only a file that also carries an
// archive extension is left to the extraction-time scan.
func IsArchiveFile(name string, data []byte) bool {
	return IsArchiveExt(filepath.Ext(name)) && IsCompressedArchive(data)
}
