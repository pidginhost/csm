package contenttype

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// imageExts are the file extensions served as raster images. The set exists
// for path-based dispatch only. Detection never trusts it: every content
// decision goes through ImageContainer, so renaming a payload cannot hide it.
var imageExts = map[string]bool{
	".png":  true,
	".jpg":  true,
	".jpeg": true,
	".jpe":  true,
	".gif":  true,
	".webp": true,
	".ico":  true,
	".cur":  true,
	".bmp":  true,
	".tif":  true,
	".tiff": true,
}

// IsImageExt reports whether ext (with the leading dot, any case) names a
// raster image format.
func IsImageExt(ext string) bool {
	return imageExts[strings.ToLower(ext)]
}

// ImageContainer identifies the raster image format data begins with and
// returns its display name. A hostile file can carry any extension, so the
// verdict comes from the leading bytes alone.
//
// The signatures are deliberately longer than the shortest unique prefix.
// "BM" and the ICO lead-in are two and four bytes wide, which ordinary text
// reaches by chance, so the structural fields that follow them are checked
// too: an image container that also holds PHP is a strong detection signal
// and a weak magic test would spend it on plain files.
func ImageContainer(data []byte) (string, bool) {
	switch {
	case bytes.HasPrefix(data, []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}):
		return "PNG", true
	case bytes.HasPrefix(data, []byte{0xff, 0xd8, 0xff}):
		return "JPEG", true
	case bytes.HasPrefix(data, []byte("GIF87a")), bytes.HasPrefix(data, []byte("GIF89a")):
		return "GIF", true
	case len(data) >= 12 && bytes.HasPrefix(data, []byte("RIFF")) && bytes.Equal(data[8:12], []byte("WEBP")):
		return "WebP", true
	case isICO(data):
		return "ICO", true
	case isBMP(data):
		return "BMP", true
	case bytes.HasPrefix(data, []byte{0x49, 0x49, 0x2a, 0x00}), bytes.HasPrefix(data, []byte{0x4d, 0x4d, 0x00, 0x2a}):
		return "TIFF", true
	}
	return "", false
}

// isICO checks the ICONDIR header: two reserved zero bytes, a type of 1 (icon)
// or 2 (cursor), and at least one directory entry.
func isICO(data []byte) bool {
	if len(data) < 6 {
		return false
	}
	if data[0] != 0 || data[1] != 0 {
		return false
	}
	imageType := binary.LittleEndian.Uint16(data[2:4])
	if imageType != 1 && imageType != 2 {
		return false
	}
	return binary.LittleEndian.Uint16(data[4:6]) > 0
}

// isBMP checks the BITMAPFILEHEADER: the "BM" tag, the two reserved words
// which the format requires to be zero, and a pixel-data offset that lands
// past the header.
func isBMP(data []byte) bool {
	if len(data) < 14 || data[0] != 'B' || data[1] != 'M' {
		return false
	}
	if binary.LittleEndian.Uint32(data[6:10]) != 0 {
		return false
	}
	return binary.LittleEndian.Uint32(data[10:14]) >= 14
}
