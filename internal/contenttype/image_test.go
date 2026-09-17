package contenttype

import (
	"bytes"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"testing"
)

// onePixel builds a 1x1 opaque image the standard encoders accept.
func onePixel() image.Image {
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	img.Set(0, 0, color.RGBA{R: 1, G: 2, B: 3, A: 255})
	return img
}

func encodePNG(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, onePixel()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func encodeJPEG(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, onePixel(), nil); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func encodeGIF(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := gif.Encode(&buf, onePixel(), nil); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// webpContainer is the 12-byte RIFF/WEBP header plus a stub VP8 chunk.
func webpContainer() []byte {
	return append([]byte("RIFF\x24\x00\x00\x00WEBPVP8 "), make([]byte, 16)...)
}

// icoContainer is a single-entry ICO directory header.
func icoContainer() []byte {
	return append([]byte{0x00, 0x00, 0x01, 0x00, 0x01, 0x00}, make([]byte, 20)...)
}

// bmpContainer is a BITMAPFILEHEADER with the two reserved words zeroed.
func bmpContainer() []byte {
	return append([]byte("BM\x46\x00\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00"), make([]byte, 20)...)
}

func TestImageContainerRecognizesRealContainers(t *testing.T) {
	cases := map[string]struct {
		data []byte
		want string
	}{
		"png":  {encodePNG(t), "PNG"},
		"jpeg": {encodeJPEG(t), "JPEG"},
		"gif":  {encodeGIF(t), "GIF"},
		"webp": {webpContainer(), "WebP"},
		"ico":  {icoContainer(), "ICO"},
		"bmp":  {bmpContainer(), "BMP"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, ok := ImageContainer(tc.data)
			if !ok || got != tc.want {
				t.Fatalf("ImageContainer = (%q, %t), want (%q, true)", got, ok, tc.want)
			}
		})
	}
}

func TestImageContainerRejectsNonImages(t *testing.T) {
	cases := map[string][]byte{
		"php":            []byte("<?php echo 'hi';"),
		"html":           []byte("<!DOCTYPE html><html></html>"),
		"empty":          nil,
		"short":          []byte("BM"),
		"zip":            []byte("PK\x03\x04payload"),
		"bmp_reserved":   []byte("BM\x46\x00\x00\x00\x01\x00\x00\x00\x36\x00\x00\x00"),
		"ico_zero_count": append([]byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x00}, make([]byte, 20)...),
		"riff_wave":      append([]byte("RIFF\x24\x00\x00\x00WAVEfmt "), make([]byte, 16)...),
		"text_png_word":  []byte("PNG images are supported by this plugin."),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if got, ok := ImageContainer(data); ok {
				t.Fatalf("ImageContainer(%s) = (%q, true), want false", name, got)
			}
		})
	}
}

func TestIsImageExtCoversTheContainersWeRecognize(t *testing.T) {
	for _, ext := range []string{".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".PNG"} {
		if !IsImageExt(ext) {
			t.Errorf("IsImageExt(%q) = false, want true", ext)
		}
	}
	for _, ext := range []string{".php", ".html", ".js", ".svg", ".zip", ""} {
		if IsImageExt(ext) {
			t.Errorf("IsImageExt(%q) = true, want false", ext)
		}
	}
}

func TestHasPHPOpenTagRecognizesTheTagsAWebServerExecutes(t *testing.T) {
	for _, sample := range []string{"<?php echo 1;", "<?PHP echo 1;", "x<?= $a ?>", "\n<?php\n", "<?php"} {
		if !HasPHPOpenTag([]byte(sample)) {
			t.Errorf("HasPHPOpenTag(%q) = false, want true", sample)
		}
	}
	// The bare short tag is off by default and is the XML declaration's
	// opener, so it is not treated as PHP.
	for _, sample := range []string{"<?xml version=\"1.0\"?>", "<? echo 1;", "phpinfo();", "", "<?phpx", "<?php-example", "<?php/* comment */", "<?php\v", "<?php\f"} {
		if HasPHPOpenTag([]byte(sample)) {
			t.Errorf("HasPHPOpenTag(%q) = true, want false", sample)
		}
	}
}
