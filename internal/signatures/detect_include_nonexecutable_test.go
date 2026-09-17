package signatures

import "testing"

// A backdoor found on 2026-09-17 prepended one line to a theme file: a cookie
// check that includes a .png sitting in a plugin asset directory. The image
// held the payload. Nothing in either ruleset looked at what an include
// actually targets, so a PHP file pulling in a picture was indistinguishable
// from ordinary templating.
//
// The samples below are shared with the YARA-X pass so neither engine can
// drift from the other on the same shapes.
func includeLoaderPositives() map[string]string {
	return map[string]string{
		"minified_include":     `<?php if($_COOKIE['x'])include'assets/payload.png';`,
		"jpe_payload":          `<?php if($_COOKIE['x']) include 'assets/payload.jpe';`,
		"closing_tag":          `<?php if($_COOKIE['x']) include 'assets/payload.png' ?>`,
		"string_concatenation": `<?php if($_COOKIE['x']) include './assets/' . 'payload.png';`,
		// The incident shape: cookie gate, absolute path in a local, include
		// of that local, all on the first line of an otherwise normal theme
		// file.
		"cookie_gate_variable_indirection": `<?php if(isset($_COOKIE["sess_kx"])){$incName="/home/site/public_html/wp-content/plugins/demo/assets/lib/images/light_square/btn.png"; include($incName); exit;} ?>
<?php
get_header();
the_post();
get_footer();
`,
		"get_gate_literal_path": `<?php
if (!empty($_GET['p'])) {
    include_once "assets/cache/data.dat";
}
`,
		"request_gate_concatenated_path": `<?php
if (isset($_REQUEST['x'])) {
    require dirname(__FILE__) . '/img/logo.gif';
}
`,
		"cookie_gate_suppressed_include": `<?php
$k = $_COOKIE['a'];
$f = './tmp/' . $k . '.log';
@include($f);
`,
		"post_gate_base64_path": `<?php
if (isset($_POST['q'])) {
    include(base64_decode('Li9hc3NldHMvYmcucG5n'));
}
`,
		"get_gate_hex_path": `<?php
if (isset($_GET['h'])) {
    require_once(hex2bin('2e2f612e706e67'));
}
`,
		"cookie_gate_relative_no_parens": `<?php
if (isset($_COOKIE['c'])) include './assets/icons/sprite.png';
`,
		"header_gate_binary_payload": `<?php
if (isset($_SERVER['HTTP_X_APP_KEY'])) {
    include_once dirname(__FILE__) . '/cache/x.bin';
}
`,
		"include_before_gate": `<?php
$tmp = WP_CONTENT_DIR . '/uploads/2026/09/shot.jpg';
include $tmp;
if (isset($_GET['run'])) {
    echo 'ok';
}
`,
	}
}

func includeLoaderNegatives() map[string]string {
	return map[string]string{
		"text_partial":                   `<?php if (isset($_GET['terms'])) { include 'terms.txt'; }`,
		"include_result_used_with_image": `<?php if ($_GET['preview']) { $out = (include 'layout.php') . '<img src="icon.png">'; }`,
		"include_helper":                 `<?php if ($_GET['preview']) { include_asset('icon.png'); }`,
		"include_result_concatenation":   `<?php if ($_GET['preview']) { $out = include('layout.php') . '/icons/sprite.png'; }`,
		// Ordinary templating: an HTML partial pulled in behind a request
		// check. The target is source, not an opaque payload container.
		"html_partial_behind_request_check": `<?php
$tpl = get_template_directory() . '/partials/hero.html';
if ( ! empty( $_GET['preview'] ) ) {
    include $tpl;
}
`,
		"tpl_partial_and_request_read": `<?php
include dirname( __FILE__ ) . '/tpl/widget.tpl';
$q = isset( $_POST['q'] ) ? sanitize_text_field( $_POST['q'] ) : '';
echo esc_html( $q );
`,
		"svg_partial_include": `<?php
if ( isset( $_GET['icon'] ) ) {
    include get_stylesheet_directory() . '/assets/icons/logo.svg';
}
`,
		// An asset URL held in a local beside an ordinary class include. Both
		// statements are adjacent, which is what a proximity-only rule would
		// have fired on.
		"asset_url_beside_class_require": `<?php
$icon = plugin_dir_url( __FILE__ ) . 'assets/icon.png';
require_once $plugin_dir . 'includes/class-demo-widget.php';
if ( isset( $_GET['tab'] ) ) {
    demo_render_tab( $_GET['tab'] );
}
`,
		// Serving an image the request names. The path is read, never
		// included, so no code can run from it.
		"request_named_image_is_read_not_included": `<?php
$file = ABSPATH . 'wp-content/uploads/' . basename( $_GET['f'] ) . '.png';
if ( file_exists( $file ) ) {
    header( 'Content-Type: image/png' );
    readfile( $file );
}
`,
		"plugin_bootstrap_without_request_input": `<?php
$cache = WP_CONTENT_DIR . '/cache/demo/manifest.dat';
if ( file_exists( $cache ) ) {
    include $cache;
}
`,
	}
}

func TestBackdoorIncludeNonExecutableMatchesGatedLoaders(t *testing.T) {
	scanner := loadRepoScanner(t)
	for name, sample := range includeLoaderPositives() {
		t.Run(name, func(t *testing.T) {
			if !yamlRuleFired(scanner, "backdoor_include_nonexecutable", sample, ".php") {
				t.Errorf("backdoor_include_nonexecutable did not match %s", name)
			}
		})
	}
}

func TestBackdoorIncludeNonExecutableIgnoresOrdinaryTemplating(t *testing.T) {
	scanner := loadRepoScanner(t)
	for name, sample := range includeLoaderNegatives() {
		t.Run(name, func(t *testing.T) {
			if yamlRuleFired(scanner, "backdoor_include_nonexecutable", sample, ".php") {
				t.Errorf("backdoor_include_nonexecutable fired on %s", name)
			}
		})
	}
}

// A minified bundle naming an include helper is not PHP and must never reach
// this rule, whichever extension the scanner is handed.
func TestBackdoorIncludeNonExecutableIgnoresMinifiedJavaScript(t *testing.T) {
	scanner := loadRepoScanner(t)
	sample := `!function(e){var t=e.include||function(n){return n};t("./sprite.png");var r=e.location.search;}(window);`
	for _, ext := range []string{".js", ".php"} {
		if yamlRuleFired(scanner, "backdoor_include_nonexecutable", sample, ext) {
			t.Errorf("backdoor_include_nonexecutable fired on minified JavaScript scanned as %s", ext)
		}
	}
}

func yamlRuleFired(scanner *Scanner, rule, sample, ext string) bool {
	for _, match := range scanner.ScanContent([]byte(sample), ext) {
		if match.RuleName == rule {
			return true
		}
	}
	return false
}
