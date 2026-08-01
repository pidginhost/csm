package signatures

import (
	"strings"
	"testing"
)

// Fixtures are assembled from the individual tokens the rules key on rather
// than pasted from a live sample: the point is to prove the rule's contract
// (which combination fires, which does not), and a runnable payload in the
// repo would add risk without adding coverage.
func injectorSample(decoder, arrayType, sink string) string {
	return strings.Join([]string{
		"<?php",
		"if ( ! defined( 'ABSPATH' ) ) { exit; }",
		"add_action( 'init', 'x_stream' );",
		"function x_stream() {",
		"    if ( is_admin() ) { return; }",
		"    ob_start( 'x_stream_filter' );",
		"}",
		"function x_stream_filter( $html ) {",
		"    $s = '<" + "script>' .",
		"      'var k=' . " + "'" + decoder + "(\"a2V5\");' .",
		"      'var d=' . " + "'" + decoder + "(\"cGF5bG9hZA==\");' .",
		"      'var b=new " + arrayType + "(d.length);' .",
		"      'for(var i=0;i<d.length;i++)b[i]=d.charCodeAt(i)^k.charCodeAt(i%k.length);' .",
		"      '(" + sink + "(new TextDecoder().decode(b)))();' .",
		"      '</" + "script>';",
		"    return str_replace( '</head>', $s . '</head>', $html );",
		"}",
	}, "\n")
}

// Variant seen in the wild: identifiers hex-escaped so a plaintext search for
// them finds nothing.
const hexAtob = `\x61\x74\x6f\x62`
const hexUint8 = `\x55\x69\x6e\x74\x38\x41\x72\x72\x61\x79`
const hexFunction = `\x46\x75\x6e\x63\x74\x69\x6f\x6e`

func TestBlockchainInjectorDetectsPlainVariant(t *testing.T) {
	sample := injectorSample("atob", "Uint8Array", "new Function")
	if _, ok := scanRepoRules(t, []byte(sample))["js_injector_decode_exec"]; !ok {
		t.Error("plain-identifier injector not detected")
	}
}

func TestBlockchainInjectorDetectsHexEscapedVariant(t *testing.T) {
	sample := injectorSample(hexAtob, hexUint8, hexFunction)
	if _, ok := scanRepoRules(t, []byte(sample))["js_injector_decode_exec"]; !ok {
		t.Error("hex-escaped injector not detected")
	}
}

// Each of these carries part of the chain. A rule that fires on any of them
// would bury the operator: buffering, decoding and self-hiding are all ordinary
// on their own across a real plugin estate.
func TestBlockchainInjectorIgnoresPartialChains(t *testing.T) {
	cases := map[string]string{
		"buffering_only": `<?php
add_action('init', function(){ if (is_admin()) { return; } ob_start('wpo_cache'); });
function wpo_cache($html){ return $html . "<!-- cached -->"; }`,
		"static_script_inject": `<?php
add_action('init', function(){ if (is_admin()) return; ob_start('ga_buf'); });
function ga_buf($h){ return str_replace('</head>', '<scr'.'ipt src="/t.js"></scr'.'ipt></head>', $h); }`,
		"php_base64_only": `<?php
$logo = base64_decode($encoded_png);
file_put_contents($path, $logo);`,
		// decodes to bytes but never executes them, and never buffers output
		"decode_without_sink": `<?php
$s = 'var raw=atob(p);var a=new Uint8Array(raw.length);' .
     'for(var i=0;i<raw.length;i++)a[i]=raw.charCodeAt(i);' .
     'img.src=URL.createObjectURL(new Blob([a]));';
echo $s;`,
		"self_hiding_only": `<?php
add_filter('all_plugins', function($p){ unset($p[plugin_basename(__FILE__)]); return $p; });
add_action('admin_init', 'hmw_settings');`,
	}
	for name, sample := range cases {
		if m, ok := scanRepoRules(t, []byte(sample))["js_injector_decode_exec"]; ok {
			t.Errorf("false positive on %s: %+v", name, m)
		}
	}
}

// Cloaker variant A: hides itself and filters the user list, tracking the
// concealed IDs in an option.
const cloakerPlain = `<?php
final class WP_Security_Helper {
	const OPTION_TRACKED = 'wsh_tracked_admin_ids';
	private function __construct() {
		add_action('pre_user_query', array($this, 'filter_pre_user_query'), 10, 1);
		add_filter('pre_count_users', array($this, 'adjust_count_users'), 999, 3);
		add_filter('views_users', array($this, 'finalize_views_users_counts'), PHP_INT_MAX, 1);
		add_filter('all_plugins', array($this, 'hide_plugin_from_list'));
	}
	public function hide_plugin_from_list($p) {
		$self = plugin_basename(__FILE__);
		unset($p[$self]);
		return $p;
	}
}
`

// Cloaker variant B: every hook name written as an escaped byte string, so a
// plaintext search for the hook names finds nothing.
const cloakerEscaped = `<?php
class WP_Security_Helper {
	private function __construct() {
		add_action("\160\162\x65\137\147\145\x74\137\x75\163\145\162\163", array($this, "fq"));
		add_filter("\x75\163\145\162\163\x5f\154\151\163\164", array($this, "mt"));
		add_filter("\x61\154\154\137\160\154\165\147\151\156\163", array($this, "hide_plugin_from_list"));
	}
	public function fq($q) { $u = get_current_user_id(); $q->set("include", array($u)); }
	public function hide_plugin_from_list($p) {
		$self = plugin_basename(__FILE__);
		unset($p[$self]);
		return $p;
	}
}
`

func TestAdminCloakerDetectsPlainVariant(t *testing.T) {
	if _, ok := scanRepoRules(t, []byte(cloakerPlain))["wp_admin_list_cloak"]; !ok {
		t.Error("plaintext rogue-admin cloaker not detected")
	}
}

func TestAdminCloakerDetectsEscapedHookVariant(t *testing.T) {
	if _, ok := scanRepoRules(t, []byte(cloakerEscaped))["wp_admin_list_cloak"]; !ok {
		t.Error("escaped-hook rogue-admin cloaker not detected")
	}
}

// Wordfence, WooCommerce, Jetpack and BuddyPress all legitimately touch the
// user-query and user-count hooks, and hardening plugins legitimately hide
// themselves. A rule keyed on either half alone flagged 354 directories on a
// live host, most of them well-known-good software.
func TestAdminCloakerIgnoresLegitimateHookUse(t *testing.T) {
	cases := map[string]string{
		"user_hooks_without_self_hide": `<?php
add_action('pre_user_query', 'wf_filter_user_query');
add_filter('pre_count_users', 'wf_count_users', 10, 3);
add_filter('views_users', 'wf_views');
function wf_filter_user_query($q){ return $q; }`,
		"self_hide_without_user_hooks": `<?php
add_filter('all_plugins', function($p){ unset($p[plugin_basename(__FILE__)]); return $p; });
add_action('admin_menu', 'hmw_menu');`,
		"single_user_hook_with_self_hide": `<?php
add_filter('all_plugins', function($p){ unset($p[plugin_basename(__FILE__)]); return $p; });
add_filter('views_users', function($v){ $v['custom'] = 'Subscribers'; return $v; });`,
	}
	for name, sample := range cases {
		if m, ok := scanRepoRules(t, []byte(sample))["wp_admin_list_cloak"]; ok {
			t.Errorf("false positive on %s: %+v", name, m)
		}
	}
}
