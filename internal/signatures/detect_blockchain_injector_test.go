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

func TestBlockchainInjectorDetectsMixedIdentifierVariants(t *testing.T) {
	sample := injectorSample(hexAtob, "Uint8Array", hexFunction)
	if _, ok := scanRepoRules(t, []byte(sample))["js_injector_decode_exec"]; !ok {
		t.Error("injector with mixed plain and hex-escaped identifiers not detected")
	}
}

func TestBlockchainInjectorDetectsAliasedJavaScriptPrimitives(t *testing.T) {
	sample := strings.Join([]string{
		"<?php",
		"if (is_admin()) { return; }",
		"ob_start('visitor_filter');",
		"const decode = atob;",
		"const byteAt = Function.call.bind(String.prototype.charCodeAt);",
		"const Bytes = Uint8Array;",
		"const execute = Function;",
		"const decoded = decode(payload);",
		"const bytes = new Bytes(decoded.length);",
		"bytes[0] = byteAt(decoded, 0);",
		"execute(new TextDecoder().decode(bytes))();",
	}, "\n")
	if _, ok := scanRepoRules(t, []byte(sample))["js_injector_decode_exec"]; !ok {
		t.Error("injector with aliased JavaScript primitives not detected")
	}
}

func TestBlockchainInjectorDetectsUppercaseHexDigits(t *testing.T) {
	sample := injectorSample(
		`\x61\x74\x6F\x62`,
		`\x55\x69\x6E\x74\x38\x41\x72\x72\x61\x79`,
		`\x46\x75\x6E\x63\x74\x69\x6F\x6E`,
	)
	if _, ok := scanRepoRules(t, []byte(sample))["js_injector_decode_exec"]; !ok {
		t.Error("hex-escaped injector with uppercase hex digits not detected")
	}
}

func TestBlockchainInjectorSignalsAreOrderIndependent(t *testing.T) {
	sample := strings.Join([]string{
		"<?php",
		"new Function",
		"Uint8Array",
		"charCodeAt",
		"atob",
		"IS_ADMIN ( )",
		"OB_START (",
	}, "\n")
	if _, ok := scanRepoRules(t, []byte(sample))["js_injector_decode_exec"]; !ok {
		t.Error("injector evidence was made order-dependent")
	}
}

func TestBlockchainInjectorRequiresEverySignal(t *testing.T) {
	full := injectorSample("atob", "Uint8Array", "new Function")
	cases := map[string]string{
		"output buffering": strings.ReplaceAll(full, "ob_start", "start_buffer"),
		"admin guard":      strings.ReplaceAll(full, "is_admin", "current_user_can"),
		"base64 decoder":   strings.ReplaceAll(full, "atob", "decode64"),
		"byte access":      strings.ReplaceAll(full, "charCodeAt", "byteAt"),
		"byte array":       strings.ReplaceAll(full, "Uint8Array", "Array"),
		"execution sink":   strings.ReplaceAll(full, "new Function", "console.log"),
	}
	for missing, sample := range cases {
		if m, ok := scanRepoRules(t, []byte(sample))["js_injector_decode_exec"]; ok {
			t.Errorf("injector matched without %s: %+v", missing, m)
		}
	}
}

func TestBlockchainInjectorRejectsCaseInsensitiveJSLookalikes(t *testing.T) {
	sample := injectorSample("ATOB", "UINT8ARRAY", "new FUNCTION")
	sample = strings.ReplaceAll(sample, "charCodeAt", "CHARCODEAT")
	if m, ok := scanRepoRules(t, []byte(sample))["js_injector_decode_exec"]; ok {
		t.Errorf("case-insensitive JavaScript lookalikes matched: %+v", m)
	}
}

func TestBlockchainInjectorRequiresWholeJavaScriptIdentifiers(t *testing.T) {
	sample := strings.Join([]string{
		"<?php",
		"if (is_admin()) { return; }",
		"ob_start('visitor_filter');",
		"const datobValue = payload;",
		"const mycharCodeAtHelper = datobValue;",
		"const MyUint8ArrayFactory = mycharCodeAtHelper;",
		"someFunction(MyUint8ArrayFactory);",
	}, "\n")
	if m, ok := scanRepoRules(t, []byte(sample))["js_injector_decode_exec"]; ok {
		t.Errorf("JavaScript identifier substrings matched as a complete injector chain: %+v", m)
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
	match, ok := scanRepoRules(t, []byte(cloakerPlain))["wp_admin_list_cloak"]
	if !ok {
		t.Error("plaintext rogue-admin cloaker not detected")
	}
	if match.Severity != "critical" || match.Category != "backdoor" {
		t.Errorf("wp_admin_list_cloak metadata = %q/%q, want critical/backdoor", match.Severity, match.Category)
	}
}

func TestAdminCloakerDetectsEscapedHookVariant(t *testing.T) {
	if _, ok := scanRepoRules(t, []byte(cloakerEscaped))["wp_admin_list_cloak"]; !ok {
		t.Error("escaped-hook rogue-admin cloaker not detected")
	}
}

func TestAdminCloakerAcceptsCaseInsensitivePHPCalls(t *testing.T) {
	sample := `<?php
PLUGIN_BASENAME(__file__)
GET_CURRENT_USER_ID
ADD_FILTER("\x70\x72\x65\x5f", "callback");`
	if _, ok := scanRepoRules(t, []byte(sample))["wp_admin_list_cloak"]; !ok {
		t.Error("escaped-hook cloak with uppercase PHP calls not detected")
	}
}

func TestAdminCloakerPlainBranchIsOrderIndependent(t *testing.T) {
	hooks := []string{
		"pre_user_query",
		"pre_count_users",
		"views_users",
		"users_list_table_query_args",
		"wsh_tracked_admin_ids",
	}
	for i := 0; i < len(hooks); i++ {
		for j := i + 1; j < len(hooks); j++ {
			orders := [][]string{
				{"all_plugins", hooks[i], hooks[j]},
				{hooks[i], "all_plugins", hooks[j]},
				{hooks[i], hooks[j], "all_plugins"},
			}
			for position, evidence := range orders {
				sample := "<?php\nplugin_basename(__FILE__)\n" + strings.Join(evidence, "\n")
				if _, ok := scanRepoRules(t, []byte(sample))["wp_admin_list_cloak"]; !ok {
					t.Errorf("plaintext cloak not detected for %s + %s at plugin-hook position %d", hooks[i], hooks[j], position)
				}
			}
		}
	}
}

func TestAdminCloakerRequiresTwoDistinctPlaintextSignals(t *testing.T) {
	hooks := []string{
		"pre_user_query",
		"pre_count_users",
		"views_users",
		"users_list_table_query_args",
		"wsh_tracked_admin_ids",
	}
	for _, hook := range hooks {
		sample := strings.Join([]string{
			"<?php",
			"plugin_basename(__FILE__)",
			"all_plugins",
			hook,
			hook,
		}, "\n")
		if m, ok := scanRepoRules(t, []byte(sample))["wp_admin_list_cloak"]; ok {
			t.Errorf("plaintext cloak matched repeated single signal %s: %+v", hook, m)
		}
	}
}

func TestAdminCloakerEscapedBranchRequiresCurrentUserGuard(t *testing.T) {
	withoutGuard := strings.ReplaceAll(cloakerEscaped, "get_current_user_id", "wp_get_current_user")
	if m, ok := scanRepoRules(t, []byte(withoutGuard))["wp_admin_list_cloak"]; ok {
		t.Errorf("escaped-hook cloak matched without current-user guard: %+v", m)
	}
}

func TestAdminCloakerDoesNotCombineIncompleteBranches(t *testing.T) {
	cases := []string{`<?php
plugin_basename(__FILE__)
all_plugins
pre_user_query

add_filter("\x70\x72\x65\x5f", "callback");`, `<?php
plugin_basename(__FILE__)
pre_user_query
views_users`}
	for _, sample := range cases {
		if m, ok := scanRepoRules(t, []byte(sample))["wp_admin_list_cloak"]; ok {
			t.Errorf("admin cloaker matched incomplete evidence: %+v", m)
		}
	}
}

func TestAdminCloakerRejectsCaseInsensitiveHookLookalikes(t *testing.T) {
	sample := "<?php\nplugin_basename(__FILE__)\nALL_PLUGINS\npre_user_query\nviews_users"
	if m, ok := scanRepoRules(t, []byte(sample))["wp_admin_list_cloak"]; ok {
		t.Errorf("case-insensitive hook lookalike matched: %+v", m)
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
