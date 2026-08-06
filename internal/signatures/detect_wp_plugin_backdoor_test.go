package signatures

import "testing"

// The 2026-08-06 link-farm kit hid its loader from the plugin list so the
// site owner could never see it in wp-admin. It unsets its own entry,
// keyed off plugin_basename(__FILE__), unless a magic query arg is set.
func TestWPPluginSelfHidingMatchesAllPluginsFilter(t *testing.T) {
	sample := []byte(`<?php
if (!defined('ABSPATH')) { exit; }
add_filter ('all_plugins', function ($plugins) {
    if (isset($_GET['sp'])) {
        return $plugins;
    }
    $current = plugin_basename (__FILE__);
    unset ($plugins[$current]);
    return $plugins;
});
`)
	match, ok := scanRepoRules(t, sample)["wp_plugin_self_hiding"]
	if !ok {
		t.Fatal("wp_plugin_self_hiding did not match a plugin that unsets itself from all_plugins")
	}
	if match.Severity != "critical" || match.Category != "backdoor" {
		t.Errorf("metadata = %q/%q, want critical/backdoor", match.Severity, match.Category)
	}
}

// White-label plugins legitimately hide OTHER plugins by name. Without both
// self-concealment and the incident's reveal flag, this is ordinary branding.
func TestWPPluginSelfHidingIgnoresWhiteLabelHidingOtherPlugins(t *testing.T) {
	sample := []byte(`<?php
add_filter('all_plugins', function ($plugins) {
    unset($plugins['hello-dolly/hello.php']);
    unset($plugins['akismet/akismet.php']);
    return $plugins;
});
`)
	if _, ok := scanRepoRules(t, sample)["wp_plugin_self_hiding"]; ok {
		t.Error("wp_plugin_self_hiding matched a white-label plugin hiding other plugins by name")
	}
}

// Some white-label products intentionally hide their own bootstrap from the
// plugin list. Self-hiding alone is not enough: the incident loader also had
// a magic request flag that temporarily revealed it to the attacker.
func TestWPPluginSelfHidingIgnoresLegitimateSelfHiding(t *testing.T) {
	sample := []byte(`<?php
add_filter('all_plugins', function ($plugins) {
    if (!get_option('agency_hide_branding')) {
        return $plugins;
    }
    $current = plugin_basename(__FILE__);
    unset($plugins[$current]);
    return $plugins;
});
`)
	if _, ok := scanRepoRules(t, sample)["wp_plugin_self_hiding"]; ok {
		t.Error("wp_plugin_self_hiding matched ordinary white-label self-hiding")
	}
}

func TestWPPluginSelfHidingIgnoresUnrelatedRequestFlag(t *testing.T) {
	sample := []byte(`<?php
add_filter('all_plugins', function ($plugins) {
    $current = plugin_basename(__FILE__);
    unset($plugins[$current]);
    return $plugins;
});
function agency_share_preview() {
    if (isset($_GET['sp'])) {
        return sanitize_text_field($_GET['sp']);
    }
}
`)
	if _, ok := scanRepoRules(t, sample)["wp_plugin_self_hiding"]; ok {
		t.Error("wp_plugin_self_hiding matched an unrelated request flag outside the hiding callback")
	}
}

// The reveal flag must guard the self-removal branch itself. A plugin can
// inspect the same short query key for an unrelated feature in the callback
// without turning separate branding logic into an attacker reveal channel.
func TestWPPluginSelfHidingIgnoresUnrelatedFlagInCallback(t *testing.T) {
	sample := []byte(`<?php
add_filter('all_plugins', function ($plugins) {
    if (isset($_GET['sp'])) {
        audit_share_preview($_GET['sp']);
    }
    return $plugins;
});
function agency_hide_branding($plugins) {
    $current = plugin_basename(__FILE__);
    unset($plugins[$current]);
    return $plugins;
}
`)
	if _, ok := scanRepoRules(t, sample)["wp_plugin_self_hiding"]; ok {
		t.Error("wp_plugin_self_hiding joined an unrelated request flag to separate branding logic")
	}
}

// wpueditors exposed an unauthenticated command route that minted hidden
// administrators. The open command channel plus administrator assignment is
// the incident shape; unrelated public routes are insufficient.
func TestWPRestUnauthAdminCreateMatchesBackdoorController(t *testing.T) {
	sample := []byte(`<?php
function wpeditor_register_routes() {
    register_rest_route ($namespace, "/command", array(
        "methods" => "POST",
        "callback" => "wpeditor_handle_command",
        "permission_callback" => "__return_true",
    ));
}
function wpeditor_create_admin($login, $email) {
    $password = wp_generate_password(24, true, false);
    $user_id = wp_create_user ($login, $password, $email);
    $user = new WP_User($user_id);
    $user->set_role ("administrator");
    return $user_id;
}
`)
	match, ok := scanRepoRules(t, sample)["wp_rest_unauth_admin_create"]
	if !ok {
		t.Fatal("wp_rest_unauth_admin_create did not match an unauthenticated admin-creation route")
	}
	if match.Severity != "critical" || match.Category != "backdoor" {
		t.Errorf("metadata = %q/%q, want critical/backdoor", match.Severity, match.Category)
	}
}

// A public read-only REST endpoint is ordinary plugin code. Without the
// administrator-minting sink it must not be flagged.
func TestWPRestUnauthAdminCreateIgnoresPublicReadEndpoint(t *testing.T) {
	sample := []byte(`<?php
register_rest_route('myplugin/v1', '/posts', array(
    'methods' => 'GET',
    'callback' => 'myplugin_list_posts',
    'permission_callback' => '__return_true',
));
`)
	if _, ok := scanRepoRules(t, sample)["wp_rest_unauth_admin_create"]; ok {
		t.Error("wp_rest_unauth_admin_create matched a benign public read endpoint")
	}
}

// Membership plugins can keep public registration and privileged account
// management in one controller file. A flat file-wide token conjunction must
// not turn those unrelated routes into an unauthenticated admin backdoor.
func TestWPRestUnauthAdminCreateIgnoresMembershipController(t *testing.T) {
	sample := []byte(`<?php
register_rest_route('membership/v1', '/register', array(
    'methods' => 'POST',
    'callback' => 'membership_register',
    'permission_callback' => '__return_true',
));
function membership_register($request) {
    return wp_insert_user(array(
        'user_login' => $request['login'],
        'role' => 'subscriber',
    ));
}
function membership_promote($user_id) {
    if (!current_user_can('promote_users')) {
        return new WP_Error('forbidden');
    }
    return wp_update_user(array('ID' => $user_id, 'role' => 'administrator'));
}
`)
	if _, ok := scanRepoRules(t, sample)["wp_rest_unauth_admin_create"]; ok {
		t.Error("wp_rest_unauth_admin_create matched unrelated public registration and privileged admin management")
	}
}

// A protected command endpoint can coexist with a separate open read route.
// The open permission must belong to the command route, not merely follow it
// somewhere else in the file.
func TestWPRestUnauthAdminCreateDoesNotBorrowPermissionFromLaterRoute(t *testing.T) {
	sample := []byte(`<?php
register_rest_route('membership/v1', '/command', array(
    'callback' => 'membership_admin_command',
    'permission_callback' => 'membership_can_manage_users',
));
register_rest_route('membership/v1', '/plans', array(
    'callback' => 'membership_list_plans',
    'permission_callback' => '__return_true',
));
function membership_admin_command($request) {
    $id = wp_create_user($request['login'], wp_generate_password());
    (new WP_User($id))->set_role('administrator');
}
`)
	if _, ok := scanRepoRules(t, sample)["wp_rest_unauth_admin_create"]; ok {
		t.Error("wp_rest_unauth_admin_create borrowed an open permission from a later route")
	}
}

// The 402KB wpueditors loader built every array key and string from
// chr() chains so static scanners saw no readable identifiers.
func TestPHPChrChainObfuscationMatchesImplodeChrArray(t *testing.T) {
	sample := []byte(`<?php
$e = error_get_last();
if ($e && in_array($e[implode ('', array (chr (116), chr (121), chr (112), chr (101)))], array(1, 4, 16, 64), true)) {
    error_log($e[implode('', array(chr(109), chr(101), chr(115), chr(115), chr(97), chr(103), chr(101)))]);
}
`)
	match, ok := scanRepoRules(t, sample)["php_chr_chain_obfuscation"]
	if !ok {
		t.Fatal("php_chr_chain_obfuscation did not match implode/chr key building")
	}
	if match.Severity != "critical" || match.Category != "obfuscation" {
		t.Errorf("metadata = %q/%q, want critical/obfuscation", match.Severity, match.Category)
	}
}

// Occasional chr() use is normal (control characters, CSV delimiters).
func TestPHPChrChainObfuscationIgnoresOccasionalChr(t *testing.T) {
	sample := []byte(`<?php
$delimiter = chr(9);
$newline = chr(10) . chr(13);
fwrite($fh, $row . $newline);
`)
	if _, ok := scanRepoRules(t, sample)["php_chr_chain_obfuscation"]; ok {
		t.Error("php_chr_chain_obfuscation matched ordinary chr() usage")
	}
}

// advanced-linkflow-control.php hid its C2 as a hex-escaped literal.
func TestPHPHexEscapedURLMatchesObfuscatedC2(t *testing.T) {
	sample := []byte(`<?php
class Advanced_LinkFlow_Control {
    private $server_url = "\x68\x74\x74\x70\x73\x3a\x2f\x2f\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d\x2f\x67\x65\x74\x2e\x70\x68\x70";
}
`)
	match, ok := scanRepoRules(t, sample)["php_hex_escaped_url"]
	if !ok {
		t.Fatal("php_hex_escaped_url did not match a hex-escaped http URL literal")
	}
	if match.Severity != "critical" || match.Category != "obfuscation" {
		t.Errorf("metadata = %q/%q, want critical/obfuscation", match.Severity, match.Category)
	}
}

// A plain URL in source is not obfuscation.
func TestPHPHexEscapedURLIgnoresPlainURL(t *testing.T) {
	sample := []byte(`<?php
$endpoint = "https://api.example.com/v1/get.php";
$response = wp_remote_get($endpoint);
`)
	if _, ok := scanRepoRules(t, sample)["php_hex_escaped_url"]; ok {
		t.Error("php_hex_escaped_url matched a plain URL")
	}
}
