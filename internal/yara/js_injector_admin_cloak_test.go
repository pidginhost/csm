//go:build yara

package yara

import (
	"strings"
	"testing"
)

const yaraInjectorPlain = `<?php
if (is_admin()) { return; }
ob_start('visitor_filter');
atob
charCodeAt
Uint8Array
new Function`

func TestJSInjectorYARADetectsIdentifierVariants(t *testing.T) {
	s := loadRepoYaraScanner(t)
	cases := map[string]string{
		"plain": yaraInjectorPlain,
		"hex escaped": `<?php
if (is_admin()) { return; }
ob_start('visitor_filter');
\x61\x74\x6f\x62
charCodeAt
\x55\x69\x6e\x74\x38\x41\x72\x72\x61\x79
\x46\x75\x6e\x63\x74\x69\x6f\x6e`,
		"uppercase hex digits": `<?php
if (is_admin()) { return; }
ob_start('visitor_filter');
\x61\x74\x6F\x62
charCodeAt
\x55\x69\x6E\x74\x38\x41\x72\x72\x61\x79
\x46\x75\x6E\x63\x74\x69\x6F\x6E`,
		"mixed identifiers": `<?php
if (is_admin()) { return; }
ob_start('visitor_filter');
\x61\x74\x6f\x62
charCodeAt
Uint8Array
\x46\x75\x6e\x63\x74\x69\x6f\x6e`,
		"aliased JavaScript primitives": `<?php
if (is_admin()) { return; }
ob_start('visitor_filter');
const decode = atob;
const byteAt = Function.call.bind(String.prototype.charCodeAt);
const Bytes = Uint8Array;
const execute = Function;
const decoded = decode(payload);
const bytes = new Bytes(decoded.length);
bytes[0] = byteAt(decoded, 0);
execute(new TextDecoder().decode(bytes))();`,
		"reordered": `<?php
new Function
Uint8Array
charCodeAt
atob
IS_ADMIN ( )
OB_START (`,
	}
	for name, sample := range cases {
		if !hasYaraRule(s.ScanBytes([]byte(sample)), "js_injector_decode_exec") {
			t.Errorf("js_injector_decode_exec did not detect %s variant", name)
		}
	}
}

func TestJSInjectorYARARequiresEverySignal(t *testing.T) {
	s := loadRepoYaraScanner(t)
	cases := map[string]string{
		"output buffering": strings.ReplaceAll(yaraInjectorPlain, "ob_start", "start_buffer"),
		"admin guard":      strings.ReplaceAll(yaraInjectorPlain, "is_admin", "current_user_can"),
		"base64 decoder":   strings.ReplaceAll(yaraInjectorPlain, "atob", "decode64"),
		"byte access":      strings.ReplaceAll(yaraInjectorPlain, "charCodeAt", "byteAt"),
		"byte array":       strings.ReplaceAll(yaraInjectorPlain, "Uint8Array", "Array"),
		"execution sink":   strings.ReplaceAll(yaraInjectorPlain, "new Function", "console.log"),
	}
	for missing, sample := range cases {
		if hasYaraRule(s.ScanBytes([]byte(sample)), "js_injector_decode_exec") {
			t.Errorf("js_injector_decode_exec matched without %s", missing)
		}
	}
}

func TestJSInjectorYARARejectsCaseInsensitiveJSLookalikes(t *testing.T) {
	s := loadRepoYaraScanner(t)
	sample := strings.NewReplacer(
		"atob", "ATOB",
		"charCodeAt", "CHARCODEAT",
		"Uint8Array", "UINT8ARRAY",
		"new Function", "new FUNCTION",
	).Replace(yaraInjectorPlain)
	if hasYaraRule(s.ScanBytes([]byte(sample)), "js_injector_decode_exec") {
		t.Error("js_injector_decode_exec matched case-insensitive JavaScript lookalikes")
	}
}

func TestJSInjectorYARARequiresWholeJavaScriptIdentifiers(t *testing.T) {
	s := loadRepoYaraScanner(t)
	sample := `<?php
if (is_admin()) { return; }
ob_start('visitor_filter');
const datobValue = payload;
const mycharCodeAtHelper = datobValue;
const MyUint8ArrayFactory = mycharCodeAtHelper;
someFunction(MyUint8ArrayFactory);`
	if hasYaraRule(s.ScanBytes([]byte(sample)), "js_injector_decode_exec") {
		t.Error("js_injector_decode_exec matched JavaScript identifier substrings")
	}
}

func TestAdminListCloakYARADetectsBothBranches(t *testing.T) {
	s := loadRepoYaraScanner(t)
	cases := map[string]string{
		"plaintext": `<?php
plugin_basename(__FILE__)
all_plugins
pre_user_query
views_users`,
		"escaped": `<?php
plugin_basename(__FILE__)
add_filter("\x70\x72\x65\x5f", "callback");
get_current_user_id`,
		"uppercase PHP calls": `<?php
PLUGIN_BASENAME(__file__)
GET_CURRENT_USER_ID
ADD_FILTER("\x70\x72\x65\x5f", "callback");`,
	}
	for name, sample := range cases {
		matches := s.ScanBytes([]byte(sample))
		if !hasYaraRule(matches, "wp_admin_list_cloak") {
			t.Errorf("wp_admin_list_cloak did not detect %s branch", name)
			continue
		}
		for _, match := range matches {
			if match.RuleName != "wp_admin_list_cloak" {
				continue
			}
			if match.Meta["severity"] != "critical" || match.Meta["category"] != "backdoor" {
				t.Errorf("wp_admin_list_cloak metadata = %q/%q, want critical/backdoor", match.Meta["severity"], match.Meta["category"])
			}
		}
	}
}

func TestAdminListCloakYARARequiresCompleteBranch(t *testing.T) {
	s := loadRepoYaraScanner(t)
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
		if hasYaraRule(s.ScanBytes([]byte(sample)), "wp_admin_list_cloak") {
			t.Errorf("wp_admin_list_cloak matched repeated single signal %s", hook)
		}
	}

	incomplete := []string{
		`<?php
plugin_basename(__FILE__)
add_filter("\x70\x72\x65\x5f", "callback");`,
		`<?php
plugin_basename(__FILE__)
all_plugins
pre_user_query
add_filter("\x70\x72\x65\x5f", "callback");`,
		`<?php
plugin_basename(__FILE__)
pre_user_query
views_users`,
	}
	for _, sample := range incomplete {
		if hasYaraRule(s.ScanBytes([]byte(sample)), "wp_admin_list_cloak") {
			t.Error("wp_admin_list_cloak combined incomplete evidence into a match")
		}
	}
}

func TestAdminListCloakYARARejectsCaseInsensitiveHookLookalikes(t *testing.T) {
	s := loadRepoYaraScanner(t)
	sample := `<?php
plugin_basename(__FILE__)
ALL_PLUGINS
pre_user_query
views_users`
	if hasYaraRule(s.ScanBytes([]byte(sample)), "wp_admin_list_cloak") {
		t.Error("wp_admin_list_cloak matched a case-insensitive hook lookalike")
	}
}
