package signatures

import "testing"

// webshell_request_decoded_exec has three sink arms. The call_user_func and
// backtick arms carried a double-escaped dollar that the regex engine read
// as a literal backslash followed by an end anchor, so those two arms could
// never match a PHP variable. Every arm must fire on its own shape.
func TestDecodedExecRuleMatchesEverySinkArm(t *testing.T) {
	scanner := loadRepoScanner(t)
	for name, body := range map[string]string{
		"direct sink":    "<?php $c=base64_decode($_REQUEST['b']); passthru($c);",
		"call_user_func": "<?php $c=base64_decode($_REQUEST['b']); call_user_func('system', $c);",
		"backtick":       "<?php $c=base64_decode($_REQUEST['b']); `$c`;",
	} {
		t.Run(name, func(t *testing.T) {
			for _, m := range scanner.ScanContent([]byte(body), ".php") {
				if m.RuleName == "webshell_request_decoded_exec" {
					return
				}
			}
			t.Fatalf("webshell_request_decoded_exec did not match the %s arm", name)
		})
	}
}
