//go:build yara

package yara

import "testing"

// The .yar twin of webshell_request_decoded_exec carried the same
// double-escaped dollar in its call_user_func and backtick arms.
func TestDecodedExecRuleMatchesEverySinkArm(t *testing.T) {
	scanner := loadRepoYaraScanner(t)
	for name, body := range map[string]string{
		"direct sink":    "<?php $c=base64_decode($_REQUEST['b']); passthru($c);",
		"call_user_func": "<?php $c=base64_decode($_REQUEST['b']); call_user_func('system', $c);",
		"backtick":       "<?php $c=base64_decode($_REQUEST['b']); `$c`;",
	} {
		t.Run(name, func(t *testing.T) {
			for _, m := range scanner.ScanBytes([]byte(body)) {
				if m.RuleName == "webshell_request_decoded_exec" {
					return
				}
			}
			t.Fatalf("webshell_request_decoded_exec did not match the %s arm", name)
		})
	}
}
