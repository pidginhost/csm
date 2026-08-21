package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/store"
)

func writeApacheConf(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func assembledText(lines []apacheConfigLine) []string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		out = append(out, strings.TrimSpace(l.Text))
	}
	return out
}

func linesFrom(file, text string) []apacheConfigLine {
	var out []apacheConfigLine
	for _, l := range strings.Split(text, "\n") {
		out = append(out, apacheConfigLine{File: file, Text: l})
	}
	return out
}

func joined(got []string) string { return strings.Join(got, "|") }

// --- assembleApacheConfig --------------------------------------------

func TestAssembleApacheConfigSplicesIncludeAtDirectivePosition(t *testing.T) {
	root := t.TempDir()
	main := filepath.Join(root, "apache2.conf")
	writeApacheConf(t, main, "ServerTokens Full\nIncludeOptional conf-enabled/*.conf\nTraceEnable On\n")
	writeApacheConf(t, filepath.Join(root, "conf-enabled", "harden.conf"), "ServerTokens Prod\n")

	got := assembledText(assembleApacheConfig(main))
	want := "ServerTokens Full|ServerTokens Prod|TraceEnable On"
	if joined(got) != want {
		t.Errorf("assembled order = %q, want %q", joined(got), want)
	}
}

func TestAssembleApacheConfigAttributesLinesToSourceFile(t *testing.T) {
	root := t.TempDir()
	main := filepath.Join(root, "apache2.conf")
	snippet := filepath.Join(root, "conf-enabled", "harden.conf")
	writeApacheConf(t, main, "IncludeOptional conf-enabled/*.conf\n")
	writeApacheConf(t, snippet, "FileETag None\n")

	for _, l := range assembleApacheConfig(main) {
		if strings.Contains(l.Text, "FileETag") {
			if l.File != snippet {
				t.Errorf("FileETag attributed to %q, want %q", l.File, snippet)
			}
			return
		}
	}
	t.Fatal("FileETag line missing from assembled config")
}

func TestAssembleApacheConfigResolvesIncludesAgainstServerRoot(t *testing.T) {
	root := t.TempDir()
	serverRoot := filepath.Join(root, "srv")
	main := filepath.Join(root, "httpd.conf")
	writeApacheConf(t, main, "ServerRoot \""+serverRoot+"\"\nInclude conf.d/*.conf\n")
	writeApacheConf(t, filepath.Join(serverRoot, "conf.d", "extra.conf"), "FileETag None\n")

	got := joined(assembledText(assembleApacheConfig(main)))
	if !strings.Contains(got, "FileETag None") {
		t.Errorf("include not resolved against ServerRoot: %q", got)
	}
}

func TestAssembleApacheConfigDefaultsServerRootToConfigDir(t *testing.T) {
	root := t.TempDir()
	main := filepath.Join(root, "apache2.conf")
	writeApacheConf(t, main, "IncludeOptional conf-enabled/*.conf\n")
	writeApacheConf(t, filepath.Join(root, "conf-enabled", "harden.conf"), "TraceEnable Off\n")

	got := joined(assembledText(assembleApacheConfig(main)))
	if !strings.Contains(got, "TraceEnable Off") {
		t.Errorf("include not resolved against config dir: %q", got)
	}
}

func TestAssembleApacheConfigIncludesEveryGlobMatchInSortedOrder(t *testing.T) {
	root := t.TempDir()
	main := filepath.Join(root, "apache2.conf")
	writeApacheConf(t, main, "IncludeOptional conf-enabled/*.conf\n")
	writeApacheConf(t, filepath.Join(root, "conf-enabled", "z-last.conf"), "ServerTokens Full\n")
	writeApacheConf(t, filepath.Join(root, "conf-enabled", "a-first.conf"), "ServerTokens Prod\n")

	want := "ServerTokens Prod|ServerTokens Full"
	if got := joined(assembledText(assembleApacheConfig(main))); got != want {
		t.Errorf("glob order = %q, want %q", got, want)
	}
}

func TestAssembleApacheConfigReadsDirectoryInclude(t *testing.T) {
	root := t.TempDir()
	main := filepath.Join(root, "apache2.conf")
	writeApacheConf(t, main, "Include conf.d\n")
	writeApacheConf(t, filepath.Join(root, "conf.d", "extra.conf"), "ServerSignature Off\n")

	got := joined(assembledText(assembleApacheConfig(main)))
	if !strings.Contains(got, "ServerSignature Off") {
		t.Errorf("directory include not expanded: %q", got)
	}
}

func TestAssembleApacheConfigBreaksIncludeCycle(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "a.conf")
	b := filepath.Join(root, "b.conf")
	writeApacheConf(t, a, "MarkerA\nInclude b.conf\n")
	writeApacheConf(t, b, "MarkerB\nInclude a.conf\n")

	got := joined(assembledText(assembleApacheConfig(a)))
	if strings.Count(got, "MarkerA") != 1 || strings.Count(got, "MarkerB") != 1 {
		t.Errorf("cycle not broken cleanly: %q", got)
	}
}

func TestAssembleApacheConfigIgnoresCommentedInclude(t *testing.T) {
	root := t.TempDir()
	main := filepath.Join(root, "apache2.conf")
	writeApacheConf(t, main, "#IncludeOptional conf-enabled/*.conf\n")
	writeApacheConf(t, filepath.Join(root, "conf-enabled", "harden.conf"), "ServerTokens Prod\n")

	if got := joined(assembledText(assembleApacheConfig(main))); strings.Contains(got, "ServerTokens Prod") {
		t.Errorf("commented include was followed: %q", got)
	}
}

func TestAssembleApacheConfigToleratesMissingInclude(t *testing.T) {
	root := t.TempDir()
	main := filepath.Join(root, "apache2.conf")
	writeApacheConf(t, main, "Include missing/*.conf\nServerTokens Prod\n")

	want := "ServerTokens Prod"
	if got := joined(assembledText(assembleApacheConfig(main))); got != want {
		t.Errorf("missing include changed output: %q, want %q", got, want)
	}
}

// --- apacheIndexesScopes ---------------------------------------------

func TestApacheIndexesScopesReportsDirectoryScope(t *testing.T) {
	got := apacheIndexesScopes(linesFrom("apache2.conf", "<Directory /var/www/>\n\tOptions Indexes FollowSymLinks\n</Directory>\n"))
	if len(got) != 1 || got[0] != "Directory /var/www/" {
		t.Errorf("scopes = %v, want [Directory /var/www/]", got)
	}
}

func TestApacheIndexesScopesIgnoresDisabledDirectory(t *testing.T) {
	got := apacheIndexesScopes(linesFrom("apache2.conf", "<Directory /var/www/>\n\tOptions -Indexes +FollowSymLinks\n</Directory>\n"))
	if len(got) != 0 {
		t.Errorf("scopes = %v, want none", got)
	}
}

func TestApacheIndexesScopesLastDirectiveInScopeWins(t *testing.T) {
	got := apacheIndexesScopes(linesFrom("apache2.conf", "<Directory /srv/>\n\tOptions Indexes\n\tOptions -Indexes\n</Directory>\n"))
	if len(got) != 0 {
		t.Errorf("scopes = %v, want none (last directive disables)", got)
	}
}

func TestApacheIndexesScopesTreatsOptionsAllAsIndexing(t *testing.T) {
	got := apacheIndexesScopes(linesFrom("apache2.conf", "Options All\n"))
	if len(got) != 1 || got[0] != "server config" {
		t.Errorf("scopes = %v, want [server config]", got)
	}
}

func TestApacheIndexesScopesTreatsConditionalBlockAsServerScope(t *testing.T) {
	got := apacheIndexesScopes(linesFrom("apache2.conf", "<IfModule mod_autoindex.c>\n\tOptions Indexes\n</IfModule>\n"))
	if len(got) != 1 || got[0] != "server config" {
		t.Errorf("scopes = %v, want [server config]", got)
	}
}

func TestApacheIndexesScopesServerScopeDoesNotClearDirectoryScope(t *testing.T) {
	// The reported case: a hardening snippet sets server-scope Options
	// -Indexes, but <Directory /var/www/> still grants Indexes and wins
	// for that tree.
	got := apacheIndexesScopes(linesFrom("apache2.conf", "<Directory /var/www/>\n\tOptions Indexes FollowSymLinks\n</Directory>\nOptions -Indexes\n"))
	if len(got) != 1 || got[0] != "Directory /var/www/" {
		t.Errorf("scopes = %v, want [Directory /var/www/]", got)
	}
}

func TestApacheIndexesScopesIgnoresCommentedOptions(t *testing.T) {
	got := apacheIndexesScopes(linesFrom("apache2.conf", "# Options Indexes\n"))
	if len(got) != 0 {
		t.Errorf("scopes = %v, want none", got)
	}
}

// --- auditApacheDirectives -------------------------------------------

func auditByName(results []store.AuditResult, name string) (store.AuditResult, bool) {
	for _, r := range results {
		if r.Name == name {
			return r, true
		}
	}
	return store.AuditResult{}, false
}

func TestAuditApacheDirectivesHonorsIncludedSnippet(t *testing.T) {
	// Reported case: hardening directives live in conf-enabled/ so the
	// distro's apache2.conf stays untouched.
	root := t.TempDir()
	main := filepath.Join(root, "apache2.conf")
	writeApacheConf(t, main, "ServerName localhost\nIncludeOptional conf-enabled/*.conf\n")
	writeApacheConf(t, filepath.Join(root, "conf-enabled", "harden.conf"),
		"ServerTokens Prod\nServerSignature Off\nTraceEnable Off\nFileETag None\n")

	results := auditApacheDirectives(main)
	for _, name := range []string{"web_server_tokens", "web_server_signature", "web_trace_enable", "web_file_etag"} {
		r, ok := auditByName(results, name)
		if !ok {
			t.Fatalf("%s missing from results", name)
		}
		if r.Status != "pass" {
			t.Errorf("%s = %s (%s), want pass", name, r.Status, r.Message)
		}
	}
}

func TestAuditApacheDirectivesNamesSnippetThatSetTheValue(t *testing.T) {
	root := t.TempDir()
	main := filepath.Join(root, "apache2.conf")
	snippet := filepath.Join(root, "conf-enabled", "harden.conf")
	writeApacheConf(t, main, "IncludeOptional conf-enabled/*.conf\n")
	writeApacheConf(t, snippet, "ServerTokens Full\n")

	r, ok := auditByName(auditApacheDirectives(main), "web_server_tokens")
	if !ok {
		t.Fatal("web_server_tokens missing")
	}
	if !strings.Contains(r.Fix, snippet) {
		t.Errorf("fix = %q, want it to name %q", r.Fix, snippet)
	}
}

func TestAuditApacheDirectivesLastServerScopeValueWins(t *testing.T) {
	root := t.TempDir()
	main := filepath.Join(root, "apache2.conf")
	writeApacheConf(t, main, "ServerTokens Full\nIncludeOptional conf-enabled/*.conf\n")
	writeApacheConf(t, filepath.Join(root, "conf-enabled", "harden.conf"), "ServerTokens Prod\n")

	r, _ := auditByName(auditApacheDirectives(main), "web_server_tokens")
	if r.Status != "pass" {
		t.Errorf("web_server_tokens = %s (%s), want pass", r.Status, r.Message)
	}
}

func TestAuditApacheDirectivesIgnoresVirtualHostScopedValue(t *testing.T) {
	root := t.TempDir()
	main := filepath.Join(root, "apache2.conf")
	writeApacheConf(t, main, "ServerSignature Off\n<VirtualHost *:80>\n\tServerSignature On\n</VirtualHost>\n")

	r, _ := auditByName(auditApacheDirectives(main), "web_server_signature")
	if r.Status != "pass" {
		t.Errorf("web_server_signature = %s (%s), want pass -- vhost scope is not the global value", r.Status, r.Message)
	}
}

func TestAuditApacheDirectivesReportsDirectoryScopedIndexing(t *testing.T) {
	root := t.TempDir()
	main := filepath.Join(root, "apache2.conf")
	writeApacheConf(t, main, "<Directory /var/www/>\n\tOptions Indexes FollowSymLinks\n</Directory>\nIncludeOptional conf-enabled/*.conf\n")
	writeApacheConf(t, filepath.Join(root, "conf-enabled", "harden.conf"), "Options -Indexes\n")

	r, ok := auditByName(auditApacheDirectives(main), "web_directory_listing")
	if !ok {
		t.Fatal("web_directory_listing missing")
	}
	if r.Status != "warn" {
		t.Fatalf("web_directory_listing = %s (%s), want warn", r.Status, r.Message)
	}
	if !strings.Contains(r.Message, "Directory /var/www/") {
		t.Errorf("message = %q, want it to name the scope", r.Message)
	}
}

func TestAuditApacheDirectivesPassesWhenNoScopeGrantsIndexing(t *testing.T) {
	root := t.TempDir()
	main := filepath.Join(root, "apache2.conf")
	writeApacheConf(t, main, "<Directory /var/www/>\n\tOptions -Indexes +FollowSymLinks\n</Directory>\n")

	r, _ := auditByName(auditApacheDirectives(main), "web_directory_listing")
	if r.Status != "pass" {
		t.Errorf("web_directory_listing = %s (%s), want pass", r.Status, r.Message)
	}
}
