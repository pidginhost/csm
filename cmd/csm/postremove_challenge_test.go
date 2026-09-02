package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func postremoveChallengeFunction(t *testing.T, root string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "build", "packaging", "scripts", "postremove.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(body)
	start := strings.Index(script, "remove_challenge_snippets() {")
	if start < 0 {
		t.Fatal("could not find remove_challenge_snippets in postremove.sh")
	}
	endMarker := "\n}\n\nsystemctl daemon-reload"
	end := strings.Index(script[start:], endMarker)
	if end < 0 {
		t.Fatal("could not isolate remove_challenge_snippets from postremove.sh")
	}
	fn := script[start : start+end+len("\n}")]
	for _, path := range []string{
		"/etc/apache2",
		"/etc/httpd",
		"/usr/local/lsws",
		"/etc/nginx",
		"/var/cache/csm",
	} {
		fn = strings.ReplaceAll(fn, path, filepath.Join(root, strings.TrimPrefix(path, "/")))
	}
	return fn
}

func runPostremoveChallengeFunction(t *testing.T, fn, suffix string) ([]byte, error) {
	t.Helper()
	cmd := exec.Command("bash", "-c", fn+"\n"+suffix) // #nosec G204 -- fn is extracted from the checked-in package script and paths are test temp dirs.
	return cmd.CombinedOutput()
}

func TestPostremoveKeepsMapsWhenApacheSnippetCannotBeRemoved(t *testing.T) {
	root := t.TempDir()
	snippet := filepath.Join(root, "etc/apache2/conf.d/csm_challenge.conf")
	if err := os.MkdirAll(filepath.Dir(snippet), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(snippet, []byte("RewriteMap csm_challenge txt:/var/cache/csm/challenge_ips.txt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fn := postremoveChallengeFunction(t, root)
	output, err := runPostremoveChallengeFunction(t, fn, "rm() { return 1; }\nremove_challenge_snippets")
	if err == nil {
		t.Fatalf("snippet removal failure was reported as success; output: %s", output)
	}
	if _, statErr := os.Stat(snippet); statErr != nil {
		t.Fatalf("fixture snippet disappeared despite mocked rm failure: %v", statErr)
	}
}

func TestPostremoveNginxGuardKeepsSnippetForExternalReferences(t *testing.T) {
	root := t.TempDir()
	nginxDir := filepath.Join(root, "etc/nginx")
	snippet := filepath.Join(nginxDir, "conf.d/csm-challenge.conf")
	server := filepath.Join(nginxDir, "sites-enabled/site.conf")
	serverTarget := filepath.Join(root, "shared/site.conf")
	for _, path := range []string{snippet, server, serverTarget} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(snippet, []byte("map $remote_addr $csm_challenged { default 0; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(serverTarget, []byte("if ($csm_challenged) { return 302 /challenge; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(serverTarget, server); err != nil {
		t.Fatal(err)
	}

	output, err := runPostremoveChallengeFunction(t, postremoveChallengeFunction(t, root), "remove_challenge_snippets")
	if err == nil {
		t.Fatalf("nginx reference guard reported success; output: %s", output)
	}
	if _, statErr := os.Stat(snippet); statErr != nil {
		t.Fatalf("nginx map snippet removed while a server block still uses it: %v", statErr)
	}
	if !strings.Contains(string(output), "$csm_challenged") {
		t.Fatalf("warning lost the literal nginx variable: %q", output)
	}
}

func TestPostremoveNginxGuardChecksSameNamedExternalConfig(t *testing.T) {
	root := t.TempDir()
	nginxDir := filepath.Join(root, "etc/nginx")
	snippet := filepath.Join(nginxDir, "conf.d/csm-challenge.conf")
	server := filepath.Join(nginxDir, "sites-enabled/csm-challenge.conf")
	for _, path := range []string{snippet, server} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(snippet, []byte("map $remote_addr $csm_challenged { default 0; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(server, []byte("if ($csm_challenged) { return 302 /challenge; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	output, err := runPostremoveChallengeFunction(t, postremoveChallengeFunction(t, root), "remove_challenge_snippets")
	if err == nil {
		t.Fatalf("same-named external nginx reference was ignored; output: %s", output)
	}
	if _, statErr := os.Stat(snippet); statErr != nil {
		t.Fatalf("nginx map snippet removed while same-named server config uses it: %v", statErr)
	}
}

func TestPostremoveNginxSnippetRemovedWithoutExternalReference(t *testing.T) {
	root := t.TempDir()
	snippet := filepath.Join(root, "etc/nginx/conf.d/csm-challenge.conf")
	if err := os.MkdirAll(filepath.Dir(snippet), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(snippet, []byte("map $remote_addr $csm_challenged { default 0; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	output, err := runPostremoveChallengeFunction(t, postremoveChallengeFunction(t, root), "remove_challenge_snippets")
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("remove_challenge_snippets exit %d: %s", exitErr.ExitCode(), output)
		}
		t.Fatal(err)
	}
	if _, statErr := os.Stat(snippet); !os.IsNotExist(statErr) {
		t.Fatalf("unreferenced nginx snippet still exists: %v", statErr)
	}
}

func TestPostremoveRemovesDanglingNginxSnippetLink(t *testing.T) {
	root := t.TempDir()
	snippet := filepath.Join(root, "etc/nginx/conf.d/csm-challenge.conf")
	if err := os.MkdirAll(filepath.Dir(snippet), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "missing-snippet"), snippet); err != nil {
		t.Fatal(err)
	}

	output, err := runPostremoveChallengeFunction(t, postremoveChallengeFunction(t, root), "remove_challenge_snippets")
	if err != nil {
		t.Fatalf("remove dangling nginx snippet: %v: %s", err, output)
	}
	if _, statErr := os.Lstat(snippet); !os.IsNotExist(statErr) {
		t.Fatalf("dangling nginx snippet still exists: %v", statErr)
	}
}

func TestPostremoveNginxGuardKeepsSnippetWhenInspectionFails(t *testing.T) {
	root := t.TempDir()
	snippet := filepath.Join(root, "etc/nginx/conf.d/csm-challenge.conf")
	if err := os.MkdirAll(filepath.Dir(snippet), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(snippet, []byte("map $remote_addr $csm_challenged { default 0; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	output, err := runPostremoveChallengeFunction(t, postremoveChallengeFunction(t, root), "find() { return 2; }\nremove_challenge_snippets")
	if err == nil {
		t.Fatalf("nginx inspection failure was reported as success; output: %s", output)
	}
	if _, statErr := os.Stat(snippet); statErr != nil {
		t.Fatalf("nginx map snippet removed after inspection failed: %v", statErr)
	}
}
