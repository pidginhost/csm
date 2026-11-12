package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/integration/webserver"
	"github.com/pidginhost/csm/internal/platform"
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

func TestPostremovePreservesDisabledApacheSiteInclude(t *testing.T) {
	for _, tc := range []struct{ name, failure string }{
		{"disabled", ""}, {"rename failure", "mv() { return 1; }"}, {"unmanaged", "unmanaged"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			failure := tc.failure
			root := t.TempDir()
			cache := filepath.Join(root, "var/cache/csm")
			if err := os.MkdirAll(cache, 0o755); err != nil {
				t.Fatal(err)
			}
			site := filepath.Join(cache, "apache-challenge-site.conf")
			body := "# csm-managed-version: 9\nRewriteEngine On\n"
			if failure == "unmanaged" {
				body = "# operator configuration\nRewriteEngine On\n"
			}
			for _, name := range []string{"apache-challenge-site.conf", "challenge_ips.txt", "challenge_ips.nginx.map"} {
				if err := os.WriteFile(filepath.Join(cache, name), []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			suffix := failure + "\nremove_challenge_snippets"
			if failure == "unmanaged" {
				suffix = "remove_challenge_snippets"
			}
			output, err := runPostremoveChallengeFunction(t, postremoveChallengeFunction(t, root), suffix)
			if (err != nil) != (failure != "") {
				t.Fatalf("cleanup = %v: %s", err, output)
			}
			got, err := os.ReadFile(site)
			if err != nil {
				t.Fatal(err)
			}
			if failure == "" {
				installer, err := webserver.New(platform.Info{OS: platform.OSUbuntu, WebServer: platform.WSApache}, nil)
				if err != nil {
					t.Fatal(err)
				}
				installer.ReadAt = func(string) ([]byte, error) { return got, nil }
				applicable, active, _, err := installer.SiteCoverage()
				if !applicable || active || err != nil {
					t.Fatalf("disabled coverage = %v, %v, %v", applicable, active, err)
				}
				for _, line := range strings.Split(string(got), "\n") {
					if line != "" && !strings.HasPrefix(line, "#") {
						t.Fatalf("active directive left: %q", line)
					}
				}
			} else if string(got) != body {
				t.Fatal("failed cleanup changed the original snippet")
			}
			for _, name := range []string{"challenge_ips.txt", "challenge_ips.nginx.map"} {
				_, err := os.Stat(filepath.Join(cache, name))
				if failure == "" && !os.IsNotExist(err) {
					t.Fatalf("map %s not removed: %v", name, err)
				}
				if failure != "" && err != nil {
					t.Fatalf("map %s removed after failure: %v", name, err)
				}
			}
		})
	}
}

// cPanel keeps including the per-site file once it has existed, and Apache
// refuses a RewriteMap whose map is gone. Package removal must leave the
// inert placeholder there before it deletes the maps.
func TestPostremoveDisablesTheCPanelSiteSnippet(t *testing.T) {
	root := t.TempDir()
	site := filepath.Join(root, "etc/apache2/conf.d/userdata/csm-challenge.conf")
	maps := filepath.Join(root, "var/cache/csm/challenge_ips.txt")
	for _, p := range []string{site, maps} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(site, []byte("# csm-managed-version: 9\nRewriteEngine On\nRewriteMap csm_chal \"txt:/var/cache/csm/challenge_ips.txt\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(maps, []byte("# map\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	output, err := runPostremoveChallengeFunction(t, postremoveChallengeFunction(t, root), "remove_challenge_snippets")
	if err != nil {
		t.Fatalf("removal failed: %v: %s", err, output)
	}
	body, err := os.ReadFile(site)
	if err != nil {
		t.Fatalf("cPanel site file removed; its required include would fail: %v", err)
	}
	if strings.Contains(string(body), "RewriteMap") || !strings.HasPrefix(string(body), "# csm-managed-version: ") {
		t.Fatalf("cPanel site file still active after removal: %q", body)
	}
	if _, err := os.Stat(maps); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("map kept after its references were disabled: %v", err)
	}
}
