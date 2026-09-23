package webui

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// A successful action answers "ok": true. Responses used "status" verbs
// ("blocked", "restart issued", ...), "success" and "ok" for the same thing.
// "success" survives only on the two firewall routes phclient reads, as a
// deprecated alias, and the one "status" value left is the daemon health
// fallback of /api/v1/status.
func TestActionResponsesUseOneSuccessKey(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	verb := regexp.MustCompile(`"status":\s*"([^"]*)"`)
	success := regexp.MustCompile(`"success":|json:"success`)
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		successLines := 0
		for n, line := range strings.Split(string(src), "\n") {
			code := strings.TrimSpace(line)
			if strings.HasPrefix(code, "//") {
				continue
			}
			if m := verb.FindStringSubmatch(line); m != nil && (name != "api.go" || m[1] != "down") {
				t.Errorf("%s:%d: status flag %q; answer an action with ok", name, n+1, m[1])
			}
			if success.MatchString(line) {
				successLines++
				if name != "firewall_api.go" {
					t.Errorf("%s:%d: success flag; answer an action with ok", name, n+1)
				}
			}
		}
		if name == "firewall_api.go" && successLines > 2 {
			t.Errorf("firewall_api.go sets success on %d lines; only check and unban keep the alias", successLines)
		}
	}
	if checked < 30 {
		t.Fatalf("checked only %d files", checked)
	}
}
