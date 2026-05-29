package webui

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"
)

var (
	reRegisteredAPIRoute = regexp.MustCompile(`mux\.Handle\("(/api/v1/[^"]+)"`)
	reOpenAPIPathKey     = regexp.MustCompile(`^\s*"(/api/v1/[^"]+)":`)
)

// registeredAPIRoutes scans the non-test Go sources in this package for
// mux.Handle("/api/v1/...") registrations.
func registeredAPIRoutes(t *testing.T) map[string]struct{} {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	routes := map[string]struct{}{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".go" || regexpHasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(name) // #nosec G304 -- package-local source file
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, m := range reRegisteredAPIRoute.FindAllStringSubmatch(string(data), -1) {
			routes[m[1]] = struct{}{}
		}
	}
	return routes
}

func regexpHasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

// documentedAPIPaths parses the path keys out of the committed OpenAPI spec.
func documentedAPIPaths(t *testing.T) map[string]struct{} {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "src", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	paths := map[string]struct{}{}
	for _, line := range splitLines(string(data)) {
		if m := reOpenAPIPathKey.FindStringSubmatch(line); m != nil {
			paths[m[1]] = struct{}{}
		}
	}
	return paths
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

// TestOpenAPISpecCoversAllRoutes is the drift guard: every registered
// /api/v1/* route must appear in docs/src/openapi.yaml, and every
// documented path must map to a real registered route. Adding a route
// without documenting it (or vice versa) fails here.
func TestOpenAPISpecCoversAllRoutes(t *testing.T) {
	registered := registeredAPIRoutes(t)
	documented := documentedAPIPaths(t)

	if len(registered) == 0 {
		t.Fatal("found no registered /api/v1 routes -- scanner regex likely broke")
	}

	var missing []string
	for r := range registered {
		if _, ok := documented[r]; !ok {
			missing = append(missing, r)
		}
	}
	var extra []string
	for d := range documented {
		if _, ok := registered[d]; !ok {
			extra = append(extra, d)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Errorf("routes registered but missing from docs/src/openapi.yaml: %v", missing)
	}
	if len(extra) > 0 {
		t.Errorf("paths documented in openapi.yaml with no registered route: %v", extra)
	}
}
