package checks

import (
	"context"
	"strings"
	"testing"
)

func TestDatabaseCoverageEscapesExamplePaths(t *testing.T) {
	for _, tt := range []struct {
		name string
		dir  string
		want string
	}{
		{"line_breaks", "site\nquery_failed=999\r\t", `site\nquery_failed=999\r\t`},
		{"terminal_controls", "site\x1b[2J\x7f", `site\x1b[2J\x7f`},
		{"unicode_controls", "site\u202e\u2028", `site\u202e\u2028`},
		{"invalid_utf8", "site\xff", `site\xff`},
		{"literal_backslash", `site\n`, `site\\n`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := "/home/alice/" + tt.dir + "/wp-config.php"
			withDatabaseCoverageInstalls(t, map[string]string{path: "<?php\n"}, nil)
			ctx, _ := withIncompleteCheckCollector(context.Background())
			f := databaseCoverageSummary(t, CheckDatabaseContent(ctx, nil, nil))
			want := "1 of 1 discovered installs could not be fully inspected.\n" +
				"missing_credentials=1 (example: /home/alice/" + tt.want + "/wp-config.php)\n" +
				"Findings without complete database coverage are retained."
			if f.Details != want {
				t.Fatalf("account path changed the diagnostic structure: got %q, want %q", f.Details, want)
			}
		})
	}
}

func TestDatabaseCoverageEscapedExampleKeepsBound(t *testing.T) {
	path := "/home/alice/" + strings.Repeat("\x1b", 100) + "/wp-config.php"
	withDatabaseCoverageInstalls(t, map[string]string{path: "<?php\n"}, nil)
	ctx, _ := withIncompleteCheckCollector(context.Background())
	f := databaseCoverageSummary(t, CheckDatabaseContent(ctx, nil, nil))
	lines := strings.Split(f.Details, "\n")
	if len(lines) != 3 {
		t.Fatalf("want one reason line: %q", f.Details)
	}
	example := strings.TrimSuffix(strings.TrimPrefix(lines[1], "missing_credentials=1 (example: "), ")")
	if len(example) > 203 || !strings.HasSuffix(example, "...") {
		t.Fatalf("escaped example exceeds the existing truncation bound: %q", example)
	}
	if strings.ContainsRune(f.String(), '\x1b') {
		t.Fatalf("account path reached terminal output without escaping: %q", f.String())
	}
}
