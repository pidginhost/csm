package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// Long escaped client fields keep the legacy findings and the observation of
// the scheduled cPanel scans.
func TestCpanelScanKeepsEscapedFieldRecords(t *testing.T) {
	forceCPanelPlatform(t)
	const attempts = 12
	line := `203.0.113.9 - - [11/09/2026:12:00:00 -0000] "POST /execute/login/?session=2096 HTTP/1.1" 401 0 "-" "` +
		strings.Repeat(`\\`, 20000) + `" "-" "-" 2096` + "\n"
	path := filepath.Join(t.TempDir(), "access_log")
	if err := os.WriteFile(path, []byte(strings.Repeat(line, attempts)), 0o600); err != nil {
		t.Fatal(err)
	}
	withMockOS(t, &mockOS{open: func(name string) (*os.File, error) {
		if name == "/usr/local/cpanel/logs/access_log" {
			return os.Open(path)
		}
		return nil, os.ErrNotExist
	}})
	for _, tc := range []struct {
		check   string
		message string
		run     func(context.Context, *config.Config, *state.Store) []alert.Finding
	}{
		{"api_auth_failure", "cPanel API auth failures from %s: %d attempts", CheckAPIAuthFailures},
		{"webmail_bruteforce", "Webmail brute force from %s: %d attempts", CheckWebmailLogins},
	} {
		t.Run(tc.check, func(t *testing.T) {
			findings := tc.run(context.Background(), &config.Config{}, nil)
			if len(findings) != 1 || findings[0].Check != tc.check || findings[0].SourceIP != "203.0.113.9" ||
				findings[0].Severity != alert.High || findings[0].Message != fmt.Sprintf(tc.message, "203.0.113.9", attempts) {
				t.Fatalf("escaped client fields changed the legacy finding: %+v", findings)
			}
			wantScanObservation(t, findings[0], ProducerCpanelScan,
				syslogTestRef(t, path, int64((attempts-1)*len(line)), line), time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC))
		})
	}
}

// A quoted field is scanned once: an escape never makes the parser search the
// rest of the field again. One long field must cost about as much as the same
// bytes in short fields; a rescanned suffix costs many times more. Both runs
// last about as long, so a busy runner slows them alike.
func TestPatternQuotedFieldEscapesAreLinear(t *testing.T) {
	const short, pieces = 2500, 64
	cost := func(escapes, fields int) time.Duration {
		field := `"` + strings.Repeat(`\\`, escapes) + `" tail`
		best := time.Duration(1<<63 - 1)
		for range 5 {
			start := time.Now()
			for range fields {
				raw, rest, ok := patternQuotedField(field)
				if !ok || len(raw) != 2*escapes || rest != " tail" {
					t.Fatalf("field of %d escapes parsed as %d bytes, rest %q, ok %v", escapes, len(raw), rest, ok)
				}
			}
			best = min(best, time.Since(start))
		}
		return best
	}
	split, whole := cost(short, pieces), cost(short*pieces, 1)
	if whole > 8*split+time.Millisecond {
		t.Fatalf("one field of %d escapes cost %v against %v for the same bytes in %d fields: the scan is not linear",
			short*pieces, whole, split, pieces)
	}
}
