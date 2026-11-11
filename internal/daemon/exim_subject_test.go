package daemon

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestParseEximLogLine_SubjectPrintingEscapes(t *testing.T) {
	resetEmailRateState()
	t.Cleanup(resetEmailRateState)
	for _, tc := range []struct{ name, logged, want string }{
		{
			"escaped controls and quotes",
			`\033[2J\n\"smtp.example.net:587,user@example.com,sample\"\t\177`,
			`\033[2J\n"smtp.example.net:587,user@example.com,sample"\t\177`,
		},
		{
			"literal escapes",
			`\\033\\n smtp.example.net:587,user@example.com,sample \\`,
			`\033\n smtp.example.net:587,user@example.com,sample \`,
		},
		{
			"literal tabs",
			"smtp.example.net:587,user@example.com,sample\tend",
			"smtp.example.net:587,user@example.com,sample\tend",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := `2026-01-01 10:00:00 1abc23-000456-AB <= sender@example.com U=sender P=local S=900 T="` + tc.logged + `" for recipient@example.org`
			findings := parseEximLogLine(line, &config.Config{})
			if len(findings) != 1 || findings[0].Check != "email_credential_leak" || findings[0].Severity != alert.Critical {
				t.Fatalf("findings = %+v, want one Critical credential leak", findings)
			}
			_, subject, ok := strings.Cut(findings[0].Details, "\nSubject: ")
			if !ok || subject != tc.want {
				t.Fatalf("subject in details = %q, %v; want %q, true", subject, ok, tc.want)
			}
			if strings.Count(findings[0].Details, "\n") != 1 {
				t.Fatalf("subject forged a line break in details: %q", findings[0].Details)
			}
		})
	}
}
