package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

func TestModSecAuditErrorSourceKeepsDenialsWithQuotedData(t *testing.T) {
	for _, source := range []string{"modsec_error_log", "platform_error_log"} {
		t.Run(source, func(t *testing.T) {
			line := `[client [2001:db8::50]:5555] ModSecurity: Access denied with code 403 [data "probe] \"text"]`
			path := auditReaderFile(t, strings.Repeat(line+"\n", 25))
			oldPaths := modsecAuditLogPaths
			modsecAuditLogPaths = func() []string { return []string{path} }
			t.Cleanup(func() { modsecAuditLogPaths = oldPaths })
			cfg := &config.Config{}
			if source == "modsec_error_log" {
				cfg.ModSecErrorLog = path
			} else {
				platform.ResetForTest()
				t.Cleanup(platform.ResetForTest)
				platform.SetOverrides(platform.Overrides{ErrorLogPaths: []string{path}})
			}
			// Both literal and escaped quotes can occur in logged request data.
			for _, data := range []string{line, strings.ReplaceAll(line, `\"`, `"`)} {
				writeAuditReaderFile(t, path, strings.Repeat(data+"\n", 25))
				findings := CheckModSecAuditLog(context.Background(), cfg, nil)
				if len(findings) != 1 || findings[0].SourceIP != "2001:db8::50" || !strings.Contains(findings[0].Message, "25 blocked") {
					t.Fatalf("denials = %+v, want 25 denials for the real client", findings)
				}
			}
		})
	}
}

func TestModSecAuditSourceCannotSwitchFormatFromContent(t *testing.T) {
	errorLine := `[client 198.51.100.7] ModSecurity: Access denied with code 403`
	index := modsecIndexLine("example.test", "203.0.113.50", "GET / HTTP/1.1", "probe", 403)
	path := auditReaderFile(t, strings.Repeat(index+"\n"+errorLine+"\n", 25))
	oldPaths := modsecAuditLogPaths
	modsecAuditLogPaths = func() []string { return []string{path} }
	t.Cleanup(func() { modsecAuditLogPaths = oldPaths })
	// Reusing the same file also proves that changing the source selection
	// discards counts and framing obtained under the old interpretation.
	for _, errorSource := range []bool{false, true, false} {
		cfg := &config.Config{}
		want := "203.0.113.50"
		if errorSource {
			cfg.ModSecErrorLog = path
			want = "198.51.100.7"
		}
		findings := CheckModSecAuditLog(context.Background(), cfg, nil)
		if len(findings) != 1 || findings[0].SourceIP != want || !strings.Contains(findings[0].Message, "25 blocked") {
			t.Fatalf("error source %v: findings = %+v, want only %s", errorSource, findings, want)
		}
	}
}
