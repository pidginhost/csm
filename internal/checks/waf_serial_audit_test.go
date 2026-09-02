package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// ModSecurity's serial audit format spreads one transaction over lettered
// sections: the client address sits on the A-section header while the
// "Access denied with code 403" message lives in H. The per-line scan found
// the denial on a line with no address and dropped it, so a serial audit
// log never produced a waf_attack_blocked finding, and 200 tail lines held
// too few transactions to reach the threshold anyway.
func serialTransaction(id, clientIP string, status int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "--%s-A--\n", id)
	fmt.Fprintf(&b, "[03/Sep/2026:10:00:00 +0000] %s %s 54321 198.51.100.1 443\n", id, clientIP)
	fmt.Fprintf(&b, "--%s-B--\n", id)
	b.WriteString("GET /wp-login.php?a=../../etc/passwd HTTP/1.1\nHost: example.com\n\n")
	fmt.Fprintf(&b, "--%s-F--\n", id)
	fmt.Fprintf(&b, "HTTP/1.1 %d\nContent-Type: text/html\n\n", status)
	fmt.Fprintf(&b, "--%s-H--\n", id)
	if status == 403 {
		b.WriteString("Message: Access denied with code 403 (phase 2). Pattern match \"passwd\" [id \"930120\"]\n")
	}
	b.WriteString("Apache-Handler: application/x-httpd-php\nStopwatch: 1 2 (- - -)\n\n")
	fmt.Fprintf(&b, "--%s-Z--\n\n", id)
	return b.String()
}

func setupSerialAuditLog(t *testing.T, content string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "modsec_audit.log")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	old := modsecAuditLogPaths
	modsecAuditLogPaths = func() []string { return []string{"/var/log/httpd/modsec_audit.log"} }
	t.Cleanup(func() { modsecAuditLogPaths = old })
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if name == "/var/log/httpd/modsec_audit.log" {
				return os.Open(path)
			}
			return nil, os.ErrNotExist
		},
	})
}

func TestCheckModSecAuditLogAttributesSerialFormatDenials(t *testing.T) {
	var log strings.Builder
	for i := 0; i < 25; i++ {
		log.WriteString(serialTransaction(fmt.Sprintf("a1b2c3%02d", i), "203.0.113.9", 403))
	}
	log.WriteString(serialTransaction("b2c3d4e5", "198.51.100.7", 200))
	setupSerialAuditLog(t, log.String())

	findings := CheckModSecAuditLog(context.Background(), &config.Config{}, nil)
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want one high-volume attacker", findings)
	}
	if findings[0].SourceIP != "203.0.113.9" {
		t.Fatalf("SourceIP = %q, want the A-section client", findings[0].SourceIP)
	}
	if !strings.Contains(findings[0].Message, "25 blocked") {
		t.Fatalf("message should count each denied transaction once: %q", findings[0].Message)
	}
}

func TestCheckModSecAuditLogSerialFormatCountsTransactionsNotLines(t *testing.T) {
	// 19 denied transactions, each with two 403-bearing lines (F status and
	// H message): under the threshold only if a transaction counts once.
	var log strings.Builder
	for i := 0; i < 19; i++ {
		log.WriteString(serialTransaction(fmt.Sprintf("c3d4e5%02d", i), "203.0.113.10", 403))
	}
	setupSerialAuditLog(t, log.String())
	if findings := CheckModSecAuditLog(context.Background(), &config.Config{}, nil); len(findings) != 0 {
		t.Fatalf("19 transactions must stay under the threshold of 20, got %+v", findings)
	}
}
