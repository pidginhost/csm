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

// mockOSWithMailLog serves content as the mail log at logPath. Open/Stat fall
// through to ErrNotExist for every other path so the reputation check's other
// log sources stay empty and the test isolates the mail-log path.
func mockOSWithMailLog(t *testing.T, logPath, content string) *mockOS {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), "maillog")
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	serve := func(name string) bool { return name == logPath }
	return &mockOS{
		open: func(name string) (*os.File, error) {
			if serve(name) {
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			if serve(name) {
				return os.Stat(tmp)
			}
			return nil, os.ErrNotExist
		},
		readFile: os.ReadFile,
	}
}

const reputationDovecotFail = "Jun 22 11:03:02 host dovecot[1]: imap-login: " +
	"Login aborted: Connection closed (auth failed, 1 attempts in 2 secs) (auth_failed): " +
	"user=<vanzari@example.ro>, method=PLAIN, rip=%s, lip=203.0.113.1, TLS: Connection closed\n"

const reputationDovecotSuccess = "Jun 22 11:02:32 host dovecot[1]: imap-login: " +
	"Logged in: user=<office@example.ro>, method=PLAIN, rip=%s, lip=203.0.113.1, mpid=1, TLS\n"

// A feed-listed IP that is also actively authenticating to a mailbox is a real
// customer on a recycled dynamic IP, not a drive-by attacker. Reputation
// auto-block on passive access must not lock that customer out.
func TestCheckIPReputationSkipsAuthenticatedCustomerIP(t *testing.T) {
	const ip = "198.51.100.7"
	statePath := t.TempDir()
	restore := SetGlobalThreatDBForTest(statePath)
	t.Cleanup(restore)
	GetThreatDB().badIPs[ip] = "permanent-blocklist"

	mailLog := filepath.Join(t.TempDir(), "live-maillog")
	content := fmt.Sprintf(reputationDovecotSuccess, ip) + fmt.Sprintf(reputationDovecotFail, ip)
	withMockOS(t, mockOSWithMailLog(t, mailLog, content))

	cfg := &config.Config{StatePath: statePath}
	cfg.MailLogs.File = mailLog
	findings := CheckIPReputation(context.Background(), cfg, nil)

	for _, f := range findings {
		if f.Check == "ip_reputation" && strings.Contains(f.Message, ip) {
			t.Fatalf("authenticated customer IP %s must not be flagged by ip_reputation, got: %+v", ip, f)
		}
	}
}

// The suppression is specific to authenticated sources: a feed-listed IP that
// only fails auth (no successful login) is still a real threat and must keep
// producing the reputation finding that drives the block.
func TestCheckIPReputationFlagsUnauthenticatedThreatIP(t *testing.T) {
	const ip = "198.51.100.8"
	statePath := t.TempDir()
	restore := SetGlobalThreatDBForTest(statePath)
	t.Cleanup(restore)
	GetThreatDB().badIPs[ip] = "permanent-blocklist"

	mailLog := filepath.Join(t.TempDir(), "live-maillog")
	withMockOS(t, mockOSWithMailLog(t, mailLog, fmt.Sprintf(reputationDovecotFail, ip)))

	cfg := &config.Config{StatePath: statePath}
	cfg.MailLogs.File = mailLog
	findings := CheckIPReputation(context.Background(), cfg, nil)

	var flagged bool
	for _, f := range findings {
		if f.Check == "ip_reputation" && strings.Contains(f.Message, ip) {
			flagged = true
		}
	}
	if !flagged {
		t.Fatalf("unauthenticated threat IP %s must still be flagged by ip_reputation, got: %+v", ip, findings)
	}
}
