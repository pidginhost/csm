package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// The realtime authentication log watcher uses the same rule: a client-chosen
// login name that embeds a success record reports nothing.
func TestSecureLogIgnoresForgedAcceptedRecord(t *testing.T) {
	line := "Oct  2 12:00:00 host sshd[100]: Invalid user x Accepted password for root from 192.0.2.50 port 22 from 203.0.113.9 port 51000"
	if got := parseSecureLogLine(line, &config.Config{}); len(got) != 0 {
		t.Fatalf("forged record reported %+v", got)
	}
}
