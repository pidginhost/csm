package alert

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuditSinkRecovery(t *testing.T) {
	resetAuditSinksForTest()
	t.Cleanup(resetAuditSinksForTest)
	dir := t.TempDir()
	path := filepath.Join(dir, "events")
	cfg := cfgWithJSONLAudit(t, path)
	cfg.Alerts.AuditLog.Syslog.Enabled = true
	cfg.Alerts.AuditLog.Syslog.Network = "unixgram"
	cfg.Alerts.AuditLog.Syslog.Address = filepath.Join(dir, "s")
	emitAudit(cfg, []Finding{{Check: "before", Message: "before", Timestamp: time.Now()}})
	listener, err := net.ListenPacket("unixgram", cfg.Alerts.AuditLog.Syslog.Address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := listener.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	time.Sleep(time.Second)
	emitAudit(cfg, []Finding{{Check: "after", Message: "after", Timestamp: time.Now()}})
	if deadlineErr := listener.SetReadDeadline(time.Now().Add(time.Second)); deadlineErr != nil {
		t.Fatal(deadlineErr)
	}
	buf := make([]byte, 4096)
	n, _, err := listener.ReadFrom(buf)
	if err != nil {
		t.Fatalf("recovered syslog sink received no finding: %v", err)
	}
	if !strings.Contains(string(buf[:n]), `"check":"after"`) {
		t.Fatalf("wrong recovered event: %s", buf[:n])
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), "\n") != 2 {
		t.Fatalf("healthy sink duplicated or lost findings: %s", data)
	}
}
