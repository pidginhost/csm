package webui

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAuditLog_NeverProducesMultipleLinesPerEntry is regression armor
// for the JSONL injection concern: every call to auditLog must write
// exactly one line to the audit file, even when the Details payload
// contains attacker-controlled newlines, JSON terminators, or a fake
// follow-on entry. If json.Marshal is ever replaced with raw string
// formatting, this test trips.
func TestAuditLog_NeverProducesMultipleLinesPerEntry(t *testing.T) {
	hostile := []string{
		"benign\nfollows",
		"split\r\nmid",
		`broken"}` + "\n" + `{"action":"forged_block","target":"203.0.113.1"`,
		"backslash\\n still one line",
		strings.Repeat("X", 8192) + "\n" + "tail",
	}
	for _, details := range hostile {
		t.Run(strings.ReplaceAll(details[:min(len(details), 30)], "\n", `\n`), func(t *testing.T) {
			s := newTestServer(t, "tok")
			r := httptest.NewRequest("POST", "/api/v1/test", nil)
			r.RemoteAddr = "10.0.0.1:1234"

			s.auditLog(r, "test_action", "203.0.113.5", details)

			entries := readUIAuditLog(s.cfg.StatePath, 10)
			if len(entries) != 1 {
				t.Fatalf("audit log produced %d entries for one auditLog call (injection), want 1: %+v", len(entries), entries)
			}
			if entries[0].Details != details {
				t.Errorf("Details round-trip mismatch: got %q, want %q", entries[0].Details, details)
			}
			if entries[0].Action != "test_action" {
				t.Errorf("Action got %q, want test_action", entries[0].Action)
			}
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
