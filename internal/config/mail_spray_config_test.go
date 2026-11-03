package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMailSprayDropInPresence(t *testing.T) {
	for _, tc := range []struct {
		name, main, fragment string
		breadth, networks    int
	}{
		{"omitted", "", "{}", 2, 3},
		{"zero overrides nonzero", "thresholds: {mail_spray_breadth_mailboxes: 4, mail_spray_missing_networks: 5}", "thresholds: {mail_spray_breadth_mailboxes: 0, mail_spray_missing_networks: 0}", 0, 0},
		{"null resets zero", "thresholds: {mail_spray_breadth_mailboxes: 0, mail_spray_missing_networks: 0}", "thresholds: {mail_spray_breadth_mailboxes: null, mail_spray_missing_networks: null}", 2, 3},
		{"absent preserves zero", "thresholds: {mail_spray_breadth_mailboxes: 0, mail_spray_missing_networks: 0}", "thresholds: {mail_spray_mode: observe}", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "spray.yaml"), []byte(tc.fragment), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadBytesWithDir([]byte(tc.main), dir)
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.Thresholds; got.MailSprayBreadthMailboxes != tc.breadth || got.MailSprayMissingNetworks != tc.networks {
				t.Fatalf("breadth/networks = %d/%d, want %d/%d", got.MailSprayBreadthMailboxes, got.MailSprayMissingNetworks, tc.breadth, tc.networks)
			}
		})
	}
}
