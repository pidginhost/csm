package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPHPRelayRecipientSettingsRejectNonIntegers(t *testing.T) {
	for _, field := range []string{"ip_recipient_spread", "ip_recipient_window_hours"} {
		for _, value := range []string{"0.5", "-0.5", "5.9", "100.9", "168.9", "5.0", "5e0", "true", `"5"`} {
			for _, form := range []string{"direct", "alias", "merge", "drop-in"} {
				t.Run(field+"/"+value+"/"+form, func(t *testing.T) {
					data := "email_protection:\n  php_relay:\n    " + field + ": " + value + "\n"
					var err error
					switch form {
					case "alias":
						data = "hostname: &value " + value + "\nemail_protection:\n  php_relay:\n    " + field + ": *value\n"
						_, err = LoadBytes([]byte(data))
					case "merge":
						data = "email_protection:\n  php_relay:\n    <<: {" + field + ": " + value + "}\n"
						_, err = LoadBytes([]byte(data))
					case "drop-in":
						dir := t.TempDir()
						if writeErr := os.WriteFile(filepath.Join(dir, "relay.yaml"), []byte(data), 0600); writeErr != nil {
							t.Fatal(writeErr)
						}
						_, err = LoadBytesWithDir(nil, dir)
					default:
						_, err = LoadBytes([]byte(data))
					}
					if err == nil || !strings.Contains(err.Error(), "email_protection.php_relay."+field) {
						t.Fatalf("expected a field-specific type error, got %v", err)
					}
				})
			}
		}
	}
}

func TestPHPRelayRecipientSettingsPreserveIntegersAndDefaults(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   string
		spread int
		window int
	}{
		{"omitted", "", 5, 24},
		{"zero", "ip_recipient_spread: 0\n    ip_recipient_window_hours: 0", 0, 24},
		{"minimum", "ip_recipient_spread: 1\n    ip_recipient_window_hours: 1", 1, 1},
		{"maximum", "ip_recipient_spread: 100\n    ip_recipient_window_hours: 168", 100, 168},
		{"null", "ip_recipient_spread: null\n    ip_recipient_window_hours: null", 5, 24},
		{"alias-null", "ip_recipient_spread: &value null\n    ip_recipient_window_hours: *value", 5, 24},
		{"alias-zero", "ip_recipient_spread: &value 0\n    ip_recipient_window_hours: *value", 0, 24},
		{"alias-integer", "ip_recipient_spread: &value 12\n    ip_recipient_window_hours: *value", 12, 12},
		{"merge-zero", "<<: {ip_recipient_spread: 0, ip_recipient_window_hours: 0}", 0, 24},
		{"merge-null", "<<: {ip_recipient_spread: null, ip_recipient_window_hours: null}", 5, 24},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte("email_protection:\n  php_relay:\n    " + tc.body + "\n")
			for _, layered := range []bool{false, true} {
				var cfg *Config
				var err error
				if layered {
					dir := t.TempDir()
					if writeErr := os.WriteFile(filepath.Join(dir, "relay.yaml"), data, 0600); writeErr != nil {
						t.Fatal(writeErr)
					}
					cfg, err = LoadBytesWithDir([]byte("email_protection:\n  php_relay:\n    ip_recipient_spread: 9\n    ip_recipient_window_hours: 48\n"), dir)
				} else {
					cfg, err = LoadBytes(data)
				}
				if err != nil {
					t.Fatalf("layered=%t: %v", layered, err)
				}
				pr := cfg.EmailProtection.PHPRelay
				if pr.IPRecipientSpread != tc.spread || pr.IPRecipientWindowHours != tc.window {
					t.Fatalf("layered=%t: spread/window = %d/%d, want %d/%d", layered, pr.IPRecipientSpread, pr.IPRecipientWindowHours, tc.spread, tc.window)
				}
				for _, field := range []string{"ip_recipient_spread", "ip_recipient_window_hours"} {
					if hasErrorOnField(Validate(cfg), "email_protection.php_relay."+field) {
						t.Errorf("layered=%t: valid %s rejected", layered, field)
					}
				}
			}
		})
	}
}
