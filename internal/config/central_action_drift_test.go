// This file is in the external test package on purpose. internal/config
// cannot import internal/reporting (reporting -> alert -> config is a cycle),
// so the validator carries its own copy of the action names. A test package
// has no such restriction and can hold the two lists against each other.
package config_test

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/reporting"
)

func centralActionConfig(action string) *config.Config {
	cfg := &config.Config{Hostname: "host.example.com"}
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.To = []string{"admin@example.com"}
	cfg.Alerts.Email.SMTP = "localhost:25"
	cfg.Alerts.Email.From = "csm@example.com"
	cfg.Alerts.MaxPerHour = 10
	cfg.Reputation.Central.Enabled = true
	cfg.Reputation.Central.Action = action
	return cfg
}

func hasCentralActionError(cfg *config.Config) bool {
	for _, r := range config.Validate(cfg) {
		if r.Level == "error" && r.Field == "reputation.central.action" {
			return true
		}
	}
	return false
}

// Every action the consumer understands must validate. If someone adds a
// fourth action to internal/reporting without updating the validator, this
// fails instead of the validator silently rejecting a legitimate policy.
func TestCentralActionsMatchReportingConstants(t *testing.T) {
	for _, action := range []reporting.Action{
		reporting.ActionOff,
		reporting.ActionChallenge,
		reporting.ActionBlockIfLocalCorroborated,
	} {
		if hasCentralActionError(centralActionConfig(string(action))) {
			t.Errorf("reporting action %q is rejected by config validation", action)
		}
	}
}

// The reverse direction: anything the validator accepts must survive
// ParseAction unchanged. A value that validates but parses to something else
// is the exact fail-open this validation exists to prevent.
func TestValidatedCentralActionsSurviveParsing(t *testing.T) {
	for _, action := range []string{"off", "challenge", "block_if_local_corroborated"} {
		if hasCentralActionError(centralActionConfig(action)) {
			t.Fatalf("action %q should validate", action)
		}
		if got := reporting.ParseAction(action); string(got) != action {
			t.Errorf("ParseAction(%q) = %q, want it unchanged", action, got)
		}
	}
}
