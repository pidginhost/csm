package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestFileResponseDefaultsAndOverrides(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		want        map[string]int
	}{
		{"omitted", "", map[string]int{"max_file_actions_per_hour": 50, "max_file_actions_per_account_per_hour": 10, "max_file_action_failures_per_hour": 3}},
		{"zero uses defaults", "auto_response:\n  max_file_actions_per_hour: 0\n  max_file_actions_per_account_per_hour: 0\n  max_file_action_failures_per_hour: 0\n", map[string]int{"max_file_actions_per_hour": 50, "max_file_actions_per_account_per_hour": 10, "max_file_action_failures_per_hour": 3}},
		{"explicit", "auto_response:\n  max_file_actions_per_hour: 4\n  max_file_actions_per_account_per_hour: 2\n  max_file_action_failures_per_hour: 1\n", map[string]int{"max_file_actions_per_hour": 4, "max_file_actions_per_account_per_hour": 2, "max_file_action_failures_per_hour": 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadBytes([]byte(tc.input))
			if err != nil {
				t.Fatal(err)
			}
			data, err := yaml.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			var decoded struct {
				AutoResponse map[string]any `yaml:"auto_response"`
			}
			if err := yaml.Unmarshal(data, &decoded); err != nil {
				t.Fatal(err)
			}
			for key, want := range tc.want {
				if got := decoded.AutoResponse[key]; got != want {
					t.Errorf("effective %s=%v, want %d", key, got, want)
				}
			}
		})
	}
}

func TestFileResponseRejectsUnsafeLimits(t *testing.T) {
	for _, key := range []string{"max_file_actions_per_hour", "max_file_actions_per_account_per_hour", "max_file_action_failures_per_hour"} {
		for _, value := range []string{"-1", "10001"} {
			t.Run(key+value, func(t *testing.T) {
				cfg, err := LoadBytes([]byte("auto_response:\n  " + key + ": " + value + "\n"))
				if err != nil {
					t.Fatal(err)
				}
				if !hasErrorOnField(Validate(cfg), "auto_response."+key) {
					t.Errorf("unsafe %s=%s accepted", key, value)
				}
			})
		}
	}
}
