package main

import (
	"reflect"
	"testing"
)

func TestYaraWorkerUsesSupervisorDisabledRules(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want []string
		bad  bool
	}{
		{"manual", nil, []string{"disk_rule"}, false},
		{"snapshot", []string{"--disabled-rules", `["active_rule"]`}, []string{"active_rule"}, false},
		{"empty snapshot", []string{"--disabled-rules", `null`}, nil, false},
		{"missing", []string{"--disabled-rules"}, nil, true},
		{"invalid", []string{"--disabled-rules", `broken`}, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := yaraWorkerConfig(tc.args, []string{"disk_rule"})
			if (err != nil) != tc.bad {
				t.Fatalf("error = %v, want bad=%t", err, tc.bad)
			}
			if !tc.bad && !reflect.DeepEqual(cfg.DisabledRules, tc.want) {
				t.Fatalf("disabled = %v, want %v", cfg.DisabledRules, tc.want)
			}
		})
	}
}
