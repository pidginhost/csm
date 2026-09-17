package adapter

import (
	"strings"
	"testing"
)

func FuzzEximMutation(f *testing.F) {
	f.Add(`{"operation":"remove"}`)
	f.Add(`{"operation":"apply","config":{"Enabled":true,"HoldSignals":{"BounceBackscatter":true}},"bad_ips":["192.0.2.1"]}`)
	f.Add(`{"operation":"remove","command":"anything"}`)
	f.Fuzz(func(t *testing.T, input string) {
		calls := 0
		target := &eximServiceAdapter{mutate: func(r eximMutation) error {
			calls++
			if r.Operation != "apply" && r.Operation != "remove" {
				t.Fatalf("arbitrary operation escaped validation: %q", r.Operation)
			}
			if r.Operation == "apply" && (!r.Config.Enabled || r.Config.DryRun || (!r.Config.HoldSignals.BounceBackscatter && !r.Config.HoldSignals.BadSenderIP)) {
				t.Fatalf("invalid policy escaped validation: %+v", r.Config)
			}
			return nil
		}}
		err := handleEximMutation(strings.NewReader(input), target)
		if err == nil && calls != 1 || err != nil && calls != 0 {
			t.Fatalf("error=%v calls=%d", err, calls)
		}
	})
}
