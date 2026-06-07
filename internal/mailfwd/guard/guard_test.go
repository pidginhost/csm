package guard

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/mailfwd/policy"
)

func TestPolicyFromConfigMapsAllSignals(t *testing.T) {
	fg := config.ForwardGuardConfig{
		Enabled: true,
		DryRun:  true,
		HoldSignals: config.ForwardHoldSignals{
			BounceBackscatter: true,
			SpamFlagged:       false,
			Malware:           true,
			BadSenderIP:       false,
			AuthFail:          true,
		},
	}
	got := PolicyFromConfig(fg)
	want := policy.Config{
		Enabled: true,
		DryRun:  true,
		HoldSignals: policy.HoldSignals{
			BounceBackscatter: true,
			SpamFlagged:       false,
			Malware:           true,
			BadSenderIP:       false,
			AuthFail:          true,
		},
	}
	if got != want {
		t.Fatalf("PolicyFromConfig = %+v, want %+v", got, want)
	}
}

// The mapped policy must drive Verdict consistently with the operator's intent:
// a disabled guard never holds even with every signal flagged.
func TestPolicyFromConfigDisabledNeverHolds(t *testing.T) {
	fg := config.ForwardGuardConfig{Enabled: false, HoldSignals: config.ForwardHoldSignals{BounceBackscatter: true}}
	if hold, _ := policy.Verdict(policy.MessageMeta{NullSender: true}, PolicyFromConfig(fg)); hold {
		t.Fatal("disabled forward guard held a message")
	}
}
