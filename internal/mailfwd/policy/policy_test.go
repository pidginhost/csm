package policy

import (
	"reflect"
	"testing"
)

// allSignals enables every hold signal; individual tests clear what they don't want.
func allSignals() Config {
	return Config{
		Enabled: true,
		HoldSignals: HoldSignals{
			BounceBackscatter: true,
			SpamFlagged:       true,
			Malware:           true,
			BadSenderIP:       true,
			AuthFail:          true,
		},
	}
}

func TestVerdictDisabledNeverHolds(t *testing.T) {
	cfg := allSignals()
	cfg.Enabled = false
	meta := MessageMeta{NullSender: true, SpamFlagged: true, MalwareHit: true, SenderIPBad: true,
		SPFFail: true, DKIMFail: true, DMARCFail: true}
	if hold, reasons := Verdict(meta, cfg); hold || len(reasons) != 0 {
		t.Fatalf("disabled guard held: hold=%v reasons=%v", hold, reasons)
	}
}

func TestVerdictCleanMessageNotHeld(t *testing.T) {
	if hold, reasons := Verdict(MessageMeta{}, allSignals()); hold || len(reasons) != 0 {
		t.Fatalf("clean message held: hold=%v reasons=%v", hold, reasons)
	}
}

func TestVerdictEachSignalIndependently(t *testing.T) {
	cases := []struct {
		name   string
		meta   MessageMeta
		reason string
	}{
		{"bounce", MessageMeta{NullSender: true}, "bounce_backscatter"},
		{"spam", MessageMeta{SpamFlagged: true}, "spam_flagged"},
		{"malware", MessageMeta{MalwareHit: true}, "malware"},
		{"bad_ip", MessageMeta{SenderIPBad: true}, "bad_sender_ip"},
		{"auth", MessageMeta{SPFFail: true, DKIMFail: true, DMARCFail: true}, "auth_fail"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hold, reasons := Verdict(c.meta, allSignals())
			if !hold {
				t.Fatalf("%s did not hold", c.name)
			}
			if !reflect.DeepEqual(reasons, []string{c.reason}) {
				t.Fatalf("reasons = %v, want [%s]", reasons, c.reason)
			}
		})
	}
}

func TestVerdictAuthFailRequiresAllThree(t *testing.T) {
	cfg := Config{Enabled: true, HoldSignals: HoldSignals{AuthFail: true}}
	cases := []struct {
		name string
		meta MessageMeta
	}{
		{"none", MessageMeta{}},
		{"spf_only", MessageMeta{SPFFail: true}},
		{"dkim_only", MessageMeta{DKIMFail: true}},
		{"dmarc_only", MessageMeta{DMARCFail: true}},
		{"spf_dkim", MessageMeta{SPFFail: true, DKIMFail: true}},
		{"spf_dmarc", MessageMeta{SPFFail: true, DMARCFail: true}},
		{"dkim_dmarc", MessageMeta{DKIMFail: true, DMARCFail: true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if hold, reasons := Verdict(c.meta, cfg); hold || len(reasons) != 0 {
				t.Fatalf("auth held on partial failure: hold=%v reasons=%v", hold, reasons)
			}
		})
	}
	all := MessageMeta{SPFFail: true, DKIMFail: true, DMARCFail: true}
	hold, reasons := Verdict(all, cfg)
	if !hold || !reflect.DeepEqual(reasons, []string{"auth_fail"}) {
		t.Fatalf("auth-all-fail: hold=%v reasons=%v", hold, reasons)
	}
}

func TestVerdictRespectsEachSignalToggle(t *testing.T) {
	cases := []struct {
		name    string
		meta    MessageMeta
		reason  string
		enable  func(*HoldSignals)
		disable func(*HoldSignals)
	}{
		{
			name:    "bounce",
			meta:    MessageMeta{NullSender: true},
			reason:  "bounce_backscatter",
			enable:  func(sig *HoldSignals) { sig.BounceBackscatter = true },
			disable: func(sig *HoldSignals) { sig.BounceBackscatter = false },
		},
		{
			name:    "spam",
			meta:    MessageMeta{SpamFlagged: true},
			reason:  "spam_flagged",
			enable:  func(sig *HoldSignals) { sig.SpamFlagged = true },
			disable: func(sig *HoldSignals) { sig.SpamFlagged = false },
		},
		{
			name:    "malware",
			meta:    MessageMeta{MalwareHit: true},
			reason:  "malware",
			enable:  func(sig *HoldSignals) { sig.Malware = true },
			disable: func(sig *HoldSignals) { sig.Malware = false },
		},
		{
			name:    "bad_ip",
			meta:    MessageMeta{SenderIPBad: true},
			reason:  "bad_sender_ip",
			enable:  func(sig *HoldSignals) { sig.BadSenderIP = true },
			disable: func(sig *HoldSignals) { sig.BadSenderIP = false },
		},
		{
			name:    "auth",
			meta:    MessageMeta{SPFFail: true, DKIMFail: true, DMARCFail: true},
			reason:  "auth_fail",
			enable:  func(sig *HoldSignals) { sig.AuthFail = true },
			disable: func(sig *HoldSignals) { sig.AuthFail = false },
		},
	}
	for _, c := range cases {
		t.Run(c.name+"_enabled", func(t *testing.T) {
			cfg := Config{Enabled: true}
			c.enable(&cfg.HoldSignals)
			hold, reasons := Verdict(c.meta, cfg)
			if !hold || !reflect.DeepEqual(reasons, []string{c.reason}) {
				t.Fatalf("hold=%v reasons=%v, want %s", hold, reasons, c.reason)
			}
		})
		t.Run(c.name+"_disabled", func(t *testing.T) {
			cfg := allSignals()
			c.disable(&cfg.HoldSignals)
			hold, reasons := Verdict(c.meta, cfg)
			if hold || len(reasons) != 0 {
				t.Fatalf("held with %s disabled: hold=%v reasons=%v", c.name, hold, reasons)
			}
		})
	}
}

func TestVerdictMultipleReasonsStableOrder(t *testing.T) {
	meta := MessageMeta{NullSender: true, SpamFlagged: true, MalwareHit: true, SenderIPBad: true,
		SPFFail: true, DKIMFail: true, DMARCFail: true}
	hold, reasons := Verdict(meta, allSignals())
	if !hold {
		t.Fatal("did not hold")
	}
	want := []string{"auth_fail", "bad_sender_ip", "bounce_backscatter", "malware", "spam_flagged"}
	if !reflect.DeepEqual(reasons, want) {
		t.Fatalf("reasons = %v, want %v", reasons, want)
	}
	// Order must be deterministic across calls (no map iteration).
	for i := 0; i < 20; i++ {
		_, reasons2 := Verdict(meta, allSignals())
		if !reflect.DeepEqual(reasons2, want) {
			t.Fatalf("call %d reasons = %v, want %v", i, reasons2, want)
		}
	}
}
