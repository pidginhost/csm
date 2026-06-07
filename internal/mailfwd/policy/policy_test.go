package policy

import (
	"reflect"
	"sort"
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
	cfg := allSignals()
	// Only SPF+DKIM fail (DMARC passes) must NOT hold on auth: the rule is
	// conservative -- all three must fail.
	partial := MessageMeta{SPFFail: true, DKIMFail: true, DMARCFail: false}
	if hold, reasons := Verdict(partial, cfg); hold {
		t.Fatalf("auth held on partial failure: reasons=%v", reasons)
	}
	all := MessageMeta{SPFFail: true, DKIMFail: true, DMARCFail: true}
	hold, reasons := Verdict(all, cfg)
	if !hold || !reflect.DeepEqual(reasons, []string{"auth_fail"}) {
		t.Fatalf("auth-all-fail: hold=%v reasons=%v", hold, reasons)
	}
}

func TestVerdictRespectsPerSignalToggle(t *testing.T) {
	// Signal present in the message but its toggle is off -> no hold.
	cfg := Config{Enabled: true, HoldSignals: HoldSignals{SpamFlagged: true}}
	if hold, _ := Verdict(MessageMeta{NullSender: true}, cfg); hold {
		t.Fatal("held on bounce while only spam_flagged toggle is enabled")
	}
	if hold, reasons := Verdict(MessageMeta{SpamFlagged: true}, cfg); !hold || reasons[0] != "spam_flagged" {
		t.Fatalf("did not hold spam with spam toggle on: hold=%v reasons=%v", hold, reasons)
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
	got := append([]string(nil), reasons...)
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reasons = %v, want (sorted) %v", reasons, want)
	}
	// Order must be deterministic across calls (no map iteration).
	_, reasons2 := Verdict(meta, allSignals())
	if !reflect.DeepEqual(reasons, reasons2) {
		t.Fatalf("reason order not deterministic: %v vs %v", reasons, reasons2)
	}
}
