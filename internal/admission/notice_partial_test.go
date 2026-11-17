package admission

import "testing"

// A verified block of a destination is a Critical withheld record keyed by
// its outcome and reason together; no other key with both is valid.
func TestPartialContainmentNoticeKey(t *testing.T) {
	k := PartialContainmentKey("c2_connection", EffectAddress)
	if err := k.validate(); err != nil || !k.Partial() || !k.Kind.Critical() {
		t.Fatalf("partial key %+v: validate %v, partial %t, critical %t", k, err, k.Partial(), k.Kind.Critical())
	}
	if b, err := k.Bytes(); err != nil {
		t.Fatalf("partial key bytes: %v", err)
	} else if got, err := ParseNoticeKey(b); err != nil || got != k {
		t.Fatalf("partial key round trip = %+v, %v", got, err)
	}
	for name, bad := range map[string]NoticeKey{
		"another reason": {Kind: NoticeWithheld, Reason: ReasonCeiling, Outcome: DispositionApplied, Check: "c2_connection", Effect: EffectAddress},
		"warning kind":   {Kind: NoticeWithheldWarning, Reason: ReasonUnsupportedContainment, Outcome: DispositionApplied, Check: "c2_connection", Effect: EffectAddress},
		"no reason":      {Kind: NoticeWithheld, Outcome: DispositionApplied, Check: "c2_connection", Effect: EffectAddress},
		"failed":         {Kind: NoticeWithheld, Reason: ReasonUnsupportedContainment, Outcome: DispositionFailed, Check: "c2_connection", Effect: EffectAddress},
	} {
		if bad.validate() == nil || bad.Partial() {
			t.Fatalf("%s: %+v validates or is partial", name, bad)
		}
	}
	if gap := (NoticeKey{Kind: NoticeWithheld, Reason: ReasonUnsupportedContainment, Check: "c2_connection", Effect: EffectAddress}); gap.validate() != nil || gap.Partial() {
		t.Fatalf("the gap of an unsupported containment changed: %+v", gap)
	}
}
