package admission

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// importName is a well-formed import name: the effect name the engine
// derives for a stamped legacy row.
func importName(n byte) ActionID {
	return ActionID("eff_" + strings.Repeat(fmt.Sprintf("%02x", n), 16))
}

// A victim is an admission attempt or an import, a stamped legacy block the
// engine names by its effect. Nothing else names one.
func TestParseVictimIDAcceptsAttemptsAndImports(t *testing.T) {
	attempt := testActionID(t, 1)
	for _, name := range []string{string(attempt), string(importName(1))} {
		if got, err := ParseVictimID(name); err != nil || string(got) != name {
			t.Fatalf("ParseVictimID(%q) = %q, %v", name, got, err)
		}
	}
	for _, name := range []string{"", "eff_", "eff_" + strings.Repeat("0", 31), "eff_" + strings.Repeat("A", 32), "imp_" + strings.Repeat("0", 32), "act_x"} {
		_, err := ParseVictimID(name)
		wantReason(t, name, err, ReasonInvalid)
	}
	if !ImportedVictim(importName(1)) || ImportedVictim(attempt) || ImportedVictim("eff_x") {
		t.Fatal("only a well-formed effect name is an import")
	}
}

// An import has no effect record: a pending block names it in its own
// record and intent, as wide as an attempt's name, and keys stay attempt
// IDs only.
func TestEffectRecordAndIntentNameAnImport(t *testing.T) {
	member := testEffect(t, 2)
	member.Target, member.Tier = mustAddr(t, "192.0.2.20"), Tier{Class: ClassC2, Severity: SeverityCritical}
	member.Victim = EffectRef{Action: importName(1), ExpiresAt: t0.Add(time.Hour)}
	key, err := member.Key()
	if err != nil {
		t.Fatal(err)
	}
	data, err := member.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if back, decodeErr := UnmarshalEffectRecord(key, data); decodeErr != nil || back != member {
		t.Fatalf("record round trip %+v, %v", back, decodeErr)
	}
	if !member.Victim.Imported() {
		t.Fatal("the record's victim is an import")
	}
	if _, keyErr := member.Victim.Key(); keyErr == nil {
		t.Fatal("an import has no record key")
	}
	in := testIntent(t)
	in.Victim = Victim{Action: importName(1), Target: mustAddr(t, "192.0.2.60"), ExpiresAt: t0.Add(time.Hour)}
	sealed, err := in.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if out, decodeErr := UnmarshalIntent(sealed); decodeErr != nil || out != in {
		t.Fatalf("intent round trip %+v, %v", out, decodeErr)
	}
	member.Victim.Action, in.Victim.Action = "eff_x", "eff_x"
	_, err = member.MarshalBinary()
	wantReason(t, "a record naming a malformed import", err, ReasonInvalid)
	_, err = in.MarshalBinary()
	wantReason(t, "an intent naming a malformed import", err, ReasonInvalid)
}

// The ledger takes an import as a victim only as the engine's list hands
// it over: an import name, an address, the import tier (C2, High), the
// general partition and an expiry after the epoch.
func TestEvictionVictimImported(t *testing.T) {
	if ImportTier != (Tier{Class: ClassC2, Severity: SeverityHigh}) {
		t.Fatalf("import tier %+v", ImportTier)
	}
	subnet, err := ParseTargetKey("net:198.51.100.0/24", v6)
	if err != nil {
		t.Fatal(err)
	}
	valid := func() EvictionVictim {
		return EvictionVictim{Action: importName(1), Target: mustAddr(t, "192.0.2.60"), Tier: ImportTier, Partition: PartitionGeneral, ExpiresAt: t0.Add(time.Hour)}
	}
	if v := valid(); !v.Imported() {
		t.Fatalf("%+v is an import", v)
	}
	for name, mutate := range map[string]func(*EvictionVictim){
		"an attempt":         func(v *EvictionVictim) { v.Action = testActionID(t, 1) },
		"a malformed name":   func(v *EvictionVictim) { v.Action = "eff_x" },
		"another tier":       func(v *EvictionVictim) { v.Tier = Tier{Class: ClassC2, Severity: SeverityCritical} },
		"reserved partition": func(v *EvictionVictim) { v.Partition = PartitionReserved },
		"no address":         func(v *EvictionVictim) { v.Target = Target{} },
		"a prefix":           func(v *EvictionVictim) { v.Target = subnet },
		"no expiry":          func(v *EvictionVictim) { v.ExpiresAt = time.Time{} },
		"before the epoch":   func(v *EvictionVictim) { v.ExpiresAt = time.Unix(-1, 0).UTC() },
	} {
		v := valid()
		mutate(&v)
		if v.Imported() {
			t.Errorf("%s: %+v taken as an import", name, v)
		}
	}
}
