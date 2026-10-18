package antispam

import (
	"encoding/json"
	"strings"
	"testing"
)

// loadedDumps builds the configdump and /symbols replies rspamd 4.2.2 gave
// for CSM's rendered learning files on the scratch host (2026-10-18):
// fuzzy_check rules as a list of single-key objects, the fuzzy worker in
// the worker list with expire in seconds, the group dump as concatenated
// objects and /symbols as a list of groups.
type loadedDumps struct {
	fuzzyCheck map[string]any
	worker     []any
	groups     []map[string]any
	symbols    []any
	actions    Actions
	keys       LearningKeys
}

func newLoadedDumps(k LearningKeys) *loadedDumps {
	rule := func(extra map[string]any) map[string]any {
		r := map[string]any{
			"servers": "127.0.0.1:11335", "fuzzy_key": k.Fuzzy.Reveal(), "fuzzy_shingles_key": k.Shingles.Reveal(),
			"read_encryption_key": k.Read.Public, "skip_unknown": true, "max_score": 18.0, "min_length": 32,
			"text_hashes": true, "text_shingles": true, "html_shingles": false, "skip_images": true,
			"mime_types": []any{}, "scan_archives": false,
		}
		for key, v := range extra {
			r[key] = v
		}
		return r
	}
	return &loadedDumps{
		keys: k,
		fuzzyCheck: map[string]any{"enabled": true, "min_bytes": 1000, "retransmits": 1, "timeout": 2.0, "rule": []any{
			map[string]any{"csm": rule(map[string]any{"read_only": true,
				"fuzzy_map": map[string]any{"CSM_FUZZY_SPAM": map[string]any{"flag": 1, "max_score": 18.0}}})},
			map[string]any{"csm_learn": rule(map[string]any{"mode": "write_only", "retransmits": 0, "write_encryption_key": k.Write.Public,
				"fuzzy_map": map[string]any{"CSM_FUZZY_LEARN": map[string]any{"flag": 1, "max_score": 18.0}}})},
		}},
		worker: []any{
			map[string]any{"normal": map[string]any{"bind_socket": "localhost:11333"}},
			map[string]any{"fuzzy": map[string]any{
				"allow_update": []any{}, "backend": "redis", "bind_socket": "127.0.0.1:11335", "count": 1,
				"encrypted_only": true, "expire": 7776000.0, "prefix": k.Prefix,
				"keypair": []any{
					map[string]any{"extensions": map[string]any{"allowed_ops": []any{"read"}}, "privkey": k.Read.Private.Reveal(), "pubkey": k.Read.Public},
					map[string]any{"extensions": map[string]any{"allowed_ops": []any{"read", "write", "delete"}}, "privkey": k.Write.Private.Reveal(), "pubkey": k.Write.Public},
				},
			}},
		},
		groups: []map[string]any{
			{"headers": map[string]any{"max_score": 8.0}},
			{"fuzzy": map[string]any{"description": "Fuzzy hashes group", "max_score": 10.0, "symbols": map[string]any{
				"CSM_FUZZY_LEARN": map[string]any{"weight": 0.0}, "CSM_FUZZY_SPAM": map[string]any{"weight": 10.0},
				"FUZZY_DENIED": map[string]any{"weight": 12.0}}}},
		},
		symbols: []any{
			map[string]any{"group": "headers", "rules": []any{map[string]any{"symbol": "FORGED_SENDER", "weight": 0.3}}},
			map[string]any{"group": "fuzzy", "rules": []any{
				map[string]any{"symbol": "CSM_FUZZY_SPAM", "weight": 10.0, "frequency": 0.0},
				map[string]any{"symbol": "CSM_FUZZY_LEARN", "weight": 0.0}}},
		},
	}
}

func (d *loadedDumps) rule(name string) map[string]any {
	for _, e := range d.fuzzyCheck["rule"].([]any) {
		if r, ok := e.(map[string]any)[name]; ok {
			return r.(map[string]any)
		}
	}
	return nil
}

func (d *loadedDumps) fuzzyWorker() map[string]any {
	return d.worker[1].(map[string]any)["fuzzy"].(map[string]any)
}

func (d *loadedDumps) check() error {
	enc := func(v any) []byte { b, _ := json.Marshal(v); return b }
	var group strings.Builder
	for _, g := range d.groups {
		group.Write(enc(g))
		group.WriteString("\n")
	}
	return CheckLearningLoaded(enc(d.fuzzyCheck), enc(d.worker), []byte(group.String()), enc(d.symbols), d.actions, d.keys)
}

func TestCheckLearningLoadedExact(t *testing.T) {
	if err := newLoadedDumps(syntheticLearningKeys()).check(); err != nil {
		t.Fatal(err)
	}
	// One rule prints as an object, not a list.
	d := newLoadedDumps(syntheticLearningKeys())
	d.fuzzyCheck["rule"] = map[string]any{"csm": d.rule("csm"), "csm_learn": d.rule("csm_learn")}
	if err := d.check(); err != nil {
		t.Fatalf("object-form rules: %v", err)
	}
}

func TestCheckLearningLoadedConflicts(t *testing.T) {
	for name, change := range map[string]func(d *loadedDumps){
		"ExtraRule": func(d *loadedDumps) {
			d.fuzzyCheck["rule"] = append(d.fuzzyCheck["rule"].([]any), map[string]any{"rspamd.com": map[string]any{"servers": "x"}})
		},
		"MissingRule":        func(d *loadedDumps) { d.fuzzyCheck["rule"] = d.fuzzyCheck["rule"].([]any)[:1] },
		"ModuleOff":          func(d *loadedDumps) { d.fuzzyCheck["enabled"] = false },
		"ReadOnlyMissing":    func(d *loadedDumps) { delete(d.rule("csm"), "read_only") },
		"ScanRuleWrites":     func(d *loadedDumps) { d.rule("csm")["write_encryption_key"] = "k" },
		"RetransmitsNonZero": func(d *loadedDumps) { d.rule("csm_learn")["retransmits"] = 1 },
		"LearnNotWriteOnly":  func(d *loadedDumps) { d.rule("csm_learn")["mode"] = "read_write" },
		"MinLengthStock":     func(d *loadedDumps) { d.rule("csm")["min_length"] = 64 },
		"HTMLShingles":       func(d *loadedDumps) { d.rule("csm_learn")["html_shingles"] = true },
		"ExtraAttribute":     func(d *loadedDumps) { d.rule("csm")["algorithm"] = "mumhash" },
		"SecondFlag": func(d *loadedDumps) {
			d.rule("csm")["fuzzy_map"].(map[string]any)["FUZZY_DENIED"] = map[string]any{"flag": 11, "max_score": 20.0}
		},
		"WrongFlag": func(d *loadedDumps) {
			d.rule("csm")["fuzzy_map"] = map[string]any{"CSM_FUZZY_SPAM": map[string]any{"flag": 2, "max_score": 18.0}}
		},
		"KeysDiffer":        func(d *loadedDumps) { d.rule("csm_learn")["fuzzy_key"] = strings.Repeat("9f", 32) },
		"WorkerAllowUpdate": func(d *loadedDumps) { d.fuzzyWorker()["allow_update"] = []any{"localhost"} },
		"WorkerPlaintext":   func(d *loadedDumps) { d.fuzzyWorker()["encrypted_only"] = false },
		"WorkerBind":        func(d *loadedDumps) { d.fuzzyWorker()["bind_socket"] = "*:11335" },
		"WorkerCount":       func(d *loadedDumps) { d.fuzzyWorker()["count"] = 2 },
		"WorkerExpire":      func(d *loadedDumps) { d.fuzzyWorker()["expire"] = 86400.0 },
		"WrongAllowedOps": func(d *loadedDumps) {
			d.fuzzyWorker()["keypair"].([]any)[0].(map[string]any)["extensions"] = map[string]any{"allowed_ops": []any{"read", "write"}}
		},
		"KeypairMismatch": func(d *loadedDumps) {
			d.fuzzyWorker()["keypair"].([]any)[1].(map[string]any)["pubkey"] = syntheticBase32(20)
		},
		"ThirdKeypair": func(d *loadedDumps) {
			kp := d.fuzzyWorker()["keypair"].([]any)
			d.fuzzyWorker()["keypair"] = append(kp, kp[1])
		},
		"SecondWorker": func(d *loadedDumps) { d.worker = append(d.worker, d.worker[1]) },
		"NoWorker":     func(d *loadedDumps) { d.worker = d.worker[:1] },
		"GroupCap":     func(d *loadedDumps) { d.groups[1]["fuzzy"].(map[string]any)["max_score"] = 20.0 },
		"NoGroup":      func(d *loadedDumps) { d.groups = d.groups[:1] },
		"GrowFactor":   func(d *loadedDumps) { v := 1.1; d.actions.GrowFactor = &v },
		"NoSymbol": func(d *loadedDumps) {
			d.symbols = d.symbols[:1]
		},
	} {
		t.Run(name, func(t *testing.T) {
			d := newLoadedDumps(syntheticLearningKeys())
			change(d)
			if err := d.check(); err == nil {
				t.Fatal("conflict accepted")
			}
		})
	}
	d := newLoadedDumps(syntheticLearningKeys())
	one := 1.0
	d.actions.GrowFactor = &one
	if err := d.check(); err != nil {
		t.Fatalf("grow_factor 1 is no rescaling: %v", err)
	}
}

// A dynamic /savesymbols override is invisible to configdump; only the
// controller's /symbols shows the effective weight (spec 6.2, spike S2).
func TestCheckLearningLoadedDynamicWeight(t *testing.T) {
	d := newLoadedDumps(syntheticLearningKeys())
	d.symbols[1].(map[string]any)["rules"].([]any)[0].(map[string]any)["weight"] = 20.0
	if err := d.check(); err == nil {
		t.Fatal("dynamic weight 20 accepted")
	}
}

func TestCheckLearningErrorsNeverCarryKeys(t *testing.T) {
	k := syntheticLearningKeys()
	secrets := []string{k.Fuzzy.Reveal(), k.Shingles.Reveal(), k.Read.Private.Reveal(), k.Write.Private.Reveal(), k.Read.Public, k.Write.Public, k.Prefix}
	for name, change := range map[string]func(d *loadedDumps){
		"key mismatch":   func(d *loadedDumps) { d.rule("csm_learn")["fuzzy_key"] = k.Shingles.Reveal() },
		"bad flag value": func(d *loadedDumps) { d.rule("csm")["read_only"] = k.Fuzzy.Reveal() },
		"pubkey": func(d *loadedDumps) {
			d.fuzzyWorker()["keypair"].([]any)[0].(map[string]any)["pubkey"] = k.Write.Public
		},
		"bad worker": func(d *loadedDumps) { d.fuzzyWorker()["prefix"] = map[string]any{"x": k.Write.Private.Reveal()} },
	} {
		d := newLoadedDumps(k)
		change(d)
		err := d.check()
		if err == nil {
			t.Fatalf("%s accepted", name)
		}
		for _, s := range secrets {
			if strings.Contains(err.Error(), s) {
				t.Fatalf("%s: error carries a key", name)
			}
		}
	}
}

func TestCheckRspamdLearningModule(t *testing.T) {
	s := learningSettings()
	if conflicts := CheckRspamd(map[string]bool{"dkim": true, "fuzzy_check": true}, defaultActions(s), s); len(conflicts) != 0 {
		t.Fatalf("learning with fuzzy_check enabled: %v", conflicts)
	}
	if conflicts := CheckRspamd(map[string]bool{"dkim": true}, defaultActions(s), s); len(conflicts) == 0 {
		t.Fatal("learning with fuzzy_check disabled accepted")
	}
	core := defaults(true)
	if conflicts := CheckRspamd(map[string]bool{"fuzzy_check": true}, defaultActions(core), core); len(conflicts) == 0 {
		t.Fatal("fuzzy_check enabled without learning accepted")
	}
}

func defaultActions(s Settings) Actions {
	reject, tag := float64(s.RejectScore), float64(s.TagScore)
	return Actions{Reject: &reject, AddHeader: &tag}
}

func TestParseActionsGrowFactor(t *testing.T) {
	a, err := ParseActions([]byte(`{"reject": 15, "add_header": 6, "grow_factor": 1.5}`))
	if err != nil || a.GrowFactor == nil || *a.GrowFactor != 1.5 {
		t.Fatalf("actions = %+v, err = %v", a, err)
	}
}

func TestCheckLearningRejectsMalformedOperations(t *testing.T) {
	d := newLoadedDumps(syntheticLearningKeys())
	d.fuzzyWorker()["keypair"].([]any)[1].(map[string]any)["extensions"] = map[string]any{"allowed_ops": []any{"read,write,delete"}}
	if err := d.check(); err == nil {
		t.Fatal("one invalid operation accepted as three permissions")
	}
}

func TestCheckLearningRejectsAmbiguousFields(t *testing.T) {
	for name, change := range map[string]func(*loadedDumps){
		"mapping": func(d *loadedDumps) {
			d.rule("csm")["fuzzy_map"] = json.RawMessage(`{"CSM_FUZZY_SPAM":{"flag":2,"flag":1,"max_score":18}}`)
		},
		"keypair": func(d *loadedDumps) {
			pair := d.fuzzyWorker()["keypair"].([]any)[0]
			b, _ := json.Marshal(pair)
			d.fuzzyWorker()["keypair"].([]any)[0] = json.RawMessage(strings.Replace(string(b), `"extensions":`, `"extensions":{"allowed_ops":["write"]},"extensions":`, 1))
		},
		"group cap": func(d *loadedDumps) {
			d.groups[1]["fuzzy"].(map[string]any)["max_score"] = 10
			b, _ := json.Marshal(d.groups[1]["fuzzy"])
			d.groups[1]["fuzzy"] = json.RawMessage(strings.Replace(string(b), `"max_score":10`, `"max_score":20,"max_score":10`, 1))
		},
		"configured weight": func(d *loadedDumps) {
			d.groups[1]["fuzzy"].(map[string]any)["symbols"].(map[string]any)["CSM_FUZZY_SPAM"] = json.RawMessage(`{"weight":20,"weight":10}`)
		},
		"effective weight": func(d *loadedDumps) {
			d.symbols[1].(map[string]any)["rules"].([]any)[0] = json.RawMessage(`{"symbol":"CSM_FUZZY_SPAM","weight":20,"weight":10}`)
		},
		"effective symbol alias": func(d *loadedDumps) {
			d.symbols[1].(map[string]any)["rules"].([]any)[0] = json.RawMessage(`{"symbol":"OTHER","SYMBOL":"CSM_FUZZY_SPAM","weight":10}`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			d := newLoadedDumps(syntheticLearningKeys())
			change(d)
			if err := d.check(); err == nil {
				t.Fatal("ambiguous loaded configuration accepted")
			}
		})
	}
}

func TestParseActionsRejectsAmbiguousGrowFactor(t *testing.T) {
	if _, err := ParseActions([]byte(`{"reject":15,"add_header":6,"grow_factor":2,"grow_factor":1}`)); err == nil {
		t.Fatal("ambiguous score rescaling accepted")
	}
}
