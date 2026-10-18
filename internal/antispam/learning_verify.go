package antispam

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
)

// LearningCheckStep is the failed step of an apply whose loaded learning
// configuration differs from CSM's files; the daemon then holds learning
// off until the learning configuration changes.
const LearningCheckStep = "learning_check"

// learningExpireSeconds is the worker's expire = 90d as configdump prints it.
const learningExpireSeconds = 90 * 24 * 3600

// Rule attributes CSM renders. A loaded rule with any other attribute, such
// as a different hash algorithm, is a conflict.
var (
	learningRuleCommon = []string{"servers", "fuzzy_key", "fuzzy_shingles_key", "read_encryption_key", "skip_unknown",
		"max_score", "min_length", "text_hashes", "text_shingles", "html_shingles", "skip_images", "mime_types",
		"scan_archives", "fuzzy_map"}
	learningRuleScan  = append(slices.Clone(learningRuleCommon), "read_only")
	learningRuleLearn = append(slices.Clone(learningRuleCommon), "mode", "retransmits", "write_encryption_key")
)

// CheckLearningLoaded compares what rspamd loaded with CSM's learning files
// (spec 6.1 to 6.3): exactly the rules csm and csm_learn with the pinned
// attributes and only flag 1, one fuzzy worker with the pinned transport
// and two keypairs, the fuzzy group cap, the effective CSM_FUZZY_SPAM weight
// from the controller's /symbols, and no score rescaling. Errors name the
// attribute, never a value that could be a key.
func CheckLearningLoaded(fuzzyCheck, worker, group, symbols []byte, a Actions) error {
	scan, learn, err := checkLearningRules(fuzzyCheck)
	if err != nil {
		return err
	}
	if err := checkLearningWorker(worker, scan, learn); err != nil {
		return err
	}
	if err := checkLearningGroup(group); err != nil {
		return err
	}
	if err := checkLearningSymbols(symbols); err != nil {
		return err
	}
	if a.GrowFactor != nil && *a.GrowFactor > 1 {
		return errors.New("rspamd rescales scores with grow_factor above 1")
	}
	return nil
}

func value(raw json.RawMessage) any {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return nil
	}
	return v
}

func isString(raw json.RawMessage) (string, bool) {
	s, ok := value(raw).(string)
	return s, ok && s != ""
}

// checkLearningRules returns the scan and learning rules once both match.
func checkLearningRules(dump []byte) (scan, learn map[string]json.RawMessage, err error) {
	root, err := dumpObjectAs[json.RawMessage](dump, "fuzzy_check")
	if err != nil {
		return nil, nil, errors.New("loaded fuzzy_check is not readable")
	}
	if raw, ok := root["enabled"]; ok && value(raw) != true {
		return nil, nil, errors.New("loaded fuzzy_check is disabled")
	}
	rules, err := loadedFuzzyRules(dump)
	if err != nil {
		return nil, nil, errors.New("loaded fuzzy rules are not readable")
	}
	scan, learn = rules["csm"], rules["csm_learn"]
	if len(rules) != 2 || scan == nil || learn == nil {
		return nil, nil, errors.New("rspamd must load exactly the fuzzy rules csm and csm_learn")
	}
	if err := checkRule("csm", scan, learningRuleScan, "CSM_FUZZY_SPAM"); err != nil {
		return nil, nil, err
	}
	if err := checkRule("csm_learn", learn, learningRuleLearn, "CSM_FUZZY_LEARN"); err != nil {
		return nil, nil, err
	}
	if value(scan["read_only"]) != true {
		return nil, nil, errors.New("fuzzy rule csm: read_only is not true")
	}
	if value(learn["mode"]) != "write_only" {
		return nil, nil, errors.New("fuzzy rule csm_learn: mode is not write_only")
	}
	if value(learn["retransmits"]) != 0.0 {
		return nil, nil, errors.New("fuzzy rule csm_learn: retransmits is not 0")
	}
	if _, ok := isString(learn["write_encryption_key"]); !ok {
		return nil, nil, errors.New("fuzzy rule csm_learn: write_encryption_key is missing")
	}
	// Both rules must hash alike and reach the worker with the same read key.
	for _, key := range []string{"fuzzy_key", "fuzzy_shingles_key", "read_encryption_key"} {
		if !reflect.DeepEqual(value(scan[key]), value(learn[key])) {
			return nil, nil, fmt.Errorf("fuzzy rules csm and csm_learn differ in %s", key)
		}
	}
	return scan, learn, nil
}

func checkRule(name string, rule map[string]json.RawMessage, attrs []string, symbol string) error {
	if len(rule) != len(attrs) {
		return fmt.Errorf("fuzzy rule %s carries attributes CSM did not set", name)
	}
	for _, attr := range attrs {
		if _, ok := rule[attr]; !ok {
			return fmt.Errorf("fuzzy rule %s: %s is missing", name, attr)
		}
	}
	want := map[string]any{
		"servers": learningServer, "skip_unknown": true, "max_score": 18.0, "min_length": float64(LearningMinLength),
		"text_hashes": true, "text_shingles": true, "html_shingles": false, "skip_images": true,
		"mime_types": []any{}, "scan_archives": false,
	}
	for attr, w := range want {
		if !reflect.DeepEqual(value(rule[attr]), w) {
			return fmt.Errorf("fuzzy rule %s: %s differs from CSM's", name, attr)
		}
	}
	for _, key := range []string{"fuzzy_key", "fuzzy_shingles_key", "read_encryption_key"} {
		if _, ok := isString(rule[key]); !ok {
			return fmt.Errorf("fuzzy rule %s: %s is missing", name, key)
		}
	}
	m, ok := value(rule["fuzzy_map"]).(map[string]any)
	wantMap := map[string]any{symbol: map[string]any{"flag": float64(LearningFlag), "max_score": 18.0}}
	if !ok || !reflect.DeepEqual(m, wantMap) {
		return fmt.Errorf("fuzzy rule %s: fuzzy_map must map only flag 1 to %s", name, symbol)
	}
	return nil
}

// checkLearningWorker requires exactly one fuzzy worker with the pinned
// transport and the two keypairs the rules use.
func checkLearningWorker(section []byte, scan, learn map[string]json.RawMessage) error {
	workers, err := fuzzyWorkers(section)
	if err != nil {
		return errors.New("loaded fuzzy worker is not readable")
	}
	if len(workers) != 1 {
		return errors.New("rspamd must load exactly one fuzzy worker")
	}
	w := workers[0]
	if disabled, err := disabledWorker(w); err != nil || disabled {
		return errors.New("the fuzzy worker is not enabled")
	}
	want := map[string]any{"bind_socket": learningServer, "count": 1.0, "backend": "redis",
		"encrypted_only": true, "allow_update": []any{}, "expire": float64(learningExpireSeconds)}
	for attr, v := range want {
		if !reflect.DeepEqual(value(w[attr]), v) {
			return fmt.Errorf("fuzzy worker: %s differs from CSM's", attr)
		}
	}
	if p, ok := isString(w["prefix"]); !ok || !learningPrefixPattern.MatchString(p) {
		return errors.New("fuzzy worker: prefix is not a CSM prefix")
	}
	var pairs []map[string]json.RawMessage
	if json.Unmarshal(w["keypair"], &pairs) != nil || len(pairs) != 2 {
		return errors.New("fuzzy worker: want exactly two keypairs")
	}
	readKey, _ := isString(scan["read_encryption_key"])
	writeKey, _ := isString(learn["write_encryption_key"])
	seen := map[string]bool{}
	for _, kp := range pairs {
		pub, ok := isString(kp["pubkey"])
		if _, priv := isString(kp["privkey"]); !ok || !priv {
			return errors.New("fuzzy worker: a keypair is incomplete")
		}
		var ext struct {
			AllowedOps []string `json:"allowed_ops"`
		}
		if json.Unmarshal(kp["extensions"], &ext) != nil {
			return errors.New("fuzzy worker: keypair extensions are not readable")
		}
		ops := strings.Join(ext.AllowedOps, ",")
		switch {
		case ops == "read" && pub == readKey:
			seen["read"] = true
		case ops == "read,write,delete" && pub == writeKey:
			seen["write"] = true
		default:
			return errors.New("fuzzy worker: a keypair's allowed_ops or public key differs from CSM's")
		}
	}
	if !seen["read"] || !seen["write"] {
		return errors.New("fuzzy worker: want one read keypair and one write keypair")
	}
	return nil
}

// fuzzyWorkers returns every fuzzy worker in the worker section, in either
// form rspamd prints.
func fuzzyWorkers(section []byte) ([]map[string]json.RawMessage, error) {
	var entries []json.RawMessage
	if json.Unmarshal(section, &entries) != nil {
		entries = []json.RawMessage{section}
	}
	var out []map[string]json.RawMessage
	for _, entry := range entries {
		obj, err := dumpObjectAs[json.RawMessage](entry, "worker")
		if err != nil {
			return nil, err
		}
		if raw, ok := obj["fuzzy"]; ok {
			w, err := dumpObjectAs[json.RawMessage](raw, "fuzzy worker")
			if err != nil {
				return nil, err
			}
			out = append(out, w)
			continue
		}
		if value(obj["type"]) == "fuzzy" {
			out = append(out, obj)
		}
	}
	return out, nil
}

// checkLearningGroup reads `configdump -j group`, a stream of objects, and
// requires the fuzzy group's cap and CSM's configured weights.
func checkLearningGroup(dump []byte) error {
	d := json.NewDecoder(strings.NewReader(string(dump)))
	var fuzzy map[string]json.RawMessage
	found := 0
	for {
		var obj map[string]json.RawMessage
		err := d.Decode(&obj)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return errors.New("loaded symbol groups are not readable")
		}
		if raw, ok := obj["fuzzy"]; ok {
			found++
			if json.Unmarshal(raw, &fuzzy) != nil {
				return errors.New("loaded fuzzy group is not readable")
			}
		}
	}
	if found != 1 {
		return errors.New("rspamd must load one fuzzy group")
	}
	if value(fuzzy["max_score"]) != 10.0 {
		return errors.New("fuzzy group: max_score is not 10")
	}
	var syms map[string]struct {
		Weight *float64 `json:"weight"`
	}
	if json.Unmarshal(fuzzy["symbols"], &syms) != nil {
		return errors.New("fuzzy group: symbols are not readable")
	}
	if s, ok := syms["CSM_FUZZY_SPAM"]; !ok || s.Weight == nil || *s.Weight != 10 {
		return errors.New("fuzzy group: CSM_FUZZY_SPAM weight is not 10")
	}
	if s, ok := syms["CSM_FUZZY_LEARN"]; !ok || s.Weight == nil || *s.Weight != 0 {
		return errors.New("fuzzy group: CSM_FUZZY_LEARN weight is not 0")
	}
	return nil
}

// checkLearningSymbols reads the controller's /symbols reply, which shows
// dynamic weight overrides configdump cannot (spike S2).
func checkLearningSymbols(reply []byte) error {
	var groups []struct {
		Rules []struct {
			Symbol string   `json:"symbol"`
			Weight *float64 `json:"weight"`
		} `json:"rules"`
	}
	if json.Unmarshal(reply, &groups) != nil {
		return errors.New("the controller's /symbols reply is not readable")
	}
	found := 0
	for _, g := range groups {
		for _, r := range g.Rules {
			if r.Symbol != "CSM_FUZZY_SPAM" {
				continue
			}
			found++
			if r.Weight == nil || *r.Weight != 10 {
				return errors.New("the effective CSM_FUZZY_SPAM weight is not 10")
			}
		}
	}
	if found != 1 {
		return errors.New("the controller does not list CSM_FUZZY_SPAM once")
	}
	return nil
}
