package antispam

import (
	"regexp"
	"strings"
	"testing"
)

func learningSettings() Settings {
	s := defaults(true)
	s.Learning, s.LearningDir = true, DefaultLearningDir
	s.LearningKeys = syntheticLearningKeys()
	return s
}

// ruleBlock returns the text of one `rule "<name>" { ... }` block.
func ruleBlock(t *testing.T, text, name string) string {
	t.Helper()
	start := strings.Index(text, "rule \""+name+"\" {\n")
	if start < 0 {
		t.Fatalf("rule %s missing in:\n%s", name, text)
	}
	end := strings.Index(text[start:], "\n}\n")
	if end < 0 {
		t.Fatalf("rule %s unterminated", name)
	}
	return text[start : start+end+3]
}

func countLine(text, line string) int {
	n := 0
	for _, l := range strings.Split(text, "\n") {
		if strings.TrimSpace(l) == line {
			n++
		}
	}
	return n
}

func TestRenderLearningPinnedValues(t *testing.T) {
	s := learningSettings()
	k := s.LearningKeys
	files, err := RenderLearning(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 4 {
		t.Fatalf("files = %v", keysOf(files))
	}
	check := files[LearningCheckPath]
	if len(regexp.MustCompile(`(?m)^rule `).FindAllStringIndex(check, -1)) != 2 {
		t.Fatalf("want exactly two rules:\n%s", check)
	}
	scan, learn := ruleBlock(t, check, "csm"), ruleBlock(t, check, "csm_learn")
	common := []string{
		`servers = "127.0.0.1:11335";`,
		`fuzzy_key = "` + k.Fuzzy.Reveal() + `";`,
		`fuzzy_shingles_key = "` + k.Shingles.Reveal() + `";`,
		`read_encryption_key = "` + k.Read.Public + `";`,
		`skip_unknown = true;`, `max_score = 18.0;`, `min_length = 32;`,
		`text_hashes = true;`, `text_shingles = true;`, `html_shingles = false;`,
		`skip_images = true;`, `mime_types = [];`, `scan_archives = false;`,
	}
	for _, line := range common {
		if countLine(scan, line) != 1 || countLine(learn, line) != 1 {
			t.Errorf("%q: csm %d, csm_learn %d times", line, countLine(scan, line), countLine(learn, line))
		}
	}
	for _, line := range []string{`read_only = true;`, `fuzzy_map = { CSM_FUZZY_SPAM { flag = 1; max_score = 18.0; } }`} {
		if countLine(scan, line) != 1 || countLine(learn, line) != 0 {
			t.Errorf("%q must be in csm only", line)
		}
	}
	for _, line := range []string{`mode = "write_only";`, `retransmits = 0;`, `write_encryption_key = "` + k.Write.Public + `";`, `fuzzy_map = { CSM_FUZZY_LEARN { flag = 1; max_score = 18.0; } }`} {
		if countLine(learn, line) != 1 || countLine(scan, line) != 0 {
			t.Errorf("%q must be in csm_learn only", line)
		}
	}
	if strings.Contains(scan, k.Write.Public) {
		t.Error("the write key reached the scan rule")
	}
	for _, priv := range []string{k.Read.Private.Reveal(), k.Write.Private.Reveal()} {
		if strings.Contains(check, priv) {
			t.Error("a private key reached fuzzy_check.conf")
		}
	}
	worker := files[LearningWorkerPath]
	for _, line := range []string{
		`count = 1;`, `bind_socket = "127.0.0.1:11335";`, `backend = "redis";`,
		`prefix = "` + k.Prefix + `";`, `expire = 90d;`, `allow_update = [];`, `encrypted_only = true;`,
		`privkey = "` + k.Read.Private.Reveal() + `";`, `pubkey = "` + k.Read.Public + `";`,
		`privkey = "` + k.Write.Private.Reveal() + `";`, `pubkey = "` + k.Write.Public + `";`,
		`extensions { allowed_ops = ["read"]; }`, `extensions { allowed_ops = ["read", "write", "delete"]; }`,
	} {
		if countLine(worker, line) != 1 {
			t.Errorf("worker: %q appears %d times", line, countLine(worker, line))
		}
	}
	if strings.Count(worker, "keypair {") != 2 {
		t.Error("worker needs exactly two keypairs")
	}
	// Each keypair block carries its own private key and operations.
	_, readBlock, found := strings.Cut(worker, `privkey = "`+k.Read.Private.Reveal())
	readBlock, _, closed := strings.Cut(readBlock, "}\n}")
	if !found || !closed || !strings.Contains(readBlock, `allowed_ops = ["read"];`) || strings.Contains(readBlock, `"write"`) {
		t.Errorf("read keypair block: %s", readBlock)
	}
	for _, secret := range []string{k.Fuzzy.Reveal(), k.Shingles.Reveal()} {
		if strings.Contains(worker, secret) {
			t.Error("a hash key reached the worker file")
		}
	}
	group := files[LearningGroupPath]
	for _, line := range []string{`max_score = 10.0;`, `CSM_FUZZY_SPAM { weight = 10.0; }`, `CSM_FUZZY_LEARN { weight = 0.0; }`} {
		if countLine(group, line) != 1 {
			t.Errorf("group: %q appears %d times", line, countLine(group, line))
		}
	}
	lua := files[LearningLuaPath]
	if lua != LearningPlugin {
		t.Error("lua file is not the embedded plugin")
	}
	for path, text := range files {
		for _, secret := range []string{k.Fuzzy.Reveal(), k.Shingles.Reveal(), k.Read.Private.Reveal(), k.Write.Private.Reveal()} {
			if (path == LearningGroupPath || path == LearningLuaPath) && strings.Contains(text, secret) {
				t.Errorf("%s carries a secret", path)
			}
		}
	}
}

func keysOf(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestRenderLearningMarkers(t *testing.T) {
	files, err := RenderLearning(learningSettings())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{LearningCheckPath, LearningWorkerPath, LearningGroupPath} {
		if first, _, _ := strings.Cut(files[p], "\n"); first != ManagedHeader {
			t.Errorf("%s first line %q", p, first)
		}
	}
	if first, _, _ := strings.Cut(files[LearningLuaPath], "\n"); first != "-- csm-managed-version: 1" {
		t.Errorf("lua first line %q", first)
	}
	if got := LearningPaths(); strings.Join(got, ",") != strings.Join([]string{LearningCheckPath, LearningWorkerPath, LearningGroupPath, LearningLuaPath}, ",") {
		t.Errorf("LearningPaths = %v", got)
	}
	if LearningCheckPath != "/etc/rspamd/override.d/fuzzy_check.conf" || LearningWorkerPath != "/etc/rspamd/override.d/worker-fuzzy.inc" ||
		LearningGroupPath != "/etc/rspamd/local.d/fuzzy_group.conf" || LearningLuaPath != "/etc/rspamd/lua.local.d/csm_learning.lua" {
		t.Error("learning paths changed")
	}
}

func TestRenderLearningOffRendersNothing(t *testing.T) {
	files, err := RenderLearning(defaults(true))
	if err != nil || len(files) != 0 {
		t.Fatalf("files=%v err=%v", keysOf(files), err)
	}
	s := learningSettings()
	s.LearningKeys = LearningKeys{}
	if _, err := RenderLearning(s); err == nil {
		t.Fatal("learning without keys rendered")
	}
	s = learningSettings()
	s.LearningKeys.Prefix = "csmfz_\"; evil"
	if _, err := RenderLearning(s); err == nil {
		t.Fatal("invalid prefix rendered")
	}
}

func TestRenderRspamdFuzzyToggle(t *testing.T) {
	off, err := RenderRspamd(defaults(true))
	if err != nil || off["fuzzy_check.conf"] != ManagedHeader+"\nenabled = false;\n" {
		t.Fatalf("off: %q %v", off["fuzzy_check.conf"], err)
	}
	on, err := RenderRspamd(learningSettings())
	if err != nil || on["fuzzy_check.conf"] != ManagedHeader+"\nenabled = true;\n" {
		t.Fatalf("on: %q %v", on["fuzzy_check.conf"], err)
	}
}

func TestManagedContentGenerationChangesWithKeys(t *testing.T) {
	s := learningSettings()
	a, err := ManagedContent(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range LearningPaths() {
		if _, ok := a[p]; !ok {
			t.Fatalf("managed content lacks %s", p)
		}
	}
	s.LearningKeys.Write = Keypair{Public: syntheticBase32(9), Private: NewSecret(syntheticBase32(10))}
	b, err := ManagedContent(s)
	if err != nil {
		t.Fatal(err)
	}
	if Generation(a) == Generation(b) {
		t.Fatal("a new keypair kept the install generation")
	}
	off, err := ManagedContent(defaults(true))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range LearningPaths() {
		if _, ok := off[p]; ok {
			t.Fatalf("learning off still manages %s", p)
		}
	}
}
