package txn

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/antispam"
)

func txnBase32(seed int) string {
	const alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"
	var b strings.Builder
	for i := 0; i < 52; i++ {
		b.WriteByte(alphabet[(i*3+seed*7)%len(alphabet)])
	}
	return b.String()
}

func txnLearningKeys() antispam.LearningKeys {
	return antispam.LearningKeys{
		Fuzzy:    antispam.NewSecret(strings.Repeat("4d", 32)),
		Shingles: antispam.NewSecret(strings.Repeat("5e", 32)),
		Read:     antispam.Keypair{Public: txnBase32(1), Private: antispam.NewSecret(txnBase32(2))},
		Write:    antispam.Keypair{Public: txnBase32(3), Private: antispam.NewSecret(txnBase32(4))},
		Prefix:   "csmfz_" + strings.Repeat("6f", 16),
	}
}

// learningApply sets f up for an apply with learning on.
func learningApply(f *fakeHost) antispam.Settings {
	f.learning = txnLearningKeys()
	s := enforce()
	s.Learning, s.LearningDir = true, antispam.DefaultLearningDir
	return s
}

func targetChange(p string, kind antispam.TargetKind) change {
	return change{target: antispam.TargetFacts{Target: antispam.Target{Path: p, Kind: kind}}, next: fileState{exists: true, content: "x"}}
}

func TestSplitRoutesRoundcubeWithoutReload(t *testing.T) {
	rspamd, exim, roundcube := split([]change{targetChange(antispam.RoundcubeIncludePath, antispam.TargetRoundcube)})
	if len(rspamd) != 0 || len(exim) != 0 || len(roundcube) != 1 {
		t.Fatalf("rspamd=%d exim=%d roundcube=%d", len(rspamd), len(exim), len(roundcube))
	}
}

func TestSplitRoutesLuaWithRspamdReload(t *testing.T) {
	rspamd, exim, roundcube := split([]change{targetChange(antispam.LearningLuaPath, antispam.TargetLuaOptional)})
	if len(rspamd) != 1 || len(exim) != 0 || len(roundcube) != 0 {
		t.Fatalf("rspamd=%d exim=%d roundcube=%d", len(rspamd), len(exim), len(roundcube))
	}
}

func TestApplyWritesLearningSecretsPrivate(t *testing.T) {
	f := newFake(t)
	s := learningApply(f)
	wantOK(t, f.host().Apply(s))
	for _, p := range []string{antispam.LearningCheckPath, antispam.LearningWorkerPath} {
		st, err := readFile(f.root + p)
		if err != nil || !st.exists || st.perm != antispam.SecretFileMode || st.gid != os.Getgid() {
			t.Fatalf("%s: %v exists=%v perm=%v gid=%d", p, err, st.exists, st.perm, st.gid)
		}
		if !strings.Contains(st.content, f.learning.Read.Public) {
			t.Fatalf("%s lacks the rendered key", p)
		}
	}
	for _, p := range []string{antispam.LearningGroupPath, antispam.LearningLuaPath} {
		if st, err := readFile(f.root + p); err != nil || !st.exists || st.perm != 0o644 {
			t.Fatalf("%s: %v exists=%v perm=%v", p, err, st.exists, st.perm)
		}
	}
	if got := f.file(antispam.RspamdLocalDir + "/fuzzy_check.conf"); got != antispam.ManagedHeader+"\nenabled = true;\n" {
		t.Fatalf("core fuzzy_check.conf = %q", got)
	}
	// A loosened secret file is repaired without a content change.
	if err := os.Chmod(f.root+antispam.LearningWorkerPath, 0o644); err != nil {
		t.Fatal(err)
	}
	f.reset()
	wantOK(t, f.host().Apply(s))
	if st, _ := readFile(f.root + antispam.LearningWorkerPath); st.perm != antispam.SecretFileMode {
		t.Fatalf("loosened worker file not repaired: %v", st.perm)
	}
}

func TestLearningTogglesLeaveEximAlone(t *testing.T) {
	f := newFake(t)
	wantOK(t, f.host().Apply(enforce()))
	for _, on := range []bool{true, false} {
		f.reset()
		s := enforce()
		if on {
			s = learningApply(f)
		}
		wantOK(t, f.host().Apply(s))
		if f.count(BuildEximConf) != 0 || f.count("systemctl reload exim.service") != 0 ||
			f.count("systemctl reload rspamd.service") != 1 {
			t.Fatalf("on=%t: learning toggle did not reload only rspamd: %v", on, f.calls)
		}
	}
	for _, p := range antispam.LearningPaths() {
		if st, _ := readFile(f.root + p); st.exists {
			t.Fatalf("%s left after learning off", p)
		}
	}
}

func TestApplyRefusesUnreadableLearningKeys(t *testing.T) {
	f := newFake(t)
	s := learningApply(f)
	f.learning, f.learningErr = antispam.LearningKeys{}, errors.New("learning key prefix: is missing")
	before := f.state()
	r := f.host().Apply(s)
	if r.OK || r.FailedStep != StepPreconditions || len(f.calls) != 0 || !maps.Equal(before, f.state()) {
		t.Fatalf("unreadable keys: %+v calls=%v", r, f.calls)
	}
}

func TestRemoveDeletesLearningFiles(t *testing.T) {
	f := newFake(t)
	wantOK(t, f.host().Apply(learningApply(f)))
	writeTest(t, f.root+antispam.RoundcubeIncludePath, "<?php\n"+antispam.ManagedHeader+"\n$config['junk_mbox'] = 'INBOX.spam';\n", 0o644)
	f.reset()
	wantOK(t, f.host().Remove())
	for _, p := range append(antispam.LearningPaths(), antispam.RoundcubeIncludePath) {
		if st, _ := readFile(f.root + p); st.exists {
			t.Fatalf("%s left after remove", p)
		}
	}
}

func TestRemoveLeavesForeignRoundcubeFile(t *testing.T) {
	f := newFake(t)
	wantOK(t, f.host().Apply(enforce()))
	foreign := "<?php\n$config['junk_mbox'] = 'Junk';\n"
	writeTest(t, f.root+antispam.RoundcubeIncludePath, foreign, 0o644)
	f.reset()
	wantOK(t, f.host().Remove())
	if got := f.file(antispam.RoundcubeIncludePath); got != foreign {
		t.Fatalf("foreign include changed: %q", got)
	}
}

const fakeControllerSocket = "/run/rspamd/csm-controller.sock"

// fakeLoaded is what rspamd would load from the files on disk, in the shapes
// rspamd 4.2.2 printed on the scratch host.
type fakeLoaded struct{ fuzzyCheck, worker, group, symbols string }

func (f *fakeHost) loaded() fakeLoaded {
	weight := f.spamWeight
	if weight == 0 {
		weight = 10
	}
	symbols := fmt.Sprintf(`[{"group":"fuzzy","rules":[{"symbol":"CSM_FUZZY_SPAM","weight":%v},{"symbol":"CSM_FUZZY_LEARN","weight":0}]}]`, weight)
	if st, _ := readFile(f.root + antispam.LearningCheckPath); !st.exists {
		return fakeLoaded{fuzzyCheck: `{"rule":{"rspamd.com":{}}}`, worker: `[{"fuzzy":{"count":-1}}]`, group: `{"fuzzy":{"max_score":12.0}}`, symbols: `[]`}
	}
	k := f.learning
	rule := func(extra string) string {
		return fmt.Sprintf(`{"servers":"127.0.0.1:11335","fuzzy_key":%q,"fuzzy_shingles_key":%q,"read_encryption_key":%q,`+
			`"skip_unknown":true,"max_score":18.0,"min_length":32,"text_hashes":true,"text_shingles":true,"html_shingles":false,`+
			`"skip_images":true,"mime_types":[],"scan_archives":false,%s}`, k.Fuzzy.Reveal(), k.Shingles.Reveal(), k.Read.Public, extra)
	}
	return fakeLoaded{
		fuzzyCheck: `{"enabled":true,"rule":[{"csm":` + rule(`"read_only":true,"fuzzy_map":{"CSM_FUZZY_SPAM":{"flag":1,"max_score":18.0}}`) + `},` +
			`{"csm_learn":` + rule(fmt.Sprintf(`"mode":"write_only","retransmits":0,"write_encryption_key":%q,"fuzzy_map":{"CSM_FUZZY_LEARN":{"flag":1,"max_score":18.0}}`, k.Write.Public)) + `}]}`,
		worker: fmt.Sprintf(`[{"fuzzy":{"allow_update":[],"backend":"redis","bind_socket":"127.0.0.1:11335","count":1,"encrypted_only":true,`+
			`"expire":7776000.0,"prefix":%q,"keypair":[{"extensions":{"allowed_ops":["read"]},"privkey":%q,"pubkey":%q},`+
			`{"extensions":{"allowed_ops":["read","write","delete"]},"privkey":%q,"pubkey":%q}]}}]`,
			k.Prefix, k.Read.Private.Reveal(), k.Read.Public, k.Write.Private.Reveal(), k.Write.Public),
		group:   `{"headers":{"max_score":8.0}}` + "\n" + `{"fuzzy":{"max_score":10.0,"symbols":{"CSM_FUZZY_SPAM":{"weight":10.0},"CSM_FUZZY_LEARN":{"weight":0.0}}}}`,
		symbols: symbols,
	}
}

func TestApplyLearningCheckRollsBack(t *testing.T) {
	f := newFake(t)
	wantOK(t, f.host().Apply(enforce()))
	before := f.state()
	f.reset()
	s := learningApply(f)
	// A dynamic /savesymbols override changed the effective weight.
	f.spamWeight = 20
	r := f.host().Apply(s)
	if r.OK || r.FailedStep != antispam.LearningCheckStep || r.Rollback != antispam.RollbackVerified {
		t.Fatalf("result = %+v", r)
	}
	if !maps.Equal(before, f.state()) {
		t.Fatal("learning check failure left files changed")
	}
	for _, secret := range []string{f.learning.Fuzzy.Reveal(), f.learning.Write.Private.Reveal()} {
		if strings.Contains(r.Error, secret) {
			t.Fatal("result carries a key")
		}
	}
	if f.count(BuildEximConf) != 0 {
		t.Fatal("a learning check failure rebuilt Exim")
	}
}

func TestApplyLearningNeedsPrivateController(t *testing.T) {
	f := newFake(t)
	s := learningApply(f)
	h := f.host()
	preflight := h.preflight
	h.preflight = func(ctx context.Context, s antispam.Settings) (antispam.HostFacts, []antispam.Problem) {
		facts, problems := preflight(ctx, s)
		facts.Controller.Listeners = nil
		return facts, problems
	}
	if r := h.Apply(s); r.OK || r.FailedStep != antispam.LearningCheckStep {
		t.Fatalf("result = %+v", r)
	}
}
