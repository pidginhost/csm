package antispam

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// syntheticBase32 returns a 52-character string in rspamd's base32
// alphabet, distinct per seed.
func syntheticBase32(seed int) string {
	const alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"
	var b strings.Builder
	for i := 0; i < 52; i++ {
		b.WriteByte(alphabet[(i*7+seed*13)%len(alphabet)])
	}
	return b.String()
}

func syntheticLearningKeys() LearningKeys {
	return LearningKeys{
		Fuzzy:    NewSecret(strings.Repeat("1a", 32)),
		Shingles: NewSecret(strings.Repeat("2b", 32)),
		Read:     Keypair{Public: syntheticBase32(1), Private: NewSecret(syntheticBase32(2))},
		Write:    Keypair{Public: syntheticBase32(3), Private: NewSecret(syntheticBase32(4))},
		Prefix:   "csmfz_" + strings.Repeat("c3", 16),
	}
}

func TestLearningKeyPaths(t *testing.T) {
	got := LearningKeyPaths("/var/lib/csm/antispam/learning")
	want := map[string]string{
		"fuzzy.key":     "/var/lib/csm/antispam/learning/keys/fuzzy.key",
		"shingles.key":  "/var/lib/csm/antispam/learning/keys/shingles.key",
		"read.keypair":  "/var/lib/csm/antispam/learning/keys/read.keypair",
		"write.keypair": "/var/lib/csm/antispam/learning/keys/write.keypair",
		"prefix":        "/var/lib/csm/antispam/learning/keys/prefix",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("paths = %v", got)
	}
}

func TestLearningKeysNeverPrint(t *testing.T) {
	k := syntheticLearningKeys()
	secrets := []string{k.Fuzzy.Reveal(), k.Shingles.Reveal(), k.Read.Private.Reveal(), k.Write.Private.Reveal()}
	data, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	out := fmt.Sprintf("%v %+v %#v %s %q %x", k, k, k, k, k, k) + string(data)
	for _, s := range secrets {
		if strings.Contains(out, s) {
			t.Fatal("formatted keys contain a secret")
		}
	}
}

func TestHashGenerationChangesWithEitherKey(t *testing.T) {
	base := syntheticLearningKeys()
	g := HashGeneration(base)
	if len(g) != 64 || strings.Trim(g, "0123456789abcdef") != "" {
		t.Fatalf("generation %q is not hex SHA-256", g)
	}
	for name, change := range map[string]func(*LearningKeys){
		"fuzzy":    func(k *LearningKeys) { k.Fuzzy = NewSecret(strings.Repeat("9f", 32)) },
		"shingles": func(k *LearningKeys) { k.Shingles = NewSecret(strings.Repeat("9f", 32)) },
		"prefix":   func(k *LearningKeys) { k.Prefix = "csmfz_" + strings.Repeat("9f", 16) },
	} {
		k := base
		change(&k)
		if HashGeneration(k) == g {
			t.Fatalf("changing %s kept the generation", name)
		}
	}
	k := base
	k.Write = Keypair{Public: syntheticBase32(5), Private: NewSecret(syntheticBase32(6))}
	k.Read = Keypair{Public: syntheticBase32(7), Private: NewSecret(syntheticBase32(8))}
	if HashGeneration(k) != g {
		t.Fatal("changing a transport keypair changed the hash generation")
	}
	// Length prefixes keep a byte moving between fields from colliding.
	a, b := base, base
	a.Fuzzy, a.Shingles = NewSecret("ab"), NewSecret("c")
	b.Fuzzy, b.Shingles = NewSecret("a"), NewSecret("bc")
	if HashGeneration(a) == HashGeneration(b) {
		t.Fatal("field boundaries are not part of the generation")
	}
}

func TestValidKeypair(t *testing.T) {
	good := Keypair{Public: syntheticBase32(1), Private: NewSecret(syntheticBase32(2))}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, kp := range map[string]Keypair{
		"short public":    {Public: syntheticBase32(1)[:51], Private: good.Private},
		"bad alphabet":    {Public: strings.Repeat("l", 52), Private: good.Private},
		"upper case":      {Public: strings.ToUpper(syntheticBase32(1)), Private: good.Private},
		"missing private": {Public: good.Public},
		"short private":   {Public: good.Public, Private: NewSecret(syntheticBase32(2)[:40])},
	} {
		err := kp.Validate()
		if err == nil {
			t.Fatalf("%s accepted", name)
		}
		if strings.Contains(err.Error(), kp.Private.Reveal()) && kp.Private.Reveal() != "" {
			t.Fatalf("%s: error carries the private key", name)
		}
	}
}
