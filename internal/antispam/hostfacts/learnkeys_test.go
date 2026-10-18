package hostfacts

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
)

func ownKeys(t *testing.T) {
	t.Helper()
	prev := keyOwner
	keyOwner = os.Getuid()
	t.Cleanup(func() { keyOwner = prev })
}

func base32Key(seed int) string {
	const alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"
	var b strings.Builder
	for i := 0; i < 52; i++ {
		b.WriteByte(alphabet[(i*5+seed*11)%len(alphabet)])
	}
	return b.String()
}

func fakeKeypairs() func(context.Context) (antispam.Keypair, error) {
	seed := 0
	return func(context.Context) (antispam.Keypair, error) {
		seed += 2
		return antispam.Keypair{Public: base32Key(seed), Private: antispam.NewSecret(base32Key(seed + 1))}, nil
	}
}

func readKeyFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for name, p := range antispam.LearningKeyPaths(dir) {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out[name] = data
	}
	return out
}

func TestEnsureLearningKeysCreatesOnce(t *testing.T) {
	ownKeys(t)
	dir := filepath.Join(t.TempDir(), "learning")
	created, err := EnsureLearningKeys(context.Background(), dir, fakeKeypairs(), rand.Reader)
	if err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	info, err := os.Stat(filepath.Join(dir, "keys"))
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("keys dir: %v %v", info, err)
	}
	for name, p := range antispam.LearningKeyPaths(dir) {
		info, statErr := os.Lstat(p)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", name, info, statErr)
		}
	}
	keys, err := LoadLearningKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	if !hex64.MatchString(keys.Fuzzy.Reveal()) || !hex64.MatchString(keys.Shingles.Reveal()) || keys.Fuzzy.Reveal() == keys.Shingles.Reveal() {
		t.Fatal("hash keys are not independent 64-character lowercase hex")
	}
	if !regexp.MustCompile(`^csmfz_[0-9a-f]{32}$`).MatchString(keys.Prefix) {
		t.Fatalf("prefix %q", keys.Prefix)
	}
	if keys.Read.Public == keys.Write.Public || keys.Read.Validate() != nil || keys.Write.Validate() != nil {
		t.Fatal("keypairs not distinct and valid")
	}
	before := readKeyFiles(t, dir)
	created, err = EnsureLearningKeys(context.Background(), dir, fakeKeypairs(), rand.Reader)
	if err != nil || created {
		t.Fatalf("second call: created=%v err=%v", created, err)
	}
	after := readKeyFiles(t, dir)
	for name := range before {
		if !bytes.Equal(before[name], after[name]) {
			t.Fatalf("%s changed on the second call", name)
		}
	}
}

func TestEnsureLearningKeysRefusesPartialSet(t *testing.T) {
	ownKeys(t)
	dir := filepath.Join(t.TempDir(), "learning")
	if _, err := EnsureLearningKeys(context.Background(), dir, fakeKeypairs(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	paths := antispam.LearningKeyPaths(dir)
	if err := os.Remove(paths["write.keypair"]); err != nil {
		t.Fatal(err)
	}
	before := readKeyFilesExcept(t, dir, "write.keypair")
	old := time.Now().Add(-time.Hour)
	mtimes := map[string]time.Time{}
	for name := range before {
		if err := os.Chtimes(paths[name], old, old); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(paths[name])
		if err != nil {
			t.Fatal(err)
		}
		mtimes[name] = info.ModTime()
	}
	created, err := EnsureLearningKeys(context.Background(), dir, fakeKeypairs(), rand.Reader)
	if err == nil || created || !strings.Contains(err.Error(), "incomplete") || !strings.Contains(err.Error(), "write.keypair") {
		t.Fatalf("created=%v err=%v, want incomplete error naming write.keypair", created, err)
	}
	if _, statErr := os.Lstat(paths["write.keypair"]); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("missing keypair was regenerated")
	}
	for name, data := range before {
		got, _ := os.ReadFile(paths[name])
		info, _ := os.Stat(paths[name])
		if !bytes.Equal(got, data) || !info.ModTime().Equal(mtimes[name]) {
			t.Fatalf("%s rewritten", name)
		}
	}
}

func readKeyFilesExcept(t *testing.T, dir, skip string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for name, p := range antispam.LearningKeyPaths(dir) {
		if name == skip {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		out[name] = data
	}
	return out
}

func newKeySet(t *testing.T) string {
	t.Helper()
	ownKeys(t)
	dir := filepath.Join(t.TempDir(), "learning")
	if _, err := EnsureLearningKeys(context.Background(), dir, fakeKeypairs(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	return dir
}

func secretsIn(t *testing.T, dir string) []string {
	t.Helper()
	files := readKeyFiles(t, dir)
	var out []string
	for _, name := range []string{"fuzzy.key", "shingles.key"} {
		out = append(out, strings.TrimSpace(string(files[name])))
	}
	return out
}

func TestLoadLearningKeysRejectsLooseMode(t *testing.T) {
	dir := newKeySet(t)
	p := antispam.LearningKeyPaths(dir)["shingles.key"]
	if err := os.Chmod(p, 0o640); err != nil {
		t.Fatal(err)
	}
	_, err := LoadLearningKeys(dir)
	if err == nil || !strings.Contains(err.Error(), "shingles.key") {
		t.Fatalf("err = %v", err)
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "keys"), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLearningKeys(dir); err == nil || !strings.Contains(err.Error(), "keys") {
		t.Fatalf("loose keys dir: err = %v", err)
	}
}

func TestLoadLearningKeysRejectsSymlink(t *testing.T) {
	dir := newKeySet(t)
	p := antispam.LearningKeyPaths(dir)["fuzzy.key"]
	target := filepath.Join(t.TempDir(), "elsewhere")
	data, _ := os.ReadFile(p)
	if err := os.WriteFile(target, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLearningKeys(dir); err == nil || !strings.Contains(err.Error(), "fuzzy.key") {
		t.Fatalf("err = %v", err)
	}
	keysDir := filepath.Join(dir, "keys")
	moved := filepath.Join(t.TempDir(), "keys")
	if err := os.Rename(keysDir, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, keysDir); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLearningKeys(dir); err == nil {
		t.Fatal("symlinked keys directory accepted")
	}
}

func TestLoadLearningKeysRejectsWrongOwner(t *testing.T) {
	dir := newKeySet(t)
	keyOwner = os.Getuid() + 1
	_, err := LoadLearningKeys(dir)
	if err == nil || !strings.Contains(err.Error(), "owned") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadLearningKeysRejectsOversize(t *testing.T) {
	dir := newKeySet(t)
	p := antispam.LearningKeyPaths(dir)["prefix"]
	if err := os.WriteFile(p, bytes.Repeat([]byte("a"), 5000), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLearningKeys(dir); err == nil || !strings.Contains(err.Error(), "prefix") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadLearningKeysRejectsBadContent(t *testing.T) {
	for name, content := range map[string]string{
		"fuzzy.key":     strings.Repeat("A", 64) + "\n",
		"shingles.key":  strings.Repeat("a", 63) + "\n",
		"prefix":        "csmfz_short\n",
		"read.keypair":  `{"pubkey":"x","privkey":"y"}` + "\n",
		"write.keypair": "not json\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := newKeySet(t)
			secrets := secretsIn(t, dir)
			if err := os.WriteFile(antispam.LearningKeyPaths(dir)[name], []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadLearningKeys(dir)
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("err = %v", err)
			}
			for _, s := range append(secrets, strings.TrimSpace(content)) {
				if len(s) > 8 && strings.Contains(err.Error(), s) {
					t.Fatal("error carries file content")
				}
			}
		})
	}
}

func TestNewFuzzyKeypairParsesJSON(t *testing.T) {
	pub, priv := base32Key(1), base32Key(2)
	for _, out := range []string{
		`{"keypair":{"pubkey":"` + pub + `","privkey":"` + priv + `","id":"x","encoding":"base32","algorithm":"curve25519","type":"kex"}}`,
		`{"pubkey":"` + pub + `","privkey":"` + priv + `"}`,
	} {
		run := func(_ context.Context, _ time.Duration, name string, args ...string) antispam.CommandResult {
			if name != "rspamadm" || strings.Join(args, " ") != "keypair -j" {
				t.Fatalf("ran %s %v", name, args)
			}
			return antispam.CommandResult{Stdout: out}
		}
		kp, err := NewFuzzyKeypair(context.Background(), run)
		if err != nil || kp.Public != pub || kp.Private.Reveal() != priv {
			t.Fatalf("keypair = %+v, err = %v", kp, err)
		}
	}
	for _, out := range []string{
		`{"keypair":{"pubkey":"` + pub[:40] + `","privkey":"` + priv + `"}}`,
		`{"keypair":{"pubkey":"` + pub + `"}}`,
		`garbage ` + priv,
		``,
	} {
		run := func(context.Context, time.Duration, string, ...string) antispam.CommandResult {
			return antispam.CommandResult{Stdout: out}
		}
		_, err := NewFuzzyKeypair(context.Background(), run)
		if err == nil || strings.Contains(err.Error(), priv) {
			t.Fatalf("output %q: err = %v", out, err)
		}
	}
	failing := func(context.Context, time.Duration, string, ...string) antispam.CommandResult {
		return antispam.CommandResult{Stdout: `{"pubkey":"` + pub + `","privkey":"` + priv + `"}`, Err: errors.New("exit status 1")}
	}
	if _, err := NewFuzzyKeypair(context.Background(), failing); err == nil {
		t.Fatal("failed command accepted")
	}
}

// The antispam state directory may not exist yet on the first enable.
func TestEnsureLearningKeysCreatesMissingParent(t *testing.T) {
	ownKeys(t)
	dir := filepath.Join(t.TempDir(), "antispam", "learning")
	if created, err := EnsureLearningKeys(context.Background(), dir, fakeKeypairs(), rand.Reader); err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
}
