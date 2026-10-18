package hostfacts

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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

func TestLoadLearningKeysRejectsRelativeSymlink(t *testing.T) {
	dir := newKeySet(t)
	p := antispam.LearningKeyPaths(dir)[antispam.KeyFuzzy]
	if err := os.Rename(p, p+"-saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(antispam.KeyFuzzy+"-saved", p); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLearningKeys(dir); err == nil || !strings.Contains(err.Error(), antispam.KeyFuzzy) {
		t.Fatal("relative key symlink accepted")
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
			t.Fatal("invalid command output accepted or exposed in error")
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

func TestStoredKeypairRejectsTrailingData(t *testing.T) {
	data, err := json.Marshal(storedKeypair{Pubkey: base32Key(1), Privkey: base32Key(2)})
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"}", "]", "\n}", "\n]", "{}", "null", "garbage"} {
		if _, err := parseStoredKeypair(string(data) + suffix); err == nil {
			t.Errorf("accepted trailing %q", suffix)
		}
	}
	if _, err := parseStoredKeypair(string(data) + "\n\t "); err != nil {
		t.Fatal("rejected trailing JSON whitespace")
	}
}

func TestEnsureLearningKeysRejectsInvalidGenerationBeforeWriting(t *testing.T) {
	for _, invalidCall := range []int{1, 2} {
		t.Run(strconv.Itoa(invalidCall), func(t *testing.T) {
			ownKeys(t)
			dir := filepath.Join(t.TempDir(), "learning")
			next := fakeKeypairs()
			calls := 0
			generate := func(ctx context.Context) (antispam.Keypair, error) {
				calls++
				kp, err := next(ctx)
				if calls == invalidCall {
					kp.Private = antispam.Secret{}
				}
				return kp, err
			}
			created, err := EnsureLearningKeys(context.Background(), dir, generate, rand.Reader)
			if err == nil || created {
				t.Fatal("invalid generated keypair accepted")
			}
			assertNoLearningKeyFiles(t, dir)
		})
	}
}

func assertNoLearningKeyFiles(t *testing.T, dir string) {
	t.Helper()
	for name, p := range antispam.LearningKeyPaths(dir) {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s exists after rejected generation", name)
		}
	}
}

func TestEnsureLearningKeysRedactsGeneratorError(t *testing.T) {
	ownKeys(t)
	dir := filepath.Join(t.TempDir(), "learning")
	secret := base32Key(1)
	generate := func(context.Context) (antispam.Keypair, error) {
		return antispam.Keypair{}, errors.New("failed: " + secret)
	}
	created, err := EnsureLearningKeys(context.Background(), dir, generate, rand.Reader)
	if err == nil || created {
		t.Fatal("failed key generation accepted")
	}
	if strings.Contains(err.Error(), secret) {
		t.Error("generator error exposed key material")
	}
	assertNoLearningKeyFiles(t, dir)
}

func TestLearningKeysRejectSharedTransportCredentials(t *testing.T) {
	for _, half := range []string{"public", "private", "both"} {
		t.Run(half, func(t *testing.T) {
			ownKeys(t)
			ctx := context.Background()
			next := fakeKeypairs()
			read, _ := next(ctx)
			write, _ := next(ctx)
			if half == "public" || half == "both" {
				write.Public = read.Public
			}
			if half == "private" || half == "both" {
				write.Private = read.Private
			}
			dir := filepath.Join(t.TempDir(), "learning")
			calls := 0
			generate := func(context.Context) (antispam.Keypair, error) {
				calls++
				if calls == 1 {
					return read, nil
				}
				return write, nil
			}
			if created, err := EnsureLearningKeys(ctx, dir, generate, rand.Reader); err == nil || created {
				t.Error("shared transport credential generated")
			}
			assertNoLearningKeyFiles(t, dir)

			existing := newKeySet(t)
			paths := antispam.LearningKeyPaths(existing)
			for name, kp := range map[string]antispam.Keypair{antispam.KeyRead: read, antispam.KeyWrite: write} {
				data, err := json.Marshal(storedKeypair{Pubkey: kp.Public, Privkey: kp.Private.Reveal()})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(paths[name], data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			before := readKeyFiles(t, existing)
			if _, err := LoadLearningKeys(existing); err == nil {
				t.Error("shared transport credential loaded")
			}
			if created, err := EnsureLearningKeys(ctx, existing, fakeKeypairs(), rand.Reader); err == nil || created {
				t.Error("shared stored transport credential accepted")
			}
			for name, after := range readKeyFiles(t, existing) {
				if !bytes.Equal(before[name], after) {
					t.Errorf("rejected set changed %s", name)
				}
			}
		})
	}
}

func TestLoadLearningKeysRejectsUnsafeLearningDirectory(t *testing.T) {
	for _, kind := range []string{"writable", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := newKeySet(t)
			if kind == "writable" {
				if err := os.Chmod(dir, 0o770); err != nil {
					t.Fatal(err)
				}
			} else {
				link := filepath.Join(t.TempDir(), "learning")
				if err := os.Symlink(dir, link); err != nil {
					t.Fatal(err)
				}
				dir = link
			}
			if _, err := LoadLearningKeys(dir); err == nil {
				t.Error("unsafe learning directory loaded")
			}
			if created, err := EnsureLearningKeys(context.Background(), dir, fakeKeypairs(), rand.Reader); err == nil || created {
				t.Error("unsafe existing learning directory accepted")
			}
		})
	}
}

func TestEnsureLearningKeysChecksExactDirectoryModeBeforeGeneration(t *testing.T) {
	ownKeys(t)
	dir := filepath.Join(t.TempDir(), "learning")
	keysDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keysDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(keysDir, 0o700) })
	calls := 0
	next := fakeKeypairs()
	generate := func(ctx context.Context) (antispam.Keypair, error) {
		calls++
		return next(ctx)
	}
	if created, err := EnsureLearningKeys(context.Background(), dir, generate, rand.Reader); err == nil || created {
		t.Error("incorrect keys directory mode accepted")
	}
	if calls != 0 {
		t.Error("generated credentials before rejecting the directory mode")
	}
	assertNoLearningKeyFiles(t, dir)
}

func TestEnsureLearningKeysDoesNotFollowReplacedKeysDirectory(t *testing.T) {
	ownKeys(t)
	dir := filepath.Join(t.TempDir(), "learning")
	keysDir := filepath.Join(dir, "keys")
	target := t.TempDir()
	next := fakeKeypairs()
	calls := 0
	generate := func(ctx context.Context) (antispam.Keypair, error) {
		calls++
		if calls == 1 {
			if err := os.Rename(keysDir, keysDir+"-saved"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, keysDir); err != nil {
				t.Fatal(err)
			}
		}
		return next(ctx)
	}
	if created, err := EnsureLearningKeys(context.Background(), dir, generate, rand.Reader); err == nil || created {
		t.Error("replaced keys directory accepted")
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("key material written through a replaced keys directory")
	}
}

func TestEnsureLearningKeysKeepsPartialWriteWithoutPrefix(t *testing.T) {
	ownKeys(t)
	dir := filepath.Join(t.TempDir(), "learning")
	paths := antispam.LearningKeyPaths(dir)
	next := fakeKeypairs()
	calls := 0
	generate := func(ctx context.Context) (antispam.Keypair, error) {
		calls++
		if calls == 1 {
			if err := os.Mkdir(paths[antispam.KeyWrite], 0o700); err != nil {
				t.Fatal(err)
			}
		}
		return next(ctx)
	}
	created, err := EnsureLearningKeys(context.Background(), dir, generate, rand.Reader)
	if err == nil || created || !strings.Contains(err.Error(), antispam.KeyWrite) {
		t.Fatal("write conflict did not stop key creation")
	}
	if _, statErr := os.Lstat(paths[antispam.KeyPrefix]); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("prefix written before completing the key set")
	}
	before := map[string][]byte{}
	for _, name := range []string{antispam.KeyFuzzy, antispam.KeyShingles, antispam.KeyRead} {
		data, readErr := os.ReadFile(paths[name])
		if readErr != nil {
			t.Fatal(readErr)
		}
		before[name] = data
	}
	created, err = EnsureLearningKeys(context.Background(), dir, generate, rand.Reader)
	if err == nil || created || !strings.Contains(err.Error(), "incomplete") || calls != 2 {
		t.Fatal("partial set was not refused before generation")
	}
	for name, want := range before {
		got, err := os.ReadFile(paths[name])
		if err != nil || !bytes.Equal(want, got) {
			t.Errorf("partial set changed %s", name)
		}
	}
}
