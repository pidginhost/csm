package hostfacts

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
)

// keyOwner is the uid every key file and the keys directory must have.
// Tests set it to their own uid.
var keyOwner = 0

// maxLearningKeyBytes bounds one key file read.
const maxLearningKeyBytes = 4 << 10

var (
	hashKeyPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	prefixPattern  = regexp.MustCompile(`^csmfz_[0-9a-f]{32}$`)
)

// storedKeypair is a keypair file: the two keys `rspamadm keypair -j` printed.
type storedKeypair struct {
	Pubkey  string `json:"pubkey"`
	Privkey string `json:"privkey"`
}

// LoadLearningKeys reads and checks the key set under dir/keys: the
// directory must be root's, mode 0700 and not a link; every file root's,
// regular, mode 0600 and small. Errors name the file and the rule, never
// the content.
func LoadLearningKeys(dir string) (antispam.LearningKeys, error) {
	var k antispam.LearningKeys
	if err := checkKeysDir(filepath.Join(dir, "keys")); err != nil {
		return k, err
	}
	paths := antispam.LearningKeyPaths(dir)
	values := make(map[string]string, len(paths))
	for _, name := range antispam.LearningKeyNames {
		data, err := readKeyFile(paths[name])
		if err != nil {
			return antispam.LearningKeys{}, fmt.Errorf("learning key %s: %w", name, err)
		}
		values[name] = strings.TrimSuffix(data, "\n")
	}
	if !hashKeyPattern.MatchString(values[antispam.KeyFuzzy]) {
		return antispam.LearningKeys{}, errors.New("learning key fuzzy.key is not 64 lowercase hex characters")
	}
	if !hashKeyPattern.MatchString(values[antispam.KeyShingles]) {
		return antispam.LearningKeys{}, errors.New("learning key shingles.key is not 64 lowercase hex characters")
	}
	if !prefixPattern.MatchString(values[antispam.KeyPrefix]) {
		return antispam.LearningKeys{}, errors.New("learning key prefix is not csmfz_ and 32 lowercase hex characters")
	}
	k.Fuzzy = antispam.NewSecret(values[antispam.KeyFuzzy])
	k.Shingles = antispam.NewSecret(values[antispam.KeyShingles])
	k.Prefix = values[antispam.KeyPrefix]
	var err error
	if k.Read, err = parseStoredKeypair(values[antispam.KeyRead]); err != nil {
		return antispam.LearningKeys{}, fmt.Errorf("learning key read.keypair: %w", err)
	}
	if k.Write, err = parseStoredKeypair(values[antispam.KeyWrite]); err != nil {
		return antispam.LearningKeys{}, fmt.Errorf("learning key write.keypair: %w", err)
	}
	return k, nil
}

func checkKeysDir(p string) error {
	info, err := os.Lstat(p)
	switch {
	case err != nil:
		return errors.New("learning keys directory cannot be read")
	case !info.IsDir():
		return errors.New("learning keys directory is not a directory")
	case info.Mode().Perm() != 0o700:
		return errors.New("learning keys directory is not mode 700")
	case fileUID(info) != keyOwner:
		return errors.New("learning keys directory is not owned by root")
	}
	return nil
}

func readKeyFile(p string) (string, error) {
	// #nosec G304 -- a fixed name under CSM's learning keys directory, opened without following a final link.
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", errors.New("is missing")
		}
		return "", errors.New("cannot be opened as a regular file")
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	switch {
	case err != nil:
		return "", errors.New("cannot be read")
	case !info.Mode().IsRegular():
		return "", errors.New("is not a regular file")
	case info.Mode().Perm() != 0o600:
		return "", errors.New("is not mode 600")
	case fileUID(info) != keyOwner:
		return "", errors.New("is not owned by root")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxLearningKeyBytes+1))
	switch {
	case err != nil:
		return "", errors.New("cannot be read")
	case len(data) > maxLearningKeyBytes:
		return "", errors.New("is larger than a key file")
	}
	return string(data), nil
}

func fileUID(info fs.FileInfo) int {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid)
	}
	return -1
}

func parseStoredKeypair(data string) (antispam.Keypair, error) {
	var stored storedKeypair
	decoder := json.NewDecoder(strings.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&stored) != nil || decoder.More() {
		return antispam.Keypair{}, errors.New("is not a keypair object")
	}
	kp := antispam.Keypair{Public: stored.Pubkey, Private: antispam.NewSecret(stored.Privkey)}
	if err := kp.Validate(); err != nil {
		return antispam.Keypair{}, err
	}
	return kp, nil
}

// NewFuzzyKeypair runs `rspamadm keypair -j` and returns its keypair.
// rspamd prints it either wrapped in a "keypair" object or bare.
func NewFuzzyKeypair(ctx context.Context, run func(context.Context, time.Duration, string, ...string) antispam.CommandResult) (antispam.Keypair, error) {
	res := run(ctx, commandTimeout, "rspamadm", "keypair", "-j")
	if res.Err != nil {
		return antispam.Keypair{}, errors.New("rspamadm keypair failed")
	}
	var out struct {
		Keypair *storedKeypair `json:"keypair"`
		storedKeypair
	}
	if json.Unmarshal([]byte(res.Stdout), &out) != nil {
		return antispam.Keypair{}, errors.New("rspamadm keypair printed no JSON keypair")
	}
	stored := out.storedKeypair
	if out.Keypair != nil {
		stored = *out.Keypair
	}
	kp := antispam.Keypair{Public: stored.Pubkey, Private: antispam.NewSecret(stored.Privkey)}
	if err := kp.Validate(); err != nil {
		return antispam.Keypair{}, fmt.Errorf("rspamadm keypair: %w", err)
	}
	return kp, nil
}

// EnsureLearningKeys creates the key set under dir/keys once. An existing
// complete set is checked and kept; a partial set is an error and nothing is
// written, because new keys would silently orphan every published hash.
func EnsureLearningKeys(ctx context.Context, dir string, newKeypair func(context.Context) (antispam.Keypair, error), rnd io.Reader) (bool, error) {
	keysDir := filepath.Join(dir, "keys")
	paths := antispam.LearningKeyPaths(dir)
	var present, missing []string
	for _, name := range antispam.LearningKeyNames {
		if _, statErr := os.Lstat(paths[name]); statErr == nil {
			present = append(present, name)
		} else if errors.Is(statErr, fs.ErrNotExist) {
			missing = append(missing, name)
		} else {
			return false, fmt.Errorf("learning key %s cannot be checked", name)
		}
	}
	switch {
	case len(missing) == 0:
		_, err := LoadLearningKeys(dir)
		return false, err
	case len(present) > 0:
		return false, fmt.Errorf("learning keys are incomplete: missing %s; CSM never regenerates part of a key set", strings.Join(missing, ", "))
	}
	// #nosec G301 -- the antispam state directory; the learning and keys directories below it are checked 0700.
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return false, fmt.Errorf("cannot create %s", filepath.Dir(dir))
	}
	if err := ensurePrivateDir(dir); err != nil {
		return false, err
	}
	if err := ensurePrivateDir(keysDir); err != nil {
		return false, err
	}
	var err error
	values := make(map[string]string, len(paths))
	for _, name := range []string{antispam.KeyFuzzy, antispam.KeyShingles} {
		if values[name], err = randomHex(rnd, 32); err != nil {
			return false, err
		}
	}
	prefix, err := randomHex(rnd, 16)
	if err != nil {
		return false, err
	}
	values[antispam.KeyPrefix] = "csmfz_" + prefix
	for _, name := range []string{antispam.KeyRead, antispam.KeyWrite} {
		kp, kpErr := newKeypair(ctx)
		if kpErr != nil {
			return false, kpErr
		}
		data, _ := json.Marshal(storedKeypair{Pubkey: kp.Public, Privkey: kp.Private.Reveal()})
		values[name] = string(data)
	}
	if values[antispam.KeyRead] == values[antispam.KeyWrite] {
		return false, errors.New("rspamadm keypair returned the same keypair twice")
	}
	for _, name := range antispam.LearningKeyNames {
		if err = writeNewKeyFile(paths[name], values[name]+"\n"); err != nil {
			return false, fmt.Errorf("learning key %s: %w", name, err)
		}
	}
	if err = syncDir(keysDir); err != nil {
		return false, err
	}
	if _, err = LoadLearningKeys(dir); err != nil {
		return false, err
	}
	return true, nil
}

func randomHex(rnd io.Reader, n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rnd, b); err != nil {
		return "", errors.New("cannot read random bytes for learning keys")
	}
	return hex.EncodeToString(b), nil
}

// ensurePrivateDir creates p as a 0700 directory, or checks an existing one
// is a real directory owned by the key owner and closed to others.
func ensurePrivateDir(p string) error {
	if err := os.Mkdir(p, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("cannot create %s", p)
	}
	info, err := os.Lstat(p)
	switch {
	case err != nil:
		return fmt.Errorf("cannot check %s", p)
	case !info.IsDir():
		return fmt.Errorf("%s is not a directory", p)
	case fileUID(info) != keyOwner:
		return fmt.Errorf("%s is not owned by root", p)
	case info.Mode().Perm()&0o077 != 0:
		return fmt.Errorf("%s is open to group or others", p)
	}
	return nil
}

func writeNewKeyFile(p, content string) error {
	// #nosec G304 -- a fixed name under CSM's learning keys directory; O_EXCL refuses an existing file or link.
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return errors.New("cannot be created")
	}
	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		return errors.New("cannot be written")
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return errors.New("cannot be synced")
	}
	if err := f.Close(); err != nil {
		return errors.New("cannot be closed")
	}
	return nil
}

func syncDir(p string) error {
	// #nosec G304 -- CSM's learning keys directory.
	d, err := os.Open(p)
	if err != nil {
		return fmt.Errorf("cannot open %s to sync it", p)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("cannot sync %s", p)
	}
	return nil
}
