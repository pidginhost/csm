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
// directories must be root's, mode 0700 and not links; every file root's,
// regular, mode 0600 and small. Errors name the file and the rule, never
// the content.
func LoadLearningKeys(dir string) (antispam.LearningKeys, error) {
	keys, err := openLearningKeysDir(dir, false)
	if err != nil {
		return antispam.LearningKeys{}, err
	}
	defer func() { _ = keys.Close() }()
	return loadLearningKeys(keys)
}

func loadLearningKeys(dir *os.Root) (antispam.LearningKeys, error) {
	var k antispam.LearningKeys
	values := make(map[string]string, len(antispam.LearningKeyNames))
	for _, name := range antispam.LearningKeyNames {
		data, err := readKeyFile(dir, name)
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
	if err := distinctLearningKeypairs(k.Read, k.Write); err != nil {
		return antispam.LearningKeys{}, err
	}
	return k, nil
}

func openLearningKeysDir(dir string, create bool) (*os.Root, error) {
	if create {
		if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
			return nil, errors.New("cannot create learning parent directory")
		}
	}
	learning, err := openPrivateKeyDir(nil, dir, "learning directory", create)
	if err != nil {
		return nil, err
	}
	defer func() { _ = learning.Close() }()
	return openPrivateKeyDir(learning, "keys", "learning keys directory", create)
}

// Pin each checked directory so later I/O cannot follow a replacement link.
func openPrivateKeyDir(parent *os.Root, name, label string, create bool) (*os.Root, error) {
	mkdir, lstat, open := os.Mkdir, os.Lstat, os.OpenRoot
	if parent != nil {
		mkdir, lstat, open = parent.Mkdir, parent.Lstat, parent.OpenRoot
	}
	if create {
		if err := mkdir(name, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("cannot create %s", label)
		}
	}
	info, err := lstat(name)
	switch {
	case err != nil:
		return nil, fmt.Errorf("%s cannot be read", label)
	case !info.IsDir():
		return nil, fmt.Errorf("%s is not a directory", label)
	case info.Mode().Perm() != 0o700:
		return nil, fmt.Errorf("%s is not mode 700", label)
	case fileUID(info) != keyOwner:
		return nil, fmt.Errorf("%s is not owned by root", label)
	}
	root, err := open(name)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s", label)
	}
	current, err := root.Stat(".")
	if err != nil || !os.SameFile(info, current) {
		_ = root.Close()
		return nil, fmt.Errorf("%s changed while opening", label)
	}
	return root, nil
}

func readKeyFile(dir *os.Root, name string) (string, error) {
	entry, err := dir.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return "", errors.New("is missing")
	}
	if err != nil {
		return "", errors.New("cannot be checked")
	}
	if !entry.Mode().IsRegular() {
		return "", errors.New("is not a regular file")
	}
	// Root.OpenFile follows links within the root, even with O_NOFOLLOW.
	// Match the opened inode to the checked entry before reading any bytes.
	f, err := dir.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
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
	case !os.SameFile(entry, info):
		return "", errors.New("changed while opening")
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
	if decoder.Decode(&stored) != nil || decoder.Decode(new(any)) != io.EOF {
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
	keys, err := openLearningKeysDir(dir, true)
	if err != nil {
		return false, err
	}
	defer func() { _ = keys.Close() }()
	var present, missing []string
	for _, name := range antispam.LearningKeyNames {
		if _, statErr := keys.Lstat(name); statErr == nil {
			present = append(present, name)
		} else if errors.Is(statErr, fs.ErrNotExist) {
			missing = append(missing, name)
		} else {
			return false, fmt.Errorf("learning key %s cannot be checked", name)
		}
	}
	switch {
	case len(missing) == 0:
		_, err = loadLearningKeys(keys)
		return false, err
	case len(present) > 0:
		return false, fmt.Errorf("learning keys are incomplete: missing %s; CSM never regenerates part of a key set", strings.Join(missing, ", "))
	}
	values := make(map[string]string, len(antispam.LearningKeyNames))
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
	var read antispam.Keypair
	for _, name := range []string{antispam.KeyRead, antispam.KeyWrite} {
		kp, kpErr := newKeypair(ctx)
		if kpErr != nil {
			return false, fmt.Errorf("learning key %s: keypair generation failed", name)
		}
		if err = kp.Validate(); err != nil {
			return false, fmt.Errorf("learning key %s: %w", name, err)
		}
		if name == antispam.KeyRead {
			read = kp
		} else if err = distinctLearningKeypairs(read, kp); err != nil {
			return false, err
		}
		data, _ := json.Marshal(storedKeypair{Pubkey: kp.Public, Privkey: kp.Private.Reveal()})
		values[name] = string(data)
	}
	for _, name := range antispam.LearningKeyNames {
		if err = writeNewKeyFile(keys, name, values[name]+"\n"); err != nil {
			return false, fmt.Errorf("learning key %s: %w", name, err)
		}
	}
	if err = syncKeysDir(keys); err != nil {
		return false, err
	}
	if _, err = LoadLearningKeys(dir); err != nil {
		return false, err
	}
	return true, nil
}

func distinctLearningKeypairs(read, write antispam.Keypair) error {
	if read.Public == write.Public || read.Private.Reveal() == write.Private.Reveal() {
		return errors.New("learning read and write keypairs must be distinct")
	}
	return nil
}

func randomHex(rnd io.Reader, n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rnd, b); err != nil {
		return "", errors.New("cannot read random bytes for learning keys")
	}
	return hex.EncodeToString(b), nil
}

func writeNewKeyFile(dir *os.Root, name, content string) error {
	f, err := dir.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
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

func syncKeysDir(dir *os.Root) error {
	d, err := dir.Open(".")
	if err != nil {
		return errors.New("cannot open learning keys directory to sync it")
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return errors.New("cannot sync learning keys directory")
	}
	return nil
}
