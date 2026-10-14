package integrity

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pidginhost/csm/internal/config"
)

// The per-fragment record sits beside the main config instead of inside its
// integrity block: the config loader rejects unknown keys, so a new key there
// would stop an older binary from starting after a downgrade.
const fragmentRecordSuffix = ".confd-fragments.json"

// ErrNoFragmentBaseline means no per-fragment record matches the signed
// conf.d state, so a scoped rehash cannot tell which fragments changed. A
// full `csm rehash` signs the current state and records one.
var ErrNoFragmentBaseline = errors.New("no per-fragment conf.d record matches the signed state")

// UnnamedChangesError refuses a scoped rehash because something other than
// the named fragments changed since the last signed state.
type UnnamedChangesError struct {
	Changed []string
}

func (e *UnnamedChangesError) Error() string {
	return "changed besides the named fragments: " + strings.Join(e.Changed, ", ")
}

// The original bytes are needed to recompute the signed aggregate digest:
// independent per-file hashes cannot prove membership in that digest. Like
// the main config and its backup, this record can contain credentials and
// must stay private to the daemon user.
type fragmentRecord struct {
	ConfdHash string            `json:"confd_hash"`
	Fragments map[string][]byte `json:"fragments"`
}

// FragmentRecordPath is where the per-fragment record for configPath lives:
// beside the resolved main config, so a legacy symlinked path and its target
// share one record.
func FragmentRecordPath(configPath string) (string, error) {
	target, err := atomicWriteTarget(configPath)
	if err != nil {
		return "", err
	}
	return target + fragmentRecordSuffix, nil
}

func writeFragmentRecord(configPath, confdHash string, contents map[string][]byte) error {
	path, err := FragmentRecordPath(configPath)
	if err != nil {
		return err
	}
	data, err := json.Marshal(fragmentRecord{ConfdHash: confdHash, Fragments: contents})
	if err != nil {
		return fmt.Errorf("encoding conf.d fragment record: %w", err)
	}
	if err := atomicWriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing conf.d fragment record: %w", err)
	}
	return nil
}

func readFragmentRecord(configPath string) (fragmentRecord, error) {
	var rec fragmentRecord
	path, err := FragmentRecordPath(configPath)
	if err != nil {
		return rec, err
	}
	data, err := os.ReadFile(path) // #nosec G304 -- derived from the operator-configured config path.
	if errors.Is(err, os.ErrNotExist) {
		return rec, ErrNoFragmentBaseline
	}
	if err != nil {
		return rec, fmt.Errorf("reading conf.d fragment record: %w", err)
	}
	rec, err = decodeFragmentRecord(data)
	if err != nil {
		return rec, fmt.Errorf("decoding conf.d fragment record %s: %w", path, err)
	}
	return rec, nil
}

func decodeFragmentRecord(data []byte) (fragmentRecord, error) {
	var wire struct {
		ConfdHash *string           `json:"confd_hash"`
		Fragments map[string][]byte `json:"fragments"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return fragmentRecord{}, err
	}
	if wire.ConfdHash == nil {
		return fragmentRecord{}, errors.New("missing conf.d digest")
	}
	rec := fragmentRecord{ConfdHash: *wire.ConfdHash, Fragments: wire.Fragments}
	return rec, rec.validate()
}

func (rec fragmentRecord) validate() error {
	if rec.Fragments == nil {
		return errors.New("missing fragments")
	}
	frags := make([]config.ConfDirFragment, 0, len(rec.Fragments))
	for _, name := range fragmentNames(rec.Fragments, nil) {
		if !validFragmentName(name) || len(rec.Fragments[name]) == 0 {
			return fmt.Errorf("invalid fragment %q", name)
		}
		frags = append(frags, config.ConfDirFragment{Name: name, Data: rec.Fragments[name]})
	}
	digest, _ := confdSnapshot(frags, nil)
	if digest != rec.ConfdHash {
		return errors.New("fragment contents do not match the recorded digest")
	}
	return nil
}

// RecordVerifiedConfD records the covered bytes of a conf.d state the
// caller just verified, so hosts signed before records existed get one
// without a rehash. It re-reads the fragments and records nothing unless they
// still hash to the signed digest. A config that was never signed has
// nothing verified to record.
func RecordVerifiedConfD(cfg *config.Config) error {
	if cfg.Integrity.BinaryHash == "" || cfg.Integrity.ConfigHash == "" {
		return nil
	}
	frags, err := config.ConfDirFragmentDigestInput(cfg.ConfigDir)
	if err != nil {
		return fmt.Errorf("hashing conf.d: %w", err)
	}
	digest, contents := confdSnapshot(frags, cfg.ConfD.IntegrityExempt)
	if digest != cfg.Integrity.ConfdHash {
		return fmt.Errorf("%w: conf.d changed after verification", ErrConfdHashMismatch)
	}
	if rec, readErr := readFragmentRecord(cfg.ConfigFile); readErr == nil && rec.ConfdHash == digest {
		return nil
	}
	return writeFragmentRecord(cfg.ConfigFile, digest, contents)
}

// RehashFragments re-signs conf.d after an integration rewrote the named
// fragments (bare file names in confDir). It refuses with an
// UnnamedChangesError when anything else differs from the last signed state:
// the binary, the main config, or any other covered fragment added, removed
// or edited. A named fragment may be new, edited or deleted; one that exists
// neither on disk nor in the record is an error. Fragments under
// confd.integrity_exempt stay outside the signed state either way. Without a
// record matching the signed state it returns ErrNoFragmentBaseline.
func RehashFragments(binaryPath, configPath, confDir string, names []string) error {
	if len(names) == 0 {
		return errors.New("name at least one conf.d fragment")
	}
	named := make(map[string]bool, len(names))
	for _, name := range names {
		if !validFragmentName(name) {
			return fmt.Errorf("invalid fragment name %q: give the bare .yaml or .yml file name inside the conf.d directory", name)
		}
		named[name] = true
	}

	data, err := os.ReadFile(configPath) // #nosec G304 -- operator-configured config path.
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	cfg, err := config.LoadBytes(data)
	if err != nil {
		return err
	}
	cfg.ConfigFile, cfg.ConfigDir = configPath, confDir
	if cfg.Integrity.BinaryHash == "" || cfg.Integrity.ConfigHash == "" {
		return fmt.Errorf("%w: the config has never been signed", ErrNoFragmentBaseline)
	}
	rec, err := readFragmentRecord(configPath)
	if err != nil {
		return err
	}
	if rec.ConfdHash != cfg.Integrity.ConfdHash {
		return fmt.Errorf("%w: the record belongs to another signed state", ErrNoFragmentBaseline)
	}
	exempt := cfg.ConfD.IntegrityExempt
	for name := range named {
		if _, recorded := rec.Fragments[name]; recorded || isExemptFragment(name, exempt) {
			continue
		}
		_, statErr := os.Lstat(filepath.Join(confDir, name))
		if errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("fragment %s does not exist in %s and is not part of the signed state", name, confDir)
		}
		if statErr != nil {
			return fmt.Errorf("fragment %s: %w", name, statErr)
		}
	}

	var changed []string
	binaryHash, err := HashFile(binaryPath)
	if err != nil {
		return fmt.Errorf("hashing binary: %w", err)
	}
	if binaryHash != cfg.Integrity.BinaryHash {
		changed = append(changed, "binary "+binaryPath)
	}
	if HashConfigStableBytes(data) != cfg.Integrity.ConfigHash {
		changed = append(changed, "main config "+configPath)
	}
	frags, err := config.ConfDirFragmentDigestInput(confDir)
	if err != nil {
		return fmt.Errorf("hashing conf.d: %w", err)
	}
	_, current := confdSnapshot(frags, exempt)
	for _, name := range fragmentNames(rec.Fragments, current) {
		if named[name] {
			continue
		}
		was, had := rec.Fragments[name]
		now, has := current[name]
		switch {
		case !had:
			changed = append(changed, "fragment "+name+" (added)")
		case !has:
			changed = append(changed, "fragment "+name+" (removed)")
		case !bytes.Equal(was, now):
			changed = append(changed, "fragment "+name+" (edited)")
		}
	}
	if len(changed) > 0 {
		return &UnnamedChangesError{Changed: changed}
	}
	return signAndSavePreserving(configPath, confDir, data, cfg, cfg.Integrity.BinaryHash, frags)
}

// validFragmentName accepts what the conf.d loader would merge: a plain
// .yaml or .yml file name with no directory part.
func validFragmentName(name string) bool {
	// Newlines can impersonate boundaries in the legacy aggregate digest.
	return (strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")) && filepath.Base(name) == name && !strings.ContainsAny(name, "\x00\r\n")
}

func fragmentNames(a, b map[string][]byte) []string {
	names := make([]string, 0, len(a)+len(b))
	for name := range a {
		names = append(names, name)
	}
	for name := range b {
		if _, dup := a[name]; !dup {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}
