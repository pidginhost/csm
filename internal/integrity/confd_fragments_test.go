package integrity

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestRehashFragmentsRejectsCorruptRecords(t *testing.T) {
	for _, body := range []string{"null", "{}", `{"fragments":{}}`, `{"confd_hash":"invalid","fragments":{}}`} {
		t.Run(body, func(t *testing.T) {
			cfg, binaryPath, confDir := signFragmentBaseline(t, "hostname: host1\n")
			path, err := FragmentRecordPath(cfg.ConfigFile)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			err = RehashFragments(binaryPath, cfg.ConfigFile, confDir, []string{agentFragment})
			if err == nil || errors.Is(err, ErrNoFragmentBaseline) {
				t.Fatalf("corrupt record: err = %v, want an error that cannot trigger full rehash", err)
			}
		})
	}
}

// A digest label must not let a record of different bytes vouch for an
// unnamed edit or deletion, even when the record is otherwise well formed.
func TestRehashFragmentsBindsRecordContentsToSignedDigest(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(fmt.Sprint("removed=", remove), func(t *testing.T) {
			cfg, binaryPath, confDir := signFragmentBaseline(t, "hostname: host1\n")
			before, err := os.ReadFile(cfg.ConfigFile)
			if err != nil {
				t.Fatal(err)
			}
			if remove {
				if err = os.Remove(filepath.Join(confDir, operatorFragment)); err != nil {
					t.Fatal(err)
				}
			} else {
				writeFragment(t, confDir, operatorFragment, "auto_response:\n  enabled: false\n")
			}
			if _, _, err = SignConfigFilePreserving(cfg.ConfigFile, confDir, cfg.Integrity.BinaryHash); err != nil {
				t.Fatal(err)
			}
			path, err := FragmentRecordPath(cfg.ConfigFile)
			if err != nil {
				t.Fatal(err)
			}
			record, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var object map[string]json.RawMessage
			if err = json.Unmarshal(record, &object); err != nil {
				t.Fatal(err)
			}
			object["confd_hash"], err = json.Marshal(cfg.Integrity.ConfdHash)
			if err != nil {
				t.Fatal(err)
			}
			record, err = json.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(path, record, 0o600); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(cfg.ConfigFile, before, 0o600); err != nil {
				t.Fatal(err)
			}
			err = RehashFragments(binaryPath, cfg.ConfigFile, confDir, []string{agentFragment})
			if err == nil || errors.Is(err, ErrNoFragmentBaseline) {
				t.Fatalf("inconsistent record: err = %v, want corruption error", err)
			}
			after, err := os.ReadFile(cfg.ConfigFile)
			if err != nil || string(after) != string(before) {
				t.Fatalf("refusal changed the signed config: %v", err)
			}
		})
	}
}

const (
	agentFragment    = "10-agent.yaml"
	operatorFragment = "20-operator.yaml"
)

func signFragmentBaseline(t *testing.T, mainBody string) (*config.Config, string, string) {
	t.Helper()
	return signTestBaseline(t, mainBody, map[string]string{
		agentFragment:    "alerts:\n  webhook:\n    url: https://panel.example.com/v1\n",
		operatorFragment: "auto_response:\n  enabled: true\n",
	})
}

func writeFragment(t *testing.T, confDir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(confDir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// reloadSigned reads the signed state back from disk, as the daemon would at
// its next start.
func reloadSigned(t *testing.T, cfg *config.Config) *config.Config {
	t.Helper()
	loaded, err := config.LoadWithDir(cfg.ConfigFile, cfg.ConfigDir)
	if err != nil {
		t.Fatalf("load signed config: %v", err)
	}
	return loaded
}

func assertUnnamedChanges(t *testing.T, err error, want ...string) {
	t.Helper()
	var unnamed *UnnamedChangesError
	if !errors.As(err, &unnamed) {
		t.Fatalf("err = %v, want UnnamedChangesError", err)
	}
	joined := strings.Join(unnamed.Changed, "\n")
	for _, w := range want {
		if !strings.Contains(joined, w) {
			t.Errorf("changed = %q, want it to name %q", unnamed.Changed, w)
		}
	}
	if len(unnamed.Changed) != len(want) {
		t.Errorf("changed = %q, want exactly %d entries", unnamed.Changed, len(want))
	}
}

func TestRehashFragmentsResignsOnlyTheNamedFragment(t *testing.T) {
	cfg, binaryPath, confDir := signFragmentBaseline(t, "hostname: host1\n")
	writeFragment(t, confDir, agentFragment, "alerts:\n  webhook:\n    url: https://panel.example.com/v2\n")

	if err := RehashFragments(binaryPath, cfg.ConfigFile, confDir, []string{agentFragment}); err != nil {
		t.Fatalf("RehashFragments: %v", err)
	}
	if err := Verify(binaryPath, reloadSigned(t, cfg)); err != nil {
		t.Fatalf("re-signed state must verify: %v", err)
	}
}

func TestRehashFragmentsSucceedsWhenNothingChanged(t *testing.T) {
	cfg, binaryPath, confDir := signFragmentBaseline(t, "hostname: host1\n")
	if err := RehashFragments(binaryPath, cfg.ConfigFile, confDir, []string{agentFragment}); err != nil {
		t.Fatalf("RehashFragments: %v", err)
	}
	if err := Verify(binaryPath, reloadSigned(t, cfg)); err != nil {
		t.Fatalf("unchanged state must still verify: %v", err)
	}
}

// The point of the scoped rehash: an integration re-signing its own fragment
// must not approve an edit somebody else made to another one.
func TestRehashFragmentsRefusesAnotherFragmentEdit(t *testing.T) {
	cfg, binaryPath, confDir := signFragmentBaseline(t, "hostname: host1\n")
	before, err := os.ReadFile(cfg.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	writeFragment(t, confDir, agentFragment, "alerts:\n  webhook:\n    url: https://panel.example.com/v2\n")
	writeFragment(t, confDir, operatorFragment, "auto_response:\n  enabled: false\n")

	err = RehashFragments(binaryPath, cfg.ConfigFile, confDir, []string{agentFragment})
	assertUnnamedChanges(t, err, operatorFragment)

	after, readErr := os.ReadFile(cfg.ConfigFile)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(after) != string(before) {
		t.Fatal("a refused rehash must leave the main config untouched")
	}
	if verifyErr := Verify(binaryPath, reloadSigned(t, cfg)); !errors.Is(verifyErr, ErrConfdHashMismatch) {
		t.Fatalf("Verify after refusal = %v, want conf.d mismatch", verifyErr)
	}
}

func TestRehashFragmentsRefusesAddedAndRemovedFragments(t *testing.T) {
	cfg, binaryPath, confDir := signFragmentBaseline(t, "hostname: host1\n")
	writeFragment(t, confDir, "30-new.yaml", "hostname: host2\n")
	if err := os.Remove(filepath.Join(confDir, operatorFragment)); err != nil {
		t.Fatal(err)
	}

	err := RehashFragments(binaryPath, cfg.ConfigFile, confDir, []string{agentFragment})
	assertUnnamedChanges(t, err, "30-new.yaml", operatorFragment)
}

func TestRehashFragmentsRefusesMainConfigEdit(t *testing.T) {
	cfg, binaryPath, confDir := signFragmentBaseline(t, "hostname: host1\n")
	data, err := os.ReadFile(cfg.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(data), "hostname: host1", "hostname: host2", 1)
	if writeErr := os.WriteFile(cfg.ConfigFile, []byte(edited), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}

	err = RehashFragments(binaryPath, cfg.ConfigFile, confDir, []string{agentFragment})
	assertUnnamedChanges(t, err, "main config")
}

func TestRehashFragmentsRefusesBinaryChange(t *testing.T) {
	cfg, binaryPath, confDir := signFragmentBaseline(t, "hostname: host1\n")
	if err := os.WriteFile(binaryPath, []byte("replaced binary"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := RehashFragments(binaryPath, cfg.ConfigFile, confDir, []string{agentFragment})
	assertUnnamedChanges(t, err, "binary")
}

func TestRehashFragmentsWithoutBaselineAsksForFullRehash(t *testing.T) {
	cfg, binaryPath, confDir := signFragmentBaseline(t, "hostname: host1\n")
	record, err := FragmentRecordPath(cfg.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if removeErr := os.Remove(record); removeErr != nil {
		t.Fatalf("signing must leave a per-fragment record: %v", removeErr)
	}

	err = RehashFragments(binaryPath, cfg.ConfigFile, confDir, []string{agentFragment})
	if !errors.Is(err, ErrNoFragmentBaseline) {
		t.Fatalf("err = %v, want ErrNoFragmentBaseline", err)
	}
}

// A record left by another signed state (a restored backup, an older binary
// that re-signed without writing one) describes fragments the stored digest
// no longer covers, so it cannot vouch for anything.
func TestRehashFragmentsIgnoresRecordOfAnotherSignedState(t *testing.T) {
	cfg, binaryPath, confDir := signFragmentBaseline(t, "hostname: host1\n")
	record, err := FragmentRecordPath(cfg.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	writeFragment(t, confDir, operatorFragment, "auto_response:\n  enabled: false\n")
	if _, _, signErr := SignConfigFilePreserving(cfg.ConfigFile, confDir, cfg.Integrity.BinaryHash); signErr != nil {
		t.Fatal(signErr)
	}
	if writeErr := os.WriteFile(record, stale, 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}

	err = RehashFragments(binaryPath, cfg.ConfigFile, confDir, []string{agentFragment})
	if !errors.Is(err, ErrNoFragmentBaseline) {
		t.Fatalf("err = %v, want ErrNoFragmentBaseline", err)
	}
}

func TestRehashFragmentsNeverSignedAsksForFullRehash(t *testing.T) {
	dir := t.TempDir()
	mainPath := filepath.Join(dir, "csm.yaml")
	if err := os.WriteFile(mainPath, []byte("hostname: host1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(dir, "csm.bin")
	if err := os.WriteFile(binaryPath, []byte("fake binary contents"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := RehashFragments(binaryPath, mainPath, filepath.Join(dir, "conf.d"), []string{agentFragment})
	if !errors.Is(err, ErrNoFragmentBaseline) {
		t.Fatalf("err = %v, want ErrNoFragmentBaseline", err)
	}
}

func TestRehashFragmentsAcceptsNewAndDeletedNamedFragments(t *testing.T) {
	cfg, binaryPath, confDir := signFragmentBaseline(t, "hostname: host1\n")
	writeFragment(t, confDir, "30-agent-extra.yaml", "hostname: host2\n")
	if err := os.Remove(filepath.Join(confDir, agentFragment)); err != nil {
		t.Fatal(err)
	}

	if err := RehashFragments(binaryPath, cfg.ConfigFile, confDir, []string{agentFragment, "30-agent-extra.yaml"}); err != nil {
		t.Fatalf("RehashFragments: %v", err)
	}
	if err := Verify(binaryPath, reloadSigned(t, cfg)); err != nil {
		t.Fatalf("re-signed state must verify: %v", err)
	}
}

func TestRehashFragmentsRejectsUnknownFragment(t *testing.T) {
	cfg, binaryPath, confDir := signFragmentBaseline(t, "hostname: host1\n")

	err := RehashFragments(binaryPath, cfg.ConfigFile, confDir, []string{"40-missing.yaml"})
	if err == nil || errors.Is(err, ErrNoFragmentBaseline) {
		t.Fatalf("err = %v, want a plain error for a fragment that never existed", err)
	}
	var unnamed *UnnamedChangesError
	if errors.As(err, &unnamed) {
		t.Fatalf("err = %v, want a plain error", err)
	}
	if !strings.Contains(err.Error(), "40-missing.yaml") {
		t.Errorf("error %q should name the fragment", err)
	}
}

func TestRehashFragmentsRejectsInvalidNames(t *testing.T) {
	cfg, binaryPath, confDir := signFragmentBaseline(t, "hostname: host1\n")
	for _, name := range []string{"", ".", "..", "../csm.yaml", "sub/10-agent.yaml", "/etc/csm/conf.d/10-agent.yaml", "10-agent.conf", "10-agent\n.yaml", "10-agent\x00.yaml"} {
		err := RehashFragments(binaryPath, cfg.ConfigFile, confDir, []string{name})
		if err == nil || errors.Is(err, ErrNoFragmentBaseline) {
			t.Errorf("name %q: err = %v, want a plain error", name, err)
		}
	}
	if err := RehashFragments(binaryPath, cfg.ConfigFile, confDir, nil); err == nil {
		t.Error("no fragment named: want an error")
	}
}

func TestFragmentRecordRejectsAmbiguousFilenameBoundaries(t *testing.T) {
	frags := []config.ConfDirFragment{
		{Name: "20-first.yaml", Data: []byte("hostname: first.example.com\n")},
		{Name: "30-second.yaml", Data: []byte("hostname: second.example.com\n")},
	}
	digest, _ := confdSnapshot(frags, nil)
	// Without rejecting newlines, one filename can embed an entire first
	// fragment and reproduce the aggregate digest of two different files.
	name := fmt.Sprintf("%s:%d\n%sconfd-fragment:%s", frags[0].Name, len(frags[0].Data), frags[0].Data, frags[1].Name)
	data, err := json.Marshal(fragmentRecord{ConfdHash: digest, Fragments: map[string][]byte{name: frags[1].Data}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeFragmentRecord(data); err == nil {
		t.Fatal("a different fragment set reproduced the signed digest")
	}
}

// Exempt fragments stay outside the signed state: naming one is harmless and
// a rewrite of one never blocks a scoped rehash.
func TestRehashFragmentsLeavesExemptFragmentsOut(t *testing.T) {
	cfg, binaryPath, confDir := signTestBaseline(t,
		"hostname: host1\nconfd:\n  integrity_exempt:\n    - 10-runtime.yaml\n",
		map[string]string{
			"10-runtime.yaml": "hostname: host2\n",
			agentFragment:     "alerts:\n  webhook:\n    url: https://panel.example.com/v1\n",
		})
	writeFragment(t, confDir, "10-runtime.yaml", "hostname: host3\n")
	writeFragment(t, confDir, agentFragment, "alerts:\n  webhook:\n    url: https://panel.example.com/v2\n")

	if err := RehashFragments(binaryPath, cfg.ConfigFile, confDir, []string{agentFragment}); err != nil {
		t.Fatalf("RehashFragments: %v", err)
	}
	if err := os.Remove(filepath.Join(confDir, "10-runtime.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := RehashFragments(binaryPath, cfg.ConfigFile, confDir, []string{"10-runtime.yaml"}); err != nil {
		t.Fatalf("naming a deleted exempt fragment: %v", err)
	}
	if err := Verify(binaryPath, reloadSigned(t, cfg)); err != nil {
		t.Fatalf("re-signed state must verify: %v", err)
	}
}

// Hosts upgraded from a release without per-fragment records get one the
// first time the daemon verifies conf.d, with no operator action.
func TestRecordVerifiedConfDGivesUpgradedHostsABaseline(t *testing.T) {
	cfg, binaryPath, confDir := signFragmentBaseline(t, "hostname: host1\n")
	record, err := FragmentRecordPath(cfg.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if removeErr := os.Remove(record); removeErr != nil {
		t.Fatal(removeErr)
	}

	if recordErr := RecordVerifiedConfD(cfg); recordErr != nil {
		t.Fatalf("RecordVerifiedConfD: %v", recordErr)
	}
	writeFragment(t, confDir, agentFragment, "alerts:\n  webhook:\n    url: https://panel.example.com/v2\n")
	if rehashErr := RehashFragments(binaryPath, cfg.ConfigFile, confDir, []string{agentFragment}); rehashErr != nil {
		t.Fatalf("RehashFragments after a recorded verification: %v", rehashErr)
	}
}

// A fragment edited between verification and recording must not slip into
// the record, or a later scoped rehash would approve it.
func TestRecordVerifiedConfDRefusesStateItCannotVouchFor(t *testing.T) {
	cfg, _, confDir := signFragmentBaseline(t, "hostname: host1\n")
	record, err := FragmentRecordPath(cfg.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if removeErr := os.Remove(record); removeErr != nil {
		t.Fatal(removeErr)
	}
	writeFragment(t, confDir, operatorFragment, "auto_response:\n  enabled: false\n")

	if recordErr := RecordVerifiedConfD(cfg); recordErr == nil {
		t.Fatal("RecordVerifiedConfD must refuse a conf.d that no longer matches the signed digest")
	}
	if _, statErr := os.Stat(record); !os.IsNotExist(statErr) {
		t.Fatalf("no record may be written for unverified fragments: %v", statErr)
	}
}

func TestRecordVerifiedConfDSkipsUnsignedConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm.yaml")
	cfg := &config.Config{ConfigFile: path}
	if err := RecordVerifiedConfD(cfg); err != nil {
		t.Fatalf("RecordVerifiedConfD: %v", err)
	}
	record, err := FragmentRecordPath(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(record); !os.IsNotExist(statErr) {
		t.Fatalf("an unsigned config has nothing verified to record: %v", statErr)
	}
}

func TestRehashFragmentsChecksSymlinkedConfigAndDirectory(t *testing.T) {
	cfg, binaryPath, confDir := signFragmentBaseline(t, "hostname: host1\n")
	aliasDir := t.TempDir()
	configLink, confLink := filepath.Join(aliasDir, "csm.yaml"), filepath.Join(aliasDir, "conf.d")
	if err := os.Symlink(cfg.ConfigFile, configLink); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(confDir, confLink); err != nil {
		t.Fatal(err)
	}
	path, err := FragmentRecordPath(configLink)
	if err != nil || path != cfg.ConfigFile+fragmentRecordSuffix {
		t.Fatalf("record path = %q, err = %v; want record beside the target", path, err)
	}
	writeFragment(t, confDir, operatorFragment, "auto_response:\n  enabled: false\n")
	assertUnnamedChanges(t, RehashFragments(binaryPath, configLink, confLink, []string{agentFragment}), operatorFragment)
	if err = RehashFragments(binaryPath, configLink, confLink, []string{operatorFragment}); err != nil {
		t.Fatal(err)
	}
	if err = Verify(binaryPath, reloadSigned(t, cfg)); err != nil {
		t.Fatalf("named edit through symlinks must verify: %v", err)
	}
	if linkInfo, linkErr := os.Lstat(configLink); linkErr != nil || linkInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("config symlink was not preserved: %v", linkErr)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("fragment snapshot must be private: %v", err)
	}
}

func TestRehashFragmentsCannotExemptAnUnnamedEdit(t *testing.T) {
	cfg, binaryPath, confDir := signFragmentBaseline(t, "hostname: host1\n")
	data, err := os.ReadFile(cfg.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte("confd:\n  integrity_exempt:\n    - "+operatorFragment+"\n")...)
	if err := os.WriteFile(cfg.ConfigFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	writeFragment(t, confDir, operatorFragment, "auto_response:\n  enabled: false\n")
	assertUnnamedChanges(t, RehashFragments(binaryPath, cfg.ConfigFile, confDir, []string{agentFragment}), "main config", operatorFragment)
}

func TestScopedSigningDoesNotApproveLaterFragmentBytes(t *testing.T) {
	cfg, binaryPath, confDir := signFragmentBaseline(t, "hostname: host1\n")
	data, err := os.ReadFile(cfg.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	main, err := config.LoadBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	main.ConfigFile, main.ConfigDir = cfg.ConfigFile, confDir
	writeFragment(t, confDir, agentFragment, "hostname: agent.example.com\n")
	checked, err := config.ConfDirFragmentDigestInput(confDir)
	if err != nil {
		t.Fatal(err)
	}
	writeFragment(t, confDir, operatorFragment, "auto_response:\n  enabled: false\n")
	if err := signAndSavePreserving(cfg.ConfigFile, confDir, data, main, cfg.Integrity.BinaryHash, checked); err != nil {
		t.Fatal(err)
	}
	if err := Verify(binaryPath, reloadSigned(t, cfg)); !errors.Is(err, ErrConfdHashMismatch) {
		t.Fatalf("bytes changed after comparison were approved: %v", err)
	}
	assertUnnamedChanges(t, RehashFragments(binaryPath, cfg.ConfigFile, confDir, []string{agentFragment}), operatorFragment)
}

func TestRecordVerifiedConfDRepairsCorruptMatchingRecord(t *testing.T) {
	cfg, binaryPath, confDir := signFragmentBaseline(t, "hostname: host1\n")
	path, err := FragmentRecordPath(cfg.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := fmt.Sprintf(`{"confd_hash":%q,"fragments":{}}`, cfg.Integrity.ConfdHash)
	if err := os.WriteFile(path, []byte(corrupt), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RecordVerifiedConfD(cfg); err != nil {
		t.Fatal(err)
	}
	if err := RehashFragments(binaryPath, cfg.ConfigFile, confDir, []string{agentFragment}); err != nil {
		t.Fatalf("verified fragments did not repair the record: %v", err)
	}
	writeFragment(t, confDir, operatorFragment, "auto_response:\n  enabled: false\n")
	assertUnnamedChanges(t, RehashFragments(binaryPath, cfg.ConfigFile, confDir, []string{agentFragment}), operatorFragment)
}
