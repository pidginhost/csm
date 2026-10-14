package integrity

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

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
	for _, name := range []string{"", ".", "..", "../csm.yaml", "sub/10-agent.yaml", "/etc/csm/conf.d/10-agent.yaml", "10-agent.conf"} {
		err := RehashFragments(binaryPath, cfg.ConfigFile, confDir, []string{name})
		if err == nil || errors.Is(err, ErrNoFragmentBaseline) {
			t.Errorf("name %q: err = %v, want a plain error", name, err)
		}
	}
	if err := RehashFragments(binaryPath, cfg.ConfigFile, confDir, nil); err == nil {
		t.Error("no fragment named: want an error")
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
