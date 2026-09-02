package main

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	signedConfig   = "hostname: prod\nintegrity:\n    binary_hash: sha256:bin2\n    config_hash: sha256:cfg2\n    confd_hash: sha256:confd2\n"
	unsignedConfig = "hostname: prod\nintegrity:\n    binary_hash: sha256:bin1\n    config_hash: sha256:cfg1\n    confd_hash: sha256:confd1\n"
)

// `csm rehash` rewrites all three integrity hashes in one copy only. After a
// conf.d drop-in edit the copies differ in confd_hash, a value CSM itself
// wrote, and refusing to start on it puts the service into a restart loop.
// Every integrity hash is tolerated, not just binary_hash.
func TestResolveDefaultConfigPathToleratesIntegrityHashDivergence(t *testing.T) {
	for name, legacyBody := range map[string]string{
		"all three hashes": unsignedConfig,
		"confd_hash only":  "hostname: prod\nintegrity:\n    binary_hash: sha256:bin2\n    config_hash: sha256:cfg2\n    confd_hash: sha256:confd1\n",
	} {
		t.Run(name, func(t *testing.T) {
			preferred, legacy := testConfigPaths(t)
			writeConfig(t, preferred, signedConfig)
			writeConfig(t, legacy, legacyBody)

			got, err := resolveDefaultConfigPath(preferred, legacy)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if got != preferred {
				t.Fatalf("config path = %q, want %q", got, preferred)
			}
		})
	}
}

// Two real copies that differ only in CSM-written hashes carry the same
// operator configuration, so migration converges them: the legacy path
// becomes the compatibility link and the signed preferred copy stays intact.
func TestMigrateDefaultConfigPathsConvergesIntegrityHashDivergence(t *testing.T) {
	preferred, legacy := testConfigPaths(t)
	writeConfig(t, preferred, signedConfig)
	writeConfig(t, legacy, unsignedConfig)

	if err := migrateDefaultConfigPaths(preferred, legacy); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	target, err := os.Readlink(legacy)
	if err != nil {
		t.Fatalf("legacy config is not a symlink after migration: %v", err)
	}
	if target != preferred {
		t.Fatalf("legacy link target = %q, want %q", target, preferred)
	}
	body, err := os.ReadFile(preferred)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != signedConfig {
		t.Fatalf("preferred copy changed during migration:\n%s", body)
	}
}

// Rehash re-signs the resolved copy only, so it is the moment to fold the
// legacy default path into the compatibility link. An explicit --config or
// a legacy-only install must not be touched.
func TestConvergeDefaultConfigCopiesAfterRehash(t *testing.T) {
	t.Run("default path converges", func(t *testing.T) {
		preferred, legacy := testConfigPaths(t)
		writeConfig(t, preferred, signedConfig)
		writeConfig(t, legacy, unsignedConfig)
		if err := convergeDefaultConfigCopies(preferred, false, preferred, legacy); err != nil {
			t.Fatalf("converge: %v", err)
		}
		if target, err := os.Readlink(legacy); err != nil || target != preferred {
			t.Fatalf("legacy = %q (%v), want link to %q", target, err, preferred)
		}
	})
	t.Run("explicit config is left alone", func(t *testing.T) {
		preferred, legacy := testConfigPaths(t)
		writeConfig(t, preferred, signedConfig)
		writeConfig(t, legacy, unsignedConfig)
		if err := convergeDefaultConfigCopies(preferred, true, preferred, legacy); err != nil {
			t.Fatalf("converge: %v", err)
		}
		if info, err := os.Lstat(legacy); err != nil || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("legacy copy touched under --config: %v %v", info, err)
		}
	})
	t.Run("legacy-only install is left alone", func(t *testing.T) {
		preferred, legacy := testConfigPaths(t)
		writeConfig(t, legacy, unsignedConfig)
		if err := convergeDefaultConfigCopies(legacy, false, preferred, legacy); err != nil {
			t.Fatalf("converge: %v", err)
		}
		if _, err := os.Lstat(preferred); !os.IsNotExist(err) {
			t.Fatalf("preferred path created for a legacy-only install: %v", err)
		}
	})
	t.Run("reverse compatibility link is normalised", func(t *testing.T) {
		preferred, legacy := testConfigPaths(t)
		writeConfig(t, legacy, signedConfig)
		if err := os.MkdirAll(filepath.Dir(preferred), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(legacy, preferred); err != nil {
			t.Fatal(err)
		}
		if err := convergeDefaultConfigCopies(preferred, false, preferred, legacy); err != nil {
			t.Fatalf("converge: %v", err)
		}
		if info, err := os.Lstat(preferred); err != nil || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("preferred config was not materialised: %v %v", info, err)
		}
		if target, err := os.Readlink(legacy); err != nil || target != preferred {
			t.Fatalf("legacy = %q (%v), want link to %q", target, err, preferred)
		}
		body, err := os.ReadFile(preferred)
		if err != nil || string(body) != signedConfig {
			t.Fatalf("materialised config = %q, err = %v", body, err)
		}
	})
}

func TestIntegrityHashLineRejectsCommentsAndOtherKeys(t *testing.T) {
	for _, line := range []string{
		"  # config_hash: operator note",
		"#confd_hash: old",
		"integrity_hash: value",
		"- binary_hash: value",
	} {
		if isIntegrityHashLine(line) {
			t.Errorf("isIntegrityHashLine(%q) = true", line)
		}
	}
	for _, line := range []string{
		"binary_hash: sha256:bin",
		"  config_hash: sha256:cfg",
		"\tconfd_hash: sha256:confd # generated",
	} {
		if !isIntegrityHashLine(line) {
			t.Errorf("isIntegrityHashLine(%q) = false", line)
		}
	}
}

func TestIntegrityHashDivergenceRequiresMatchingKeys(t *testing.T) {
	preferred, legacy := testConfigPaths(t)
	writeConfig(t, preferred, "integrity:\n  binary_hash: sha256:bin\n  config_hash: sha256:cfg\n")
	writeConfig(t, legacy, "integrity:\n  config_hash: sha256:bin\n  binary_hash: sha256:cfg\n")

	same, err := divergesOnlyByIntegrityHashes(preferred, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if same {
		t.Fatal("different integrity keys at the same line positions were treated as hash-value-only divergence")
	}
}

func TestIntegrityHashDivergenceRejectsSameNamedKeysOutsideIntegrity(t *testing.T) {
	preferred, legacy := testConfigPaths(t)
	writeConfig(t, preferred, "feature:\n  config_hash: operator-a\nintegrity:\n  config_hash: sha256:same\n")
	writeConfig(t, legacy, "feature:\n  config_hash: operator-b\nintegrity:\n  config_hash: sha256:same\n")

	same, err := divergesOnlyByIntegrityHashes(preferred, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if same {
		t.Fatal("a same-named key outside the integrity block was treated as a generated hash")
	}
}
