package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/integrity"
)

func signedFragmentHost(t *testing.T) (binPath, cfgPath, confDir string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath = filepath.Join(dir, "csm.yaml")
	confDir = filepath.Join(dir, "conf.d")
	binPath = filepath.Join(dir, "csm")
	if err := os.MkdirAll(confDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binPath, []byte("stand-in"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"10-agent.yaml":    "hostname: agent.example.com\n",
		"20-operator.yaml": "hostname: operator.example.com\n",
	} {
		if err := os.WriteFile(filepath.Join(confDir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(cfgPath, []byte("hostname: main.example.com\nintegrity:\n  binary_hash: \"\"\n  config_hash: \"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bh, err := integrity.HashFile(binPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := integrity.SignConfigFilePreserving(cfgPath, confDir, bh); err != nil {
		t.Fatal(err)
	}
	return binPath, cfgPath, confDir
}

// The phpanel agent branches on these exit codes, so each one is a contract.
func TestRehashFragmentsExitCodes(t *testing.T) {
	t.Run("named fragment changed", func(t *testing.T) {
		binPath, cfgPath, confDir := signedFragmentHost(t)
		if err := os.WriteFile(filepath.Join(confDir, "10-agent.yaml"), []byte("hostname: rewritten.example.com\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		if code := rehashFragments(binPath, cfgPath, confDir, []string{"10-agent.yaml"}, &stdout, &stderr); code != 0 {
			t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "10-agent.yaml") {
			t.Errorf("stdout %q should name the re-signed fragment", stdout.String())
		}
	})
	t.Run("another fragment changed", func(t *testing.T) {
		binPath, cfgPath, confDir := signedFragmentHost(t)
		if err := os.WriteFile(filepath.Join(confDir, "20-operator.yaml"), []byte("hostname: tampered.example.com\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		if code := rehashFragments(binPath, cfgPath, confDir, []string{"10-agent.yaml"}, &stdout, &stderr); code != exitRehashUnnamedChanges {
			t.Fatalf("exit = %d, want %d", code, exitRehashUnnamedChanges)
		}
		if !strings.Contains(stderr.String(), "20-operator.yaml") {
			t.Errorf("stderr %q should name what changed", stderr.String())
		}
	})
	t.Run("no per-fragment record", func(t *testing.T) {
		binPath, cfgPath, confDir := signedFragmentHost(t)
		record, err := integrity.FragmentRecordPath(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(record); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		if code := rehashFragments(binPath, cfgPath, confDir, []string{"10-agent.yaml"}, &stdout, &stderr); code != exitRehashNoBaseline {
			t.Fatalf("exit = %d, want %d", code, exitRehashNoBaseline)
		}
		if !strings.Contains(stderr.String(), "csm rehash") {
			t.Errorf("stderr %q should name the full rehash", stderr.String())
		}
	})
	t.Run("bad fragment name", func(t *testing.T) {
		binPath, cfgPath, confDir := signedFragmentHost(t)
		var stdout, stderr bytes.Buffer
		if code := rehashFragments(binPath, cfgPath, confDir, []string{"../csm.yaml"}, &stdout, &stderr); code != 1 {
			t.Fatalf("exit = %d, want 1", code)
		}
	})
}

func TestRehashFragmentArgs(t *testing.T) {
	names, err := rehashFragmentArgs([]string{"csm", "rehash", "--config", "/etc/csm/csm.yaml", "--fragment", "10-a.yaml", "--config-dir", "/etc/csm/conf.d", "--fragment", "20-b.yml"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(names, []string{"10-a.yaml", "20-b.yml"}) {
		t.Fatalf("names = %v", names)
	}
	if names, err := rehashFragmentArgs([]string{"csm", "rehash"}); err != nil || names != nil {
		t.Fatalf("plain rehash: names=%v err=%v", names, err)
	}
	if _, err := rehashFragmentArgs([]string{"csm", "rehash", "--fragment"}); err == nil {
		t.Fatal("--fragment without a name must fail")
	}
	if names, err := rehashFragmentArgs([]string{"csm", "rehash", "--fragment=10-a.yaml"}); err != nil || !slices.Equal(names, []string{"10-a.yaml"}) {
		t.Fatalf("--fragment=NAME: names=%v err=%v", names, err)
	}
	if _, err := rehashFragmentArgs([]string{"csm", "rehash", "--fragment="}); err == nil {
		t.Fatal("--fragment= without a name must fail")
	}
}

// A mistyped flag must not fall through to a full rehash, which would sign
// every change the scoped mode exists to refuse.
func TestRehashRejectsUnknownArgs(t *testing.T) {
	for _, arg := range []string{"--fragments", "--frag", "-fragment", "10-a.yaml", "--config=/etc/csm/csm.yaml"} {
		if _, err := rehashFragmentArgs([]string{"csm", "rehash", arg, "10-a.yaml"}); err == nil {
			t.Errorf("rehash %s: want an error", arg)
		}
	}
}
