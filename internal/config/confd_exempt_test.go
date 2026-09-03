package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A fragment must not be able to exempt itself from the integrity digest, or
// an attacker with write access to conf.d could hide any override.
func TestLoadConfDirRejectsConfdOverride(t *testing.T) {
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "10-self.yaml"),
		[]byte("confd:\n  integrity_exempt:\n    - 10-self.yaml\n"), 0o600))

	_, err := LoadConfDir(dir)
	if err == nil {
		t.Fatal("conf.d confd override must be rejected")
	}
	if !strings.Contains(err.Error(), "confd") {
		t.Fatalf("error = %v, want confd refusal", err)
	}

	_, err = ConfDirFragmentDigestInput(dir)
	if err == nil {
		t.Fatal("digest input must reject the same fragment set")
	}
	if !strings.Contains(err.Error(), "confd") {
		t.Fatalf("digest error = %v, want confd refusal", err)
	}
}

func TestLoadConfDirRejectsMergedConfdOverride(t *testing.T) {
	dir := t.TempDir()
	fragment := `<<: &managed
  confd:
    integrity_exempt:
      - 10-self.yaml
`
	must(t, os.WriteFile(filepath.Join(dir, "10-self.yaml"), []byte(fragment), 0o600))

	_, err := LoadConfDir(dir)
	if err == nil {
		t.Fatal("conf.d confd override hidden in a YAML merge must be rejected")
	}
	if !strings.Contains(err.Error(), "confd") {
		t.Fatalf("error = %v, want confd refusal", err)
	}

	_, err = ConfDirFragmentDigestInput(dir)
	if err == nil {
		t.Fatal("digest input must reject a confd override hidden in a YAML merge")
	}
	if !strings.Contains(err.Error(), "confd") {
		t.Fatalf("digest error = %v, want confd refusal", err)
	}
}

// The exemption matches fragment filenames exactly, so anything that is not a
// bare .yaml/.yml filename can never match and is an operator mistake.
func TestValidateConfdIntegrityExemptEntries(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entry   string
		wantErr bool
	}{
		{"bare yaml filename", "10-agent-runtime.yaml", false},
		{"bare yml filename", "10-agent-runtime.yml", false},
		{"path component", "sub/10-agent.yaml", true},
		{"absolute path", "/etc/csm/conf.d/10-agent.yaml", true},
		{"wrong extension", "10-agent.txt", true},
		{"empty", "", true},
		{"parent dir", "..", true},
		{"glob", "*.yaml", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := lockoutTestConfig(nil)
			cfg.ConfD.IntegrityExempt = []string{tc.entry}
			_, got := findResult(Validate(cfg), "error", "confd.integrity_exempt")
			if got != tc.wantErr {
				t.Errorf("entry %q: error=%v, want %v; results=%v", tc.entry, got, tc.wantErr, Validate(cfg))
			}
		})
	}
}
