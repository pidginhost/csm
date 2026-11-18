package ci

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// A .deb that ships /etc/csm/csm.yaml registers it as a conffile. postinstall
// always edits that file, so dpkg stops every upgrade that changes the
// template to ask whether to replace the operator's config. The deb must ship
// the template elsewhere and leave /etc/csm/csm.yaml to postinstall. RPM keeps
// owning it: dropping a modified %config file makes rpm rename it to
// .rpmsave after postinstall has already run.
func TestDebDoesNotOwnMainConfig(t *testing.T) {
	data, err := os.ReadFile("../../build/nfpm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var pkg struct {
		Contents []struct {
			Src      string `yaml:"src"`
			Dst      string `yaml:"dst"`
			Packager string `yaml:"packager"`
		} `yaml:"contents"`
	}
	if err := yaml.Unmarshal(data, &pkg); err != nil {
		t.Fatal(err)
	}
	var template bool
	for _, c := range pkg.Contents {
		if c.Dst == "/etc/csm/csm.yaml" && c.Packager != "rpm" {
			t.Errorf("/etc/csm/csm.yaml ships to packager %q; only rpm may own it", c.Packager)
		}
		if c.Dst == "/usr/lib/csm/csm.yaml.default" && c.Src == "build/packaging/csm.yaml.default" && c.Packager == "" {
			template = true
		}
	}
	if !template {
		t.Error("both packages must ship the template at /usr/lib/csm/csm.yaml.default")
	}
}

// Run postinstall's config setup against a scratch tree.
func TestPostinstallSeedsMissingConfigOnly(t *testing.T) {
	script, err := os.ReadFile("../../build/packaging/scripts/postinstall.sh")
	if err != nil {
		t.Fatal(err)
	}
	start := bytes.Index(script, []byte("is_placeholder_config() {"))
	end := bytes.Index(script, []byte("\nmigrate_main_config\n"))
	if start < 0 || end < start {
		t.Fatal("config setup boundaries missing")
	}
	funcs := string(script[start:end])
	template, err := os.ReadFile("../../build/packaging/csm.yaml.default")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name      string
		preferred string // "" = absent
		legacy    string // "" = absent
		want      string // "" = template
	}{
		{name: "fresh"},
		{name: "existing kept", preferred: "hostname: kept\n", want: "hostname: kept\n"},
		{name: "legacy wins", legacy: "hostname: legacy\n", want: "hostname: legacy\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			def := filepath.Join(dir, "usr", "csm.yaml.default")
			pref := filepath.Join(dir, "etc", "csm.yaml")
			leg := filepath.Join(dir, "opt", "csm.yaml")
			// postinstall creates the config dir before this step.
			for _, d := range []string{filepath.Dir(def), filepath.Dir(pref), filepath.Dir(leg)} {
				if err := os.MkdirAll(d, 0755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(def, template, 0644); err != nil {
				t.Fatal(err)
			}
			if tc.preferred != "" {
				if err := os.WriteFile(pref, []byte(tc.preferred), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.legacy != "" {
				if err := os.WriteFile(leg, []byte(tc.legacy), 0600); err != nil {
					t.Fatal(err)
				}
			}
			// The extracted functions read the paths at call time.
			body := "PREFERRED_CONFIG=$1; LEGACY_CONFIG=$2; DEFAULT_CONFIG=$3\n" + funcs + "\nmigrate_main_config\n"
			cmd := exec.Command("bash", "-ec", body, "postinstall", pref, leg, def)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("postinstall config setup failed: %v\n%s", err, out)
			}
			got, err := os.ReadFile(pref)
			if err != nil {
				t.Fatalf("config not created: %v", err)
			}
			want := tc.want
			if want == "" {
				want = string(template)
			}
			if string(got) != want {
				t.Errorf("config content = %q, want %q", strings.SplitN(string(got), "\n", 2)[0], strings.SplitN(want, "\n", 2)[0])
			}
			if st, err := os.Stat(pref); err == nil && st.Mode().Perm() != 0600 {
				t.Errorf("config mode = %v, want 0600", st.Mode().Perm())
			}
			if target, err := os.Readlink(leg); err != nil || target != pref {
				t.Errorf("legacy path not linked to config: %q %v", target, err)
			}
		})
	}
}
