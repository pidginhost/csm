package ci

import (
	"errors"
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
			Type     string `yaml:"type"`
			FileInfo struct {
				Mode uint32 `yaml:"mode"`
			} `yaml:"file_info"`
		} `yaml:"contents"`
	}
	if err := yaml.Unmarshal(data, &pkg); err != nil {
		t.Fatal(err)
	}
	var template, rpmConfig int
	for _, c := range pkg.Contents {
		if c.Dst == "/etc/csm/csm.yaml" {
			rpmConfig++
			if c.Packager != "rpm" || c.Type != "config|noreplace" || c.FileInfo.Mode != 0600 || c.Src != "build/packaging/csm.yaml.default" {
				t.Errorf("unexpected main config entry: %+v", c)
			}
		}
		if c.Dst == "/usr/lib/csm/csm.yaml.default" && c.Src == "build/packaging/csm.yaml.default" && c.Packager == "" {
			template++
		}
	}
	if rpmConfig != 1 {
		t.Errorf("got %d RPM config entries, want one", rpmConfig)
	}
	if template != 1 {
		t.Error("both packages must ship the template at /usr/lib/csm/csm.yaml.default")
	}
}

// Exercise the package scripts with their installed paths under a temporary root.
// Keep service management and host cleanup outside the executed blocks.
type packageConfigTree struct {
	root, preferred, legacy, template string
}

func newPackageConfigTree(t *testing.T) packageConfigTree {
	t.Helper()
	root := t.TempDir()
	tree := packageConfigTree{
		root:      root,
		preferred: root + "/etc/csm/csm.yaml",
		legacy:    root + "/opt/csm/csm.yaml",
		template:  root + "/usr/lib/csm/csm.yaml.default",
	}
	for _, path := range []string{tree.preferred, tree.legacy, tree.template} {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
	}
	return tree
}

func (tree packageConfigTree) run(t *testing.T, script string, args ...string) error {
	t.Helper()
	data, err := os.ReadFile("../../build/packaging/scripts/" + script + ".sh")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	var body string
	relocate := "PREFERRED_CONFIG=$TEST_ROOT$PREFERRED_CONFIG\nLEGACY_CONFIG=$TEST_ROOT$LEGACY_CONFIG\n"
	if script == "postinstall" {
		paths, detection, start := strings.Cut(source, "# Detect fresh install vs upgrade\n")
		detection, _, end := strings.Cut(detection, "# Ensure FHS dirs exist")
		_, funcs, found := strings.Cut(source, "is_placeholder_config() {")
		funcs, _, done := strings.Cut(funcs, "# Snapshot whether")
		if !start || !end || !found || !done {
			t.Fatal("cannot isolate package config setup")
		}
		body = paths + relocate + "DEFAULT_CONFIG=$TEST_ROOT$DEFAULT_CONFIG\n" +
			"MARKER=$TEST_ROOT$MARKER\nLEGACY_MARKER=$TEST_ROOT$LEGACY_MARKER\n" +
			detection + "is_placeholder_config() {" + funcs
	} else {
		const purge = `if [ "${1:-}" = purge ]; then`
		_, tail, start := strings.Cut(source, "\nPREFERRED_CONFIG=")
		paths, cleanup, end := strings.Cut(tail, purge)
		if !start || !end {
			t.Fatal("cannot isolate config cleanup")
		}
		body = "PREFERRED_CONFIG=" + paths + relocate + purge + cleanup
	}
	cmd := exec.Command("bash", append([]string{"-c", body, script}, args...)...)
	cmd.Env = append(os.Environ(), "TEST_ROOT="+tree.root)
	return cmd.Run()
}

func TestPostinstallSeedsMissingConfigOnly(t *testing.T) {
	const operator = "hostname: kept\n"
	shipped, err := os.ReadFile("../../build/packaging/csm.yaml.default")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name              string
		args              []string
		preferred, legacy bool
		want              string
	}{
		{"fresh", []string{"configure", ""}, false, false, string(shipped)},
		{"retry", []string{"configure"}, true, false, operator},
		{"deb upgrade", []string{"configure", "4.14.0"}, true, false, operator},
		{"rpm upgrade", []string{"2"}, true, false, operator},
		{"legacy upgrade", []string{"configure", "4.14.0"}, false, true, operator},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := newPackageConfigTree(t)
			if err := os.WriteFile(tree.template, shipped, 0644); err != nil {
				t.Fatal(err)
			}
			for path, present := range map[string]bool{tree.preferred: tc.preferred, tree.legacy: tc.legacy} {
				if present {
					if err := os.WriteFile(path, []byte(operator), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := tree.run(t, "postinstall", tc.args...); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(tree.preferred)
			if err != nil || string(got) != tc.want {
				t.Fatalf("incorrect active config: %v", err)
			}
			st, err := os.Stat(tree.preferred)
			if err != nil || st.Mode().Perm() != 0600 {
				t.Fatalf("expected private config: %v, %v", st, err)
			}
			if target, err := os.Readlink(tree.legacy); err != nil || target != tree.preferred {
				t.Fatalf("incorrect legacy link: %q, %v", target, err)
			}
		})
	}
}

func TestPostinstallRefusesToReplaceUnavailableConfig(t *testing.T) {
	for _, tc := range []struct {
		name  string
		args  []string
		state string
	}{
		{"deleted with install marker", []string{"configure"}, "marker"},
		{"deleted on deb upgrade", []string{"configure", "4.14.0"}, ""},
		{"deleted on rpm upgrade", []string{"2"}, ""},
		{"dangling preferred", []string{"configure"}, "preferred"},
		{"external legacy config", []string{"configure"}, "legacy"},
		{"preferred directory", []string{"configure"}, "directory"},
		{"legacy directory", []string{"configure"}, "legacy directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := newPackageConfigTree(t)
			if err := os.WriteFile(tree.template, []byte("hostname: default\n"), 0644); err != nil {
				t.Fatal(err)
			}
			target := tree.root + "/operator.yaml"
			var link string
			switch tc.state {
			case "marker":
				dir := tree.root + "/var/lib/csm"
				if err := os.MkdirAll(dir, 0711); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(dir+"/.pkg-installed", nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "directory", "legacy directory":
				dir := tree.preferred
				if tc.state == "legacy directory" {
					dir = tree.legacy
				}
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
			case "preferred":
				link = tree.preferred
			case "legacy":
				link = tree.legacy
				if err := os.WriteFile(target, []byte("hostname: kept\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if link != "" {
				if err := os.Symlink(target, link); err != nil {
					t.Fatal(err)
				}
			}
			if err := tree.run(t, "postinstall", tc.args...); err == nil {
				t.Error("setup accepted an unavailable config")
			}
			if _, err := os.Stat(tree.preferred); tc.state != "directory" && !errors.Is(err, os.ErrNotExist) {
				t.Errorf("unexpected preferred config: %v", err)
			}
			if link != "" {
				if got, err := os.Readlink(link); err != nil || got != target {
					t.Errorf("operator link changed: %q, %v", got, err)
				}
			}
		})
	}
}

func TestPackageConfigRemoval(t *testing.T) {
	for _, tc := range []struct {
		action      string
		managedLink bool
	}{
		{"remove", true}, {"0", true}, {"purge", true}, {"purge", false},
	} {
		t.Run(tc.action, func(t *testing.T) {
			tree := newPackageConfigTree(t)
			external := tree.root + "/operator.yaml"
			if err := os.WriteFile(external, []byte("hostname: kept\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if tc.managedLink {
				if err := os.WriteFile(tree.preferred, []byte("hostname: kept\n"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Symlink(external, tree.preferred); err != nil {
				t.Fatal(err)
			}
			target := external
			if tc.managedLink {
				target = tree.preferred
			}
			if err := os.Symlink(target, tree.legacy); err != nil {
				t.Fatal(err)
			}
			if err := tree.run(t, "postremove", tc.action); err != nil {
				t.Fatal(err)
			}
			for path, removed := range map[string]bool{
				tree.preferred: tc.action == "purge",
				tree.legacy:    tc.action == "purge" && tc.managedLink,
				external:       false,
			} {
				_, err := os.Lstat(path)
				if (removed && !errors.Is(err, os.ErrNotExist)) || (!removed && err != nil) {
					t.Errorf("path %s, want removed=%t: %v", path, removed, err)
				}
			}
		})
	}
}

func TestInterruptedConfigSeedCanRetry(t *testing.T) {
	tree := newPackageConfigTree(t)
	if err := os.WriteFile(tree.template, []byte("hostname: fresh\n"), 0644); err != nil {
		t.Fatal(err)
	}
	realInstall, lookErr := exec.LookPath("install")
	if lookErr != nil {
		t.Fatal(lookErr)
	}
	bin := t.TempDir()
	const failCopy = `#!/bin/bash
if [[ -n "${OPERATOR_CONFIG:-}" ]]; then
    echo "hostname: kept" > "$OPERATOR_CONFIG"
    exec "$REAL_INSTALL" "$@"
fi
echo partial > "${!#}"
exit 1
`
	if err := os.WriteFile(filepath.Join(bin, "install"), []byte(failCopy), 0700); err != nil {
		t.Fatal(err)
	}
	path := os.Getenv("PATH")
	t.Setenv("REAL_INSTALL", realInstall)
	t.Setenv("OPERATOR_CONFIG", "")
	t.Setenv("PATH", bin+":"+path)
	if err := tree.run(t, "postinstall", "configure"); err == nil {
		t.Fatal("setup succeeded after failed copy")
	}
	if _, err := os.Lstat(tree.preferred); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed copy published a partial config")
	}
	t.Setenv("OPERATOR_CONFIG", tree.preferred)
	if err := tree.run(t, "postinstall", "configure"); err == nil {
		t.Fatal("setup reported success after the operator created the config")
	}
	got, err := os.ReadFile(tree.preferred)
	if err != nil || string(got) != "hostname: kept\n" {
		t.Fatal("setup overwrote the operator config")
	}
	if err = os.Remove(tree.preferred); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", path)
	if err = tree.run(t, "postinstall", "configure"); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(tree.preferred)
	if err != nil || string(got) != "hostname: fresh\n" {
		t.Fatal("retry did not install the complete config")
	}
}
