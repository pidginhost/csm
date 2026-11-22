package platform

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// pure-ftpd logs a client's reverse DNS name unless DontResolve is on, and
// the client's owner controls that name. Every configuration source present
// must turn it on, read the way pure-ftpd and Debian's wrapper read it.
func TestPureFTPDDontResolve(t *testing.T) {
	const conf, packaged, debian = "pure-ftpd.conf", "packaged.conf", "conf"
	for _, tc := range []struct {
		name      string
		installed bool
		files     map[string]string // relative to the test directory
		dirs      []string
		configs   []string
		missing   []string
	}{
		{name: "no configuration"},
		{name: "installed without a known configuration", installed: true, missing: []string{"pure-ftpd's configuration"}},
		{name: "installed and set", installed: true, files: map[string]string{conf: "DontResolve yes\n"}, configs: []string{conf}},
		{name: "cPanel sets it", files: map[string]string{conf: "NoAnonymous yes\nDontResolve yes\n"}, configs: []string{conf}},
		{name: "unset resolves", files: map[string]string{conf: "NoAnonymous yes\n"}, configs: []string{conf}, missing: []string{conf}},
		{name: "explicit no", files: map[string]string{conf: "DontResolve no\n"}, configs: []string{conf}, missing: []string{conf}},
		{name: "commented out", files: map[string]string{conf: "  # DontResolve yes\n"}, configs: []string{conf}, missing: []string{conf}},
		{name: "case and colon", files: map[string]string{conf: "  dontresolve: On\n"}, configs: []string{conf}},
		{name: "equals and digit", files: map[string]string{conf: "DontResolve=1\n"}, configs: []string{conf}},
		{name: "a later no does not undo it", files: map[string]string{conf: "DontResolve true\nDontResolve no\n"}, configs: []string{conf}},
		{name: "another key with the same start", files: map[string]string{conf: "DontResolveX yes\n"}, configs: []string{conf}, missing: []string{conf}},
		{name: "packaged configuration", files: map[string]string{packaged: "DontResolve yes\n"}, configs: []string{packaged}},
		{name: "debian option file", dirs: []string{debian}, files: map[string]string{debian + "/DontResolve": "# set by admin\n Yes \n"}, configs: []string{debian + "/DontResolve"}},
		{name: "debian without the option", dirs: []string{debian}, files: map[string]string{debian + "/NoAnonymous": "yes\n"}, configs: []string{debian + "/DontResolve"}, missing: []string{debian + "/DontResolve"}},
		{name: "debian option off", dirs: []string{debian}, files: map[string]string{debian + "/DontResolve": "off\n"}, configs: []string{debian + "/DontResolve"}, missing: []string{debian + "/DontResolve"}},
		{name: "every source must set it", dirs: []string{debian}, files: map[string]string{conf: "DontResolve yes\n"}, configs: []string{conf, debian + "/DontResolve"}, missing: []string{debian + "/DontResolve"}},
		{name: "unreadable configuration", dirs: []string{conf}, configs: []string{conf}, missing: []string{conf}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withMTAProbes(t, nil, map[string]bool{"/usr/sbin/pure-ftpd": tc.installed})
			root := t.TempDir()
			for _, d := range tc.dirs {
				if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			for name, body := range tc.files {
				if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			oldFiles, oldDir := pureFTPDConfigFiles, pureFTPDOptionDir
			pureFTPDConfigFiles = []string{filepath.Join(root, conf), filepath.Join(root, packaged)}
			pureFTPDOptionDir = filepath.Join(root, debian)
			t.Cleanup(func() { pureFTPDConfigFiles, pureFTPDOptionDir = oldFiles, oldDir })

			configs, missing := PureFTPDDontResolve()
			rel := func(paths []string) []string {
				var out []string
				for _, p := range paths {
					if !filepath.IsAbs(p) {
						out = append(out, p)
						continue
					}
					r, err := filepath.Rel(root, p)
					if err != nil {
						t.Fatal(err)
					}
					out = append(out, r)
				}
				return out
			}
			if got := rel(configs); !slices.Equal(got, tc.configs) {
				t.Errorf("configs = %v, want %v", got, tc.configs)
			}
			if got := rel(missing); !slices.Equal(got, tc.missing) {
				t.Errorf("missing = %v, want %v", got, tc.missing)
			}
		})
	}
}

func TestPureFTPDConfSeparators(t *testing.T) {
	for _, separator := range []string{" ", "\t", "=", ":", " = ", "\t: \t", "\v", "\f", "\r"} {
		for _, value := range []string{"yes", "ON", "True", "1"} {
			line := "DontResolve" + separator + value
			if !pureFTPDConfEnables(line, "DontResolve") {
				t.Errorf("valid assignment rejected: %q", line)
			}
		}
	}
	for _, line := range []string{"DontResolve == yes", "DontResolve : = yes", "DontResolve yes # comment", "DontResolve yesplease", "DontRe\u017folve yes", "\u00a0DontResolve yes", "DontResolve=\u00a0yes"} {
		if pureFTPDConfEnables(line, "DontResolve") {
			t.Errorf("invalid assignment accepted: %q", line)
		}
	}
}

func TestPureFTPDBrokenSourcesAreNotAbsent(t *testing.T) {
	withMTAProbes(t, nil, nil)
	root := t.TempDir()
	good, broken := filepath.Join(root, "good.conf"), filepath.Join(root, "broken.conf")
	options := filepath.Join(root, "conf")
	if err := os.WriteFile(good, []byte("DontResolve yes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{broken, options} {
		if err := os.Symlink(filepath.Join(root, "absent"), path); err != nil {
			t.Fatal(err)
		}
	}
	oldFiles, oldDir := pureFTPDConfigFiles, pureFTPDOptionDir
	t.Cleanup(func() { pureFTPDConfigFiles, pureFTPDOptionDir = oldFiles, oldDir })
	pureFTPDConfigFiles, pureFTPDOptionDir = []string{good, broken}, options
	configs, missing := PureFTPDDontResolve()
	if !slices.Equal(configs, []string{good, broken, filepath.Join(options, "DontResolve")}) ||
		!slices.Equal(missing, []string{broken, filepath.Join(options, "DontResolve")}) {
		t.Fatalf("unreadable sources were ignored: configs=%v missing=%v", configs, missing)
	}
}
