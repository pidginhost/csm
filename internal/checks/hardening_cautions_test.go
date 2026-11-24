package checks

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Exercise the same selection path used by the API and root worker, with
// writes confined to temporary files and commands captured by the injector.
func TestApplyHardeningCautionsRequireExplicitNames(t *testing.T) {
	for _, category := range []struct {
		name      string
		cautioned []string
		ordinary  string
	}{
		{"ssh", []string{"ssh_max_auth_tries"}, "ssh_use_dns"},
		{"os", []string{"os_sysctl_rp_filter"}, "os_sysctl_aslr"},
		{"cpanel", []string{"cp_cookie_validation", "cp_nobodyspam", "cp_max_emails_hour"}, "cp_ssl_only"},
	} {
		for _, selection := range []string{"omitted", "empty", "explicit", "ordinary"} {
			t.Run(category.name+"/"+selection, func(t *testing.T) {
				useCPanelPlatform(t)
				path := withTempSSHDConfig(t, "MaxAuthTries 6\nUseDNS yes\nX11Forwarding no\n")
				dir := t.TempDir()
				oldSysctl, oldShadow, oldTmp := hardeningSysctlConfPath, hardeningShadowPath, hardeningTmpDirs
				hardeningSysctlConfPath = filepath.Join(dir, "sysctl.conf")
				hardeningShadowPath = filepath.Join(dir, "missing-shadow")
				hardeningTmpDirs = nil
				t.Cleanup(func() { hardeningSysctlConfPath, hardeningShadowPath, hardeningTmpDirs = oldSysctl, oldShadow, oldTmp })
				withMockOS(t, &mockOS{
					open: func(name string) (*os.File, error) {
						if name == path {
							return os.Open(path)
						}
						return nil, os.ErrNotExist
					},
				})
				var commands []string
				withMockCmd(t, &mockCmd{run: func(name string, args ...string) ([]byte, error) {
					commands = append(commands, name+" "+strings.Join(args, " "))
					if name == "whmapi1" {
						return []byte(`{"metadata":{"result":1}}`), nil
					}
					return nil, nil
				}})
				var names []string
				switch selection {
				case "empty":
					names = []string{}
				case "explicit":
					names = append([]string{category.ordinary}, category.cautioned...)
				case "ordinary":
					names = []string{category.ordinary}
				}
				results, err := ApplyHardening(nil, category.name, names)
				if err != nil {
					t.Fatal(err)
				}
				statuses := map[string]string{}
				for _, r := range results {
					statuses[r.Name] = r.Status
					if slices.Contains(category.cautioned, r.Name) && selection != "explicit" && r.Status == "skipped" && !strings.Contains(r.Message, "explicit") {
						t.Errorf("skip does not explain opt-in: %+v", r)
					}
				}
				if statuses[category.ordinary] != "applied" {
					t.Errorf("ordinary fix not applied: %v", results)
				}
				for _, name := range category.cautioned {
					want := "skipped"
					if selection == "explicit" {
						want = "applied"
					}
					if selection == "ordinary" {
						want = ""
					}
					if statuses[name] != want {
						t.Errorf("%s status = %q, want %q", name, statuses[name], want)
					}
				}
				selected := selection == "explicit"
				switch category.name {
				case "ssh":
					data, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					if strings.Contains(string(data), "\nMaxAuthTries 4\n") != selected {
						t.Errorf("unexpected SSH edit: %s", data)
					}
				case "os":
					data, err := os.ReadFile(hardeningSysctlConfPath)
					if err != nil {
						t.Fatal(err)
					}
					if strings.Contains(string(data), "net.ipv4.conf.all.rp_filter = 1") != selected {
						t.Errorf("unexpected sysctl edit: %s", data)
					}
					if slices.Contains(commands, "sysctl -w net.ipv4.conf.all.rp_filter=1") != selected {
						t.Errorf("unexpected sysctl commands: %v", commands)
					}
				case "cpanel":
					for _, setting := range []string{"cookieipvalidation", "nobodyspam", "maxemailsperhour"} {
						found := false
						for _, command := range commands {
							if strings.Contains(command, "key="+setting+" ") {
								found = true
							}
						}
						if found != selected {
							t.Errorf("unexpected %s command: %v", setting, commands)
						}
					}
				}
			})
		}
	}
}
