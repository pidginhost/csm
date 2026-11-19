package checks

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestAuditSCTP(t *testing.T) {
	const (
		modular  = "CONFIG_IP_SCTP=m\n"
		builtin  = "CONFIG_IP_SCTP=y\n"
		disabled = "# CONFIG_IP_SCTP is not set\n"
		loaded   = "sctp 1 0 - Live 0x0\n"
		insert   = "insmod /lib/modules/example/sctp.ko.zst\n"
		block    = "install /bin/false \n"
		missing  = "modprobe: FATAL: Module sctp not found in directory "
		tree     = "/lib/modules/example"
		index    = tree + "/modules.dep.bin\n"
	)
	refused := exec.Command("/usr/bin/false").Run()
	if refused == nil {
		t.Fatal("expected false to exit with failure")
	}
	for _, tc := range []struct {
		name, config, modules, modulesDisabled string
		modulesErr, policyErr, probeErr        error
		plan, resolvesTo, treeOutput           string
		treeErr                                error
		want, message, fix                     string
	}{
		{name: "built in", config: builtin, policyErr: os.ErrPermission, modulesErr: os.ErrPermission, want: "fail", message: "built into", fix: "kernel"},
		{name: "loaded with unreadable policy", modules: loaded, policyErr: os.ErrPermission, want: "fail", message: "loaded", fix: "modprobe -r sctp"},
		{name: "loaded despite disabled loading", config: modular, modules: loaded, modulesDisabled: "1", want: "fail", message: "loaded", fix: "reboot"},
		{name: "disabled without proc modules", config: disabled, policyErr: os.ErrPermission, modulesErr: os.ErrNotExist, want: "pass", message: "no SCTP support"},
		{name: "kernel without INET", config: "# CONFIG_INET is not set\n", want: "pass", message: "no SCTP support"},
		{name: "unknown kernel", want: "warn", message: "CONFIG_IP_SCTP"},
		{name: "truncated kernel config", config: "CONFIG_IP_SCTP_DIAG=m\n", want: "warn", message: "CONFIG_IP_SCTP"},
		{name: "unknown loaded state", config: modular, modulesErr: os.ErrPermission, want: "warn", message: "/proc/modules"},
		{name: "unreadable policy", config: modular, policyErr: os.ErrPermission, want: "warn", message: "local.conf"},
		{name: "kernel module loading disabled", config: modular, modules: "sctp_diag 1 0 - Live 0x0\n", modulesDisabled: "1\n", want: "pass", message: "module loading is disabled"},
		{name: "effective block after dependencies", config: modular, plan: "insmod /lib/modules/example/libcrc32c.ko.xz\n" + block, resolvesTo: "sctp", want: "pass", message: "blocked"},
		{name: "true replacement", config: modular, plan: "install /usr/bin/true", resolvesTo: "sctp", want: "pass", message: "blocked"},
		{name: "blacklist permits dependency load", config: modular, plan: insert, want: "fail", message: "can load", fix: "install sctp /bin/false"},
		{name: "different module blocked", config: modular, plan: block + insert, want: "fail", message: "can load", fix: "install sctp /bin/false"},
		{name: "custom install command", config: modular, plan: "install /bin/true && /usr/local/sbin/load-module", want: "warn", message: "cannot confirm"},
		{name: "reload command", config: modular, plan: "install /sbin/modprobe --ignore-install sctp", want: "fail", message: "can load", fix: "install sctp /bin/false"},
		{name: "alias redirects name", config: modular, plan: block, resolvesTo: "another_module", want: "warn", message: "resolve"},
		{name: "missing modprobe", config: modular, probeErr: os.ErrNotExist, want: "warn", message: "modprobe"},
		{name: "module not installed", config: modular, plan: missing + tree + "\n", probeErr: refused, treeOutput: index, want: "pass", message: "not installed"},
		{name: "usr module tree", config: modular, plan: missing + "/usr" + tree + "\n", probeErr: refused, treeOutput: "/usr" + index, want: "pass", message: "not installed"},
		{name: "other module missing", config: modular, plan: "modprobe: FATAL: Module sctp_diag not found in directory " + tree, probeErr: refused, want: "warn", message: "modprobe"},
		{name: "not-found text with success", config: modular, plan: missing + tree, want: "warn", message: "cannot confirm"},
		{name: "index error before not-found", config: modular, plan: "libkmod: ERROR could not read module index\n" + missing + tree, probeErr: refused, want: "warn", message: "modprobe"},
		{name: "partial plan after not-found", config: modular, plan: missing + tree + "\n" + insert, probeErr: refused, want: "warn", message: "modprobe"},
		{name: "wrong kernel tree", config: modular, plan: missing + tree + "-old", probeErr: refused, want: "warn", message: "modprobe"},
		{name: "interrupted lookup", config: modular, plan: missing + tree, probeErr: context.DeadlineExceeded, want: "warn", message: "modprobe"},
		{name: "hidden module tree", config: modular, plan: missing + tree, probeErr: refused, treeErr: os.ErrPermission, want: "warn", message: "module tree"},
		{name: "no module index", config: modular, plan: missing + tree, probeErr: refused, want: "warn", message: "module tree"},
		{name: "unindexed SCTP", config: modular, plan: missing + tree, probeErr: refused, treeOutput: index + tree + "/updates/sctp.ko.xz\n", want: "warn", message: "module tree"},
		{name: "empty plan", config: modular, plan: " ", want: "warn", message: "cannot confirm"},
		{name: "kmod diagnostic with successful exit", config: modular, plan: "libkmod: ERROR could not read configuration\n" + block, want: "warn", message: "cannot confirm"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "local.conf"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			observedDisabled := false
			withMockOS(t, &mockOS{
				readDir: func(path string) ([]os.DirEntry, error) {
					if path == "/etc/modprobe.d" {
						return os.ReadDir(dir)
					}
					return nil, os.ErrNotExist
				},
				readFile: func(path string) ([]byte, error) {
					switch path {
					case "/proc/sys/kernel/osrelease":
						return []byte("example"), nil
					case "/boot/config-example":
						return []byte(tc.config), nil
					case "/proc/modules":
						if tc.modulesDisabled != "" && !observedDisabled {
							t.Fatal("must verify loaded state after observing the module loading lock")
						}
						return []byte(tc.modules), tc.modulesErr
					case "/proc/sys/kernel/modules_disabled":
						observedDisabled = true
						return []byte(tc.modulesDisabled), nil
					case "/etc/modprobe.d/local.conf":
						return nil, tc.policyErr
					}
					return nil, os.ErrNotExist
				},
			})
			withMockCmd(t, &mockCmd{run: func(name string, args ...string) ([]byte, error) {
				if name == "find" {
					return []byte(tc.treeOutput), tc.treeErr
				}
				if name != "modprobe" {
					t.Fatalf("unexpected command %q", name)
				}
				switch {
				case slices.Equal(args, []string{"--show-depends", "sctp"}):
					if tc.plan == "" && tc.probeErr == nil {
						t.Fatal("consulted modprobe despite decisive or unreadable kernel state")
					}
					return []byte(tc.plan), tc.probeErr
				case slices.Equal(args, []string{"--resolve-alias", "sctp"}):
					return []byte(tc.resolvesTo + "\n"), nil
				default:
					t.Fatalf("unexpected modprobe arguments %q", args)
					return nil, nil
				}
			}})
			r := auditSCTP()
			if r.Name != "os_sctp_blocked" || r.Category != "os" || r.Status != tc.want ||
				!strings.Contains(r.Message, tc.message) || !strings.Contains(r.Fix, tc.fix) {
				t.Fatalf("got %+v, want %s containing %q and fix containing %q", r, tc.want, tc.message, tc.fix)
			}
			if tc.want == "pass" && r.Fix != "" || tc.modules != loaded && strings.Contains(r.Fix, "modprobe -r") {
				t.Errorf("unexpected remediation %q", r.Fix)
			}
		})
	}
}

func TestSCTPQueriesHostModuleIndexes(t *testing.T) {
	withMockOS(t, &mockOS{readFile: func(path string) ([]byte, error) {
		switch path {
		case "/proc/sys/kernel/osrelease":
			return []byte("example"), nil
		case "/boot/config-example":
			return []byte("CONFIG_IP_SCTP=m"), nil
		case "/proc/modules":
			return nil, nil
		}
		return nil, os.ErrNotExist
	}})
	withMockCmd(t, &mockCmd{
		lookPath: func(name string) (string, error) {
			if name == "systemd-run" {
				return "/usr/bin/systemd-run", nil
			}
			return "", os.ErrNotExist
		},
		run: func(name string, args ...string) ([]byte, error) {
			split := slices.Index(args, "--")
			if name != "/usr/bin/systemd-run" || split < 0 ||
				!slices.Contains(args, "--pipe") || !slices.Contains(args, "--property=CapabilityBoundingSet=CAP_DAC_READ_SEARCH") {
				t.Fatalf("query did not run in the read-only host service: %s %q", name, args)
			}
			switch strings.Join(args[split+1:], " ") {
			case "/bin/true":
				return nil, nil
			case "modprobe --show-depends sctp":
				return []byte("install /bin/false"), nil
			case "modprobe --resolve-alias sctp":
				return []byte("sctp"), nil
			default:
				t.Fatalf("unexpected host query %q", args)
				return nil, nil
			}
		},
	})
	if got := auditSCTP(); got.Status != "pass" {
		t.Fatalf("host block not recognized: %+v", got)
	}
}

func TestSCTPAbsentFromTree(t *testing.T) {
	withMockCmd(t, &mockCmd{runContext: realCmd{}.RunContext})
	for _, tc := range []struct {
		name, module, link string
		index, absent      bool
	}{
		{name: "empty mount"},
		{name: "different module", module: "sctp_diag.ko", link: "weak-updates", index: true, absent: true},
		{name: "backup copy", module: "sctp.ko.old", link: "updates", index: true, absent: true},
		{name: "uncompressed SCTP", module: "sctp.ko", link: "build", index: true},
		{name: "compressed SCTP", module: "sctp.ko.zst", link: "weak-updates", index: true},
		{name: "versioned SCTP", module: "sctp.vendor.ko.xz", link: "updates", index: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := t.TempDir()
			if tc.index {
				if err := os.WriteFile(filepath.Join(tree, "modules.dep.bin"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.module != "" {
				target := t.TempDir()
				if err := os.WriteFile(filepath.Join(target, tc.module), nil, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, filepath.Join(tree, tc.link)); err != nil {
					t.Fatal(err)
				}
			}
			if got := sctpAbsentFromTree(tree); got != tc.absent {
				t.Fatalf("absence confirmed = %t, want %t", got, tc.absent)
			}
		})
	}
}

func TestSCTPReadsOnlyEffectivePolicyFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"local.conf", ".ignored.conf", "backup.conf~"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var reads []string
	withMockOS(t, &mockOS{
		readDir: func(path string) ([]os.DirEntry, error) {
			switch path {
			case "/etc/modprobe.d", "/usr/lib/modprobe.d":
				return os.ReadDir(dir)
			default:
				return nil, os.ErrNotExist
			}
		},
		readFile: func(path string) ([]byte, error) {
			reads = append(reads, path)
			return nil, nil
		},
	})
	if err := checkModprobePolicyReadable(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(reads, []string{"/etc/modprobe.d/local.conf"}) {
		t.Fatalf("read policy files %q", reads)
	}
}

func TestAuditSCTP_AppearsInOSAuditResults(t *testing.T) {
	for _, r := range auditOS() {
		if r.Name == "os_sctp_blocked" {
			return
		}
	}
	t.Error("auditOS() did not include the SCTP check")
}
