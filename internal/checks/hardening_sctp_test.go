package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEvaluateSCTP(t *testing.T) {
	blocked := map[string]string{"/etc/modprobe.d/csm-disable-sctp.conf": "install sctp /bin/false\n"}
	cases := []struct {
		name      string
		kconfig   string
		loaded    bool
		confs     map[string]string
		want      string
		msgHas    string
		fixHas    string
		fixHasNot string
	}{
		{name: "module blocked and unloaded", kconfig: "m", confs: blocked, want: "pass"},
		{name: "blacklist directive counts", kconfig: "m", confs: map[string]string{"/etc/modprobe.d/local.conf": "blacklist sctp\n"}, want: "pass"},
		{name: "config unknown, blocked", kconfig: "", confs: blocked, want: "pass"},
		{name: "kernel without sctp", kconfig: "n", want: "pass", msgHas: "no SCTP support"},
		{name: "loadable on demand", kconfig: "m", want: "fail", msgHas: "loaded on demand", fixHas: "install sctp /bin/false", fixHasNot: "modprobe -r"},
		{name: "loaded", kconfig: "m", loaded: true, confs: blocked, want: "fail", msgHas: "loaded", fixHas: "modprobe -r sctp"},
		{name: "built in", kconfig: "y", confs: blocked, want: "fail", msgHas: "built into the kernel", fixHasNot: "modprobe.d"},
		{name: "reload form does not block", kconfig: "m", confs: map[string]string{"/etc/modprobe.d/x.conf": "install sctp /sbin/modprobe --ignore-install sctp\n"}, want: "fail"},
		{name: "commented directive does not block", kconfig: "m", confs: map[string]string{"/etc/modprobe.d/x.conf": "# install sctp /bin/false\n"}, want: "fail"},
		{name: "other module's block does not count", kconfig: "m", confs: map[string]string{"/etc/modprobe.d/x.conf": "install algif_aead /bin/false\nblacklist sctp_diag\n"}, want: "fail"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := evaluateSCTP(c.kconfig, c.loaded, c.confs)
			if r.Name != "os_sctp_blocked" || r.Category != "os" {
				t.Fatalf("name/category = %q/%q", r.Name, r.Category)
			}
			if r.Status != c.want {
				t.Fatalf("status = %q, want %q (msg: %s)", r.Status, c.want, r.Message)
			}
			if c.msgHas != "" && !strings.Contains(r.Message, c.msgHas) {
				t.Errorf("message %q lacks %q", r.Message, c.msgHas)
			}
			if c.fixHas != "" && !strings.Contains(r.Fix, c.fixHas) {
				t.Errorf("fix %q lacks %q", r.Fix, c.fixHas)
			}
			if c.fixHasNot != "" && strings.Contains(r.Fix, c.fixHasNot) {
				t.Errorf("fix %q must not contain %q", r.Fix, c.fixHasNot)
			}
			if c.want == "fail" && r.Fix == "" {
				t.Error("a fail must carry a Fix")
			}
		})
	}
}

func TestKernelConfigOption(t *testing.T) {
	cfg := "CONFIG_IP_SCTP=m\n# CONFIG_IP_DCCP is not set\nCONFIG_INET=y\nCONFIG_IP_SCTP_DIAG=m\n"
	for opt, want := range map[string]string{"CONFIG_IP_SCTP": "m", "CONFIG_INET": "y", "CONFIG_IP_DCCP": "n", "CONFIG_MISSING": "n"} {
		if got := kernelConfigOption(cfg, opt); got != want {
			t.Errorf("kernelConfigOption(%s) = %q, want %q", opt, got, want)
		}
	}
}

// sctpMockOS serves /proc/modules, one modprobe.d file and an optional
// kernel config through the osFS injector.
func sctpMockOS(t *testing.T, modules, kconfig string, confReadErr error) {
	t.Helper()
	conf := filepath.Join(t.TempDir(), "csm-disable-sctp.conf")
	if err := os.WriteFile(conf, []byte("install sctp /bin/false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if name != "/proc/modules" {
				return nil, os.ErrNotExist
			}
			f, err := os.CreateTemp(t.TempDir(), "modules")
			if err != nil {
				return nil, err
			}
			_, _ = f.WriteString(modules)
			_, _ = f.Seek(0, 0)
			return f, nil
		},
		glob: func(pattern string) ([]string, error) {
			if pattern == "/etc/modprobe.d/*.conf" {
				return []string{conf}, nil
			}
			return nil, nil
		},
		readFile: func(name string) ([]byte, error) {
			switch name {
			case conf:
				if confReadErr != nil {
					return nil, confReadErr
				}
				return os.ReadFile(name)
			case "/proc/sys/kernel/osrelease":
				return []byte("6.1.0-test\n"), nil
			case "/boot/config-6.1.0-test":
				if kconfig != "" {
					return []byte(kconfig), nil
				}
			}
			return nil, os.ErrNotExist
		},
	})
}

func TestAuditSCTP_HostState(t *testing.T) {
	cases := []struct {
		name, modules, kconfig string
		readErr                error
		want, msgHas           string
	}{
		{name: "blocked, unloaded, no config", modules: "bridge 1 0 - Live 0x0\n", want: "pass"},
		{name: "loaded despite block", modules: "sctp 1 0 - Live 0x0\n", kconfig: "CONFIG_IP_SCTP=m\n", want: "fail", msgHas: "loaded"},
		{name: "built in", modules: "", kconfig: "CONFIG_IP_SCTP=y\n", want: "fail", msgHas: "built into the kernel"},
		{name: "unreadable modprobe.d file", modules: "", kconfig: "CONFIG_IP_SCTP=m\n", readErr: os.ErrPermission, want: "warn", msgHas: "Cannot read"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sctpMockOS(t, c.modules, c.kconfig, c.readErr)
			r := auditSCTP()
			if r.Status != c.want {
				t.Fatalf("status = %q, want %q (msg: %s)", r.Status, c.want, r.Message)
			}
			if !strings.Contains(r.Message, c.msgHas) {
				t.Errorf("message %q lacks %q", r.Message, c.msgHas)
			}
		})
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
