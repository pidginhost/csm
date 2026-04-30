package checks

import (
	"bytes"
	"compress/gzip"
	"os"
	"strings"
	"testing"
)

func TestConfigHasBuiltInAFAlgAEAD_DetectsYes(t *testing.T) {
	cfg := `CONFIG_CRYPTO_AEAD=y
CONFIG_CRYPTO_USER_API=y
CONFIG_CRYPTO_USER_API_AEAD=y
`
	if !configHasBuiltInAFAlgAEAD(cfg) {
		t.Error("=y line should be detected as built-in")
	}
}

func TestConfigHasBuiltInAFAlgAEAD_RejectsModule(t *testing.T) {
	cfg := `CONFIG_CRYPTO_USER_API_AEAD=m
`
	if configHasBuiltInAFAlgAEAD(cfg) {
		t.Error("=m (loadable module) must NOT be classified as built-in")
	}
}

func TestConfigHasBuiltInAFAlgAEAD_RejectsUnset(t *testing.T) {
	cfg := `# CONFIG_CRYPTO_USER_API_AEAD is not set
`
	if configHasBuiltInAFAlgAEAD(cfg) {
		t.Error("`is not set` form must NOT be classified as built-in")
	}
}

func TestConfigHasBuiltInAFAlgAEAD_RejectsAbsent(t *testing.T) {
	cfg := `CONFIG_KVM=y
CONFIG_X86_64=y
`
	if configHasBuiltInAFAlgAEAD(cfg) {
		t.Error("config without the key at all must return false")
	}
}

func TestConfigHasBuiltInAFAlgAEAD_TolerantOfWhitespace(t *testing.T) {
	cfg := "  CONFIG_CRYPTO_USER_API_AEAD=y  \n"
	if !configHasBuiltInAFAlgAEAD(cfg) {
		t.Error("leading/trailing whitespace should not defeat detection")
	}
}

func TestKcareReportsCopyFailPatched_PositiveMatch(t *testing.T) {
	// Real kcarectl --patch-info output shape, simplified.
	out := []byte(`kpatch-name: rhel8/4.18.0-553.X/CVE-2026-31431-copy-fail.patch
kpatch-cve: CVE-2026-31431
kpatch-cve-url: https://access.redhat.com/security/cve/CVE-2026-31431
`)
	if !kcareReportsCopyFailPatched(out) {
		t.Error("output containing CVE-2026-31431 should be detected as patched")
	}
}

func TestKcareReportsCopyFailPatched_NegativeWhenAbsent(t *testing.T) {
	// kcarectl output that lists OTHER CVEs but not Copy Fail.
	out := []byte(`kpatch-name: rhel8/4.18.0-553.X/CVE-2026-23001-foo.patch
kpatch-cve: CVE-2026-23001
kpatch-name: rhel8/4.18.0-553.X/CVE-2026-22998-bar.patch
kpatch-cve: CVE-2026-22998
`)
	if kcareReportsCopyFailPatched(out) {
		t.Error("output without CVE-2026-31431 must NOT be classified as patched")
	}
}

func TestKcareReportsCopyFailPatched_EmptyOutputIsNotPatched(t *testing.T) {
	if kcareReportsCopyFailPatched(nil) {
		t.Error("nil/empty kcarectl output must not be classified as patched")
	}
	if kcareReportsCopyFailPatched([]byte("")) {
		t.Error("empty kcarectl output must not be classified as patched")
	}
}

func TestKernelHasBuiltInAFAlgAEAD_ReadsBootConfig(t *testing.T) {
	// Mock /proc/sys/kernel/osrelease and /boot/config-<release>.
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/proc/sys/kernel/osrelease":
				return []byte("4.18.0-553.44.1.lve.el8.x86_64\n"), nil
			case "/boot/config-4.18.0-553.44.1.lve.el8.x86_64":
				return []byte("CONFIG_CRYPTO_USER_API_AEAD=y\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	got, err := kernelHasBuiltInAFAlgAEAD()
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !got {
		t.Error("expected built-in detection to succeed")
	}
}

func TestKernelHasBuiltInAFAlgAEAD_FallsBackToProcConfigGz(t *testing.T) {
	// Boot config absent (e.g. minimal image), but /proc/config.gz exposed.
	gzPayload := func(content string) []byte {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write([]byte(content))
		_ = zw.Close()
		return buf.Bytes()
	}

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/proc/sys/kernel/osrelease":
				return []byte("6.1.0-test\n"), nil
			case "/proc/config.gz":
				return gzPayload("CONFIG_CRYPTO_USER_API_AEAD=y\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	got, err := kernelHasBuiltInAFAlgAEAD()
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !got {
		t.Error("expected built-in detection via /proc/config.gz to succeed")
	}
}

func TestKernelHasBuiltInAFAlgAEAD_NoConfigAvailableIsFalseNotError(t *testing.T) {
	// A locked-down host with no readable kernel config — common on
	// some Debian/Ubuntu builds where /proc/config.gz isn't enabled
	// and /boot/config-* is mode 0600. The audit must not error here;
	// it simply cannot determine the build configuration.
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return nil, os.ErrNotExist
		},
	})

	got, err := kernelHasBuiltInAFAlgAEAD()
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got {
		t.Error("config-unreadable host must default to NOT-built-in")
	}
}

func TestKcareHasCopyFailPatch_True(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(name string, args ...string) ([]byte, error) {
			if name == "kcarectl" {
				return []byte("kpatch-cve: CVE-2026-31431\n"), nil
			}
			return nil, nil
		},
	})
	if !kcareHasCopyFailPatch() {
		t.Error("expected true when kcarectl reports the CVE")
	}
}

func TestKcareHasCopyFailPatch_FalseWhenKcarectlAbsent(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(name string, args ...string) ([]byte, error) {
			return nil, os.ErrNotExist
		},
	})
	if kcareHasCopyFailPatch() {
		t.Error("kcarectl absent must mean NOT patched")
	}
}

func TestAFAlgKernelState_StringIsOperatorReadable(t *testing.T) {
	cases := []struct {
		state    AFAlgKernelState
		mustHave string
	}{
		{AFAlgKernelState{LivepatchActive: true}, "KernelCare"},
		{AFAlgKernelState{BuiltIn: true}, "built into the kernel"},
		{AFAlgKernelState{}, "loadable module"},
	}
	for _, c := range cases {
		got := c.state.String()
		if !strings.Contains(got, c.mustHave) {
			t.Errorf("state %+v string %q should contain %q", c.state, got, c.mustHave)
		}
	}
}
