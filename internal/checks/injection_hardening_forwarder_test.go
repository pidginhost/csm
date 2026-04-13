package checks

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/state"
)

// ==========================================================================
// hardening_audit.go tests
// ==========================================================================

func TestDetectServerTypeBare(t *testing.T) {
	st := detectServerType()
	switch st {
	case "cpanel", "cloudlinux", "bare":
	default:
		t.Errorf("unexpected server type %q", st)
	}
}

func TestAuditOSShadowPermissions_Pass0600(t *testing.T) {
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if name == "/etc/shadow" {
				return fakeFileInfoWithMode{name: "shadow", mode: 0o600}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/os-release" {
				return []byte("PRETTY_NAME=\"AlmaLinux 9.3\"\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{})
	for _, r := range auditOS() {
		if r.Name == "os_shadow_permissions" {
			if r.Status != "pass" {
				t.Errorf("shadow 0600 should pass, got %q: %s", r.Status, r.Message)
			}
			return
		}
	}
	t.Error("os_shadow_permissions result not found")
}

func TestAuditOSShadowPermissions_Fail0666(t *testing.T) {
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if name == "/etc/shadow" {
				return fakeFileInfoWithMode{name: "shadow", mode: 0o666}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/os-release" {
				return []byte("PRETTY_NAME=\"Ubuntu 24.04\"\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{})
	for _, r := range auditOS() {
		if r.Name == "os_shadow_permissions" {
			if r.Status != "fail" {
				t.Errorf("shadow 0666 should fail, got %q: %s", r.Status, r.Message)
			}
			return
		}
	}
	t.Error("os_shadow_permissions result not found")
}

func TestAuditOSShadowPermissions_Pass0640(t *testing.T) {
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if name == "/etc/shadow" {
				return fakeFileInfoWithMode{name: "shadow", mode: 0o640}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/os-release" {
				return []byte("PRETTY_NAME=\"Debian 12\"\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{})
	for _, r := range auditOS() {
		if r.Name == "os_shadow_permissions" {
			if r.Status != "pass" {
				t.Errorf("shadow 0640 should pass, got %q: %s", r.Status, r.Message)
			}
			return
		}
	}
	t.Error("os_shadow_permissions result not found")
}

func TestAuditOSShadowPermissions_Pass0000(t *testing.T) {
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if name == "/etc/shadow" {
				return fakeFileInfoWithMode{name: "shadow", mode: 0}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/os-release" {
				return []byte("PRETTY_NAME=\"Ubuntu 24.04\"\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{})
	for _, r := range auditOS() {
		if r.Name == "os_shadow_permissions" {
			if r.Status != "pass" {
				t.Errorf("shadow 0000 should pass, got %q: %s", r.Status, r.Message)
			}
			return
		}
	}
	t.Error("os_shadow_permissions result not found")
}

func TestAuditOSSwap_Active(t *testing.T) {
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		readFile: func(name string) ([]byte, error) {
			if name == "/proc/swaps" {
				return []byte("Filename\tType\tSize\tUsed\tPriority\n/swapfile\tfile\t2097148\t0\t-2\n"), nil
			}
			if name == "/etc/os-release" {
				return []byte("PRETTY_NAME=\"Ubuntu 24.04\"\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{})
	for _, r := range auditOS() {
		if r.Name == "os_swap" {
			if r.Status != "pass" {
				t.Errorf("active swap should pass, got %q: %s", r.Status, r.Message)
			}
			return
		}
	}
	t.Error("os_swap result not found")
}

func TestAuditOSSwap_None(t *testing.T) {
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		readFile: func(name string) ([]byte, error) {
			if name == "/proc/swaps" {
				return []byte("Filename\tType\tSize\tUsed\tPriority\n"), nil
			}
			if name == "/etc/os-release" {
				return []byte("PRETTY_NAME=\"Ubuntu 24.04\"\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{})
	for _, r := range auditOS() {
		if r.Name == "os_swap" {
			if r.Status != "warn" {
				t.Errorf("no swap should warn, got %q: %s", r.Status, r.Message)
			}
			return
		}
	}
	t.Error("os_swap result not found")
}

func TestAuditOSNobodyCron_Absent(t *testing.T) {
	withMockOS(t, &mockOS{
		stat:     func(name string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		readFile: func(name string) ([]byte, error) { return nil, os.ErrNotExist },
	})
	withMockCmd(t, &mockCmd{})
	for _, r := range auditOS() {
		if r.Name == "os_nobody_cron" {
			if r.Status != "pass" {
				t.Errorf("absent nobody cron should pass, got %q", r.Status)
			}
			return
		}
	}
	t.Error("os_nobody_cron result not found")
}

func TestAuditOSNobodyCron_Empty(t *testing.T) {
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if name == "/var/spool/cron/nobody" {
				return fakeFileInfo{name: "nobody", size: 0}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) { return nil, os.ErrNotExist },
	})
	withMockCmd(t, &mockCmd{})
	for _, r := range auditOS() {
		if r.Name == "os_nobody_cron" {
			if r.Status != "pass" {
				t.Errorf("empty nobody cron should pass, got %q", r.Status)
			}
			return
		}
	}
	t.Error("os_nobody_cron result not found")
}

func TestAuditOSNobodyCron_NonEmpty(t *testing.T) {
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if name == "/var/spool/cron/nobody" {
				return fakeFileInfo{name: "nobody", size: 42}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) { return nil, os.ErrNotExist },
	})
	withMockCmd(t, &mockCmd{})
	for _, r := range auditOS() {
		if r.Name == "os_nobody_cron" {
			if r.Status != "fail" {
				t.Errorf("nonempty nobody cron should fail, got %q", r.Status)
			}
			return
		}
	}
	t.Error("os_nobody_cron result not found")
}

func TestAuditOSSysctl_AllPass(t *testing.T) {
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		readFile: func(name string) ([]byte, error) {
			m := map[string]string{
				"/proc/sys/net/ipv4/tcp_syncookies":              "1\n",
				"/proc/sys/kernel/randomize_va_space":            "2\n",
				"/proc/sys/net/ipv4/conf/all/rp_filter":          "1\n",
				"/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts": "1\n",
				"/proc/sys/fs/protected_symlinks":                "1\n",
				"/proc/sys/fs/protected_hardlinks":               "1\n",
				"/etc/os-release":                                "PRETTY_NAME=\"Ubuntu 24.04\"\n",
			}
			if v, ok := m[name]; ok {
				return []byte(v), nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{})
	for _, r := range auditOS() {
		if strings.HasPrefix(r.Name, "os_sysctl_") && r.Status != "pass" {
			t.Errorf("%s should pass, got %q: %s", r.Name, r.Status, r.Message)
		}
	}
}

func TestAuditOSSysctl_SyncookiesOff(t *testing.T) {
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		readFile: func(name string) ([]byte, error) {
			if name == "/proc/sys/net/ipv4/tcp_syncookies" {
				return []byte("0\n"), nil
			}
			if name == "/etc/os-release" {
				return []byte("PRETTY_NAME=\"Ubuntu 24.04\"\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{})
	for _, r := range auditOS() {
		if r.Name == "os_sysctl_syncookies" {
			if r.Status != "fail" {
				t.Errorf("syncookies=0 should fail, got %q", r.Status)
			}
			return
		}
	}
	t.Error("os_sysctl_syncookies result not found")
}

func TestCheckUnnecessaryServicesResult(t *testing.T) {
	// checkUnnecessaryServices uses auditRunCmd (exec.CommandContext directly).
	// On macOS without systemctl, we get warn. Verify it produces exactly 1 result.
	results := checkUnnecessaryServices()
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != "pass" && results[0].Status != "warn" {
		t.Errorf("expected pass or warn, got %q", results[0].Status)
	}
}

func TestAuditFirewallNoRules(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) { return nil, fmt.Errorf("not found") },
	})
	withMockOS(t, &mockOS{readFile: func(name string) ([]byte, error) { return nil, os.ErrNotExist }})
	for _, r := range auditFirewall() {
		if r.Name == "fw_active" && r.Status != "fail" {
			t.Errorf("no rules should fail fw_active, got %q", r.Status)
		}
		if r.Name == "fw_default_policy" && r.Status != "fail" {
			t.Errorf("no rules should fail fw_default_policy, got %q", r.Status)
		}
	}
}

func TestAuditFirewallTelnetListening(t *testing.T) {
	procTCP := "  sl  local_address rem_address   st\n   0: 00000000:0017 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0\n"
	withMockCmd(t, &mockCmd{run: func(name string, args ...string) ([]byte, error) { return nil, fmt.Errorf("nope") }})
	withMockOS(t, &mockOS{readFile: func(name string) ([]byte, error) {
		if name == "/proc/net/tcp" {
			return []byte(procTCP), nil
		}
		return nil, os.ErrNotExist
	}})
	for _, r := range auditFirewall() {
		if r.Name == "fw_telnet" && r.Status != "fail" {
			t.Errorf("telnet listening should fail, got %q", r.Status)
		}
	}
}

func TestCheckMySQLExposedNotListening(t *testing.T) {
	withMockOS(t, &mockOS{readFile: func(name string) ([]byte, error) { return nil, os.ErrNotExist }})
	results := checkMySQLExposed(false, "", false, "")
	if len(results) != 1 || results[0].Status != "pass" {
		t.Errorf("not listening should pass, got %v", results)
	}
}

func TestCheckMySQLExposedLoopback(t *testing.T) {
	procTCP := "  sl  local_address rem_address   st\n   0: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0\n"
	withMockOS(t, &mockOS{readFile: func(name string) ([]byte, error) {
		if name == "/proc/net/tcp" {
			return []byte(procTCP), nil
		}
		return nil, os.ErrNotExist
	}})
	results := checkMySQLExposed(false, "", false, "")
	if len(results) != 1 || results[0].Status != "pass" {
		t.Errorf("loopback bind should pass, got %v", results)
	}
}

func TestCheckMySQLExposedWildcardNoFirewall(t *testing.T) {
	procTCP := "  sl  local_address rem_address   st\n   0: 00000000:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0\n"
	withMockOS(t, &mockOS{readFile: func(name string) ([]byte, error) {
		if name == "/proc/net/tcp" {
			return []byte(procTCP), nil
		}
		return nil, os.ErrNotExist
	}})
	results := checkMySQLExposed(false, "", false, "")
	if len(results) != 1 || results[0].Status != "fail" {
		t.Errorf("wildcard + no fw should fail, got %v", results)
	}
}

func TestCheckMySQLExposedWildcardWithIptablesDrop(t *testing.T) {
	procTCP := "  sl  local_address rem_address   st\n   0: 00000000:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0\n"
	withMockOS(t, &mockOS{readFile: func(name string) ([]byte, error) {
		if name == "/proc/net/tcp" {
			return []byte(procTCP), nil
		}
		return nil, os.ErrNotExist
	}})
	iptRules := "Chain INPUT (policy DROP)\ntarget prot source destination\nACCEPT tcp 0.0.0.0/0 0.0.0.0/0 tcp dpt:22\n"
	results := checkMySQLExposed(false, "", true, iptRules)
	if len(results) != 1 || results[0].Status != "warn" {
		t.Errorf("wildcard + iptables DROP should warn, got %v", results)
	}
}

func TestCheckMySQLExposedPrivateAddress(t *testing.T) {
	procTCP := "  sl  local_address rem_address   st\n   0: 6401A8C0:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0\n"
	withMockOS(t, &mockOS{readFile: func(name string) ([]byte, error) {
		if name == "/proc/net/tcp" {
			return []byte(procTCP), nil
		}
		return nil, os.ErrNotExist
	}})
	results := checkMySQLExposed(false, "", false, "")
	if len(results) != 1 || results[0].Status != "pass" {
		t.Errorf("private bind should pass, got %v", results)
	}
}

func TestCheckIPv6FirewallNoIPv6(t *testing.T) {
	withMockOS(t, &mockOS{readFile: func(name string) ([]byte, error) { return nil, os.ErrNotExist }})
	withMockCmd(t, &mockCmd{})
	results := checkIPv6Firewall()
	if len(results) != 1 || results[0].Status != "pass" {
		t.Errorf("no IPv6 should pass, got %v", results)
	}
}

func TestCheckIPv6FirewallOnlyLinkLocal(t *testing.T) {
	withMockOS(t, &mockOS{readFile: func(name string) ([]byte, error) {
		if name == "/proc/net/if_inet6" {
			return []byte("fe80000000000000021e06fffe123456 02 40 20 80 eth0\n"), nil
		}
		return nil, os.ErrNotExist
	}})
	withMockCmd(t, &mockCmd{})
	results := checkIPv6Firewall()
	if len(results) != 1 || results[0].Status != "pass" {
		t.Errorf("link-local only should pass, got %v", results)
	}
}

func TestCheckIPv6FirewallGlobalNoPolicy(t *testing.T) {
	withMockOS(t, &mockOS{readFile: func(name string) ([]byte, error) {
		if name == "/proc/net/if_inet6" {
			return []byte("26001f180026000100000000000000010040 02 40 00 80 eth0\n"), nil
		}
		return nil, os.ErrNotExist
	}})
	withMockCmd(t, &mockCmd{run: func(name string, args ...string) ([]byte, error) { return nil, fmt.Errorf("nope") }})
	results := checkIPv6Firewall()
	if len(results) != 1 || results[0].Status != "fail" {
		t.Errorf("global IPv6 + no policy should fail, got %v", results)
	}
}

func TestAuditCloudLinuxCageFSError(t *testing.T) {
	withMockOS(t, &mockOS{readFile: func(name string) ([]byte, error) { return nil, os.ErrNotExist }})
	withMockCmd(t, &mockCmd{run: func(name string, args ...string) ([]byte, error) { return nil, fmt.Errorf("nope") }})
	for _, r := range auditCloudLinux() {
		if r.Name == "cl_cagefs" && r.Status != "warn" {
			t.Errorf("cagefsctl error should warn, got %q", r.Status)
		}
	}
}

func TestAuditPHPWithEOLVersion(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, "ea-php") {
				return []string{"/opt/cpanel/ea-php74/root/etc/php.ini"}, nil
			}
			return nil, nil
		},
		readFile: func(name string) ([]byte, error) {
			if name == "/opt/cpanel/ea-php74/root/etc/php.ini" {
				return []byte("expose_php = On\nallow_url_fopen = On\nenable_dl = On\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{})
	found := map[string]string{}
	for _, r := range auditPHP("cpanel") {
		found[r.Name] = r.Status
	}
	if found["php_version_74"] != "fail" {
		t.Errorf("PHP 7.4 should fail, got %q", found["php_version_74"])
	}
	if found["php_disable_functions_74"] != "fail" {
		t.Errorf("empty disable_functions should fail, got %q", found["php_disable_functions_74"])
	}
	if found["php_enable_dl_74"] != "fail" {
		t.Errorf("enable_dl=On should fail, got %q", found["php_enable_dl_74"])
	}
}

func TestAuditPHPWithSecureConfig(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, "ea-php") {
				return []string{"/opt/cpanel/ea-php83/root/etc/php.ini"}, nil
			}
			return nil, nil
		},
		readFile: func(name string) ([]byte, error) {
			if name == "/opt/cpanel/ea-php83/root/etc/php.ini" {
				return []byte("disable_functions = passthru,shell_exec,popen\nexpose_php = Off\nallow_url_fopen = Off\nenable_dl = Off\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{})
	for _, r := range auditPHP("cpanel") {
		if r.Status == "fail" {
			t.Errorf("%s should not fail with secure config, got %q: %s", r.Name, r.Status, r.Message)
		}
	}
}

func TestAuditPHPWithCloudLinuxAltPHP(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, "ea-php") {
				return nil, nil
			}
			if strings.Contains(pattern, "alt/php") {
				return []string{"/opt/alt/php81/etc/php.ini"}, nil
			}
			return nil, nil
		},
		readFile: func(name string) ([]byte, error) {
			if name == "/opt/alt/php81/etc/php.ini" {
				return []byte("disable_functions = passthru\nexpose_php = Off\nallow_url_fopen = Off\nenable_dl = Off\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{})
	results := auditPHP("cloudlinux")
	if len(results) == 0 {
		t.Error("should produce results for alt-php")
	}
	for _, r := range results {
		if r.Name == "php_version_81" && r.Status != "pass" {
			t.Errorf("PHP 8.1 should pass, got %q", r.Status)
		}
	}
}

func TestAuditMailRootForwardMissing(t *testing.T) {
	withMockOS(t, &mockOS{
		stat:     func(name string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		readFile: func(name string) ([]byte, error) { return nil, os.ErrNotExist },
	})
	withMockCmd(t, &mockCmd{run: func(name string, args ...string) ([]byte, error) { return nil, fmt.Errorf("nope") }})
	for _, r := range auditMail() {
		if r.Name == "mail_root_forwarder" && r.Status != "warn" {
			t.Errorf("missing .forward should warn, got %q", r.Status)
		}
	}
}

func TestAuditMailRootForwardConfigured(t *testing.T) {
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if name == "/root/.forward" {
				return fakeFileInfo{name: ".forward", size: 25}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) { return nil, os.ErrNotExist },
	})
	withMockCmd(t, &mockCmd{run: func(name string, args ...string) ([]byte, error) { return nil, fmt.Errorf("nope") }})
	for _, r := range auditMail() {
		if r.Name == "mail_root_forwarder" && r.Status != "pass" {
			t.Errorf("configured .forward should pass, got %q", r.Status)
		}
	}
}

func TestAuditMailEximLoggingNoExim(t *testing.T) {
	// auditMail calls auditRunCmd (exec.CommandContext) for exim, not cmdExec.
	// On non-exim hosts, the exim command fails and we get a warn for logging.
	withMockOS(t, &mockOS{
		stat:     func(name string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		readFile: func(name string) ([]byte, error) { return nil, os.ErrNotExist },
	})
	withMockCmd(t, &mockCmd{})
	results := auditMail()
	for _, r := range results {
		if r.Name == "mail_exim_logging" {
			// Without exim binary, expect warn
			if r.Status != "warn" {
				t.Errorf("no exim should warn, got %q", r.Status)
			}
			return
		}
	}
	t.Error("mail_exim_logging result not found")
}

func TestAuditMailSecureAuth_Disabled(t *testing.T) {
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/exim.conf.localopts" {
				return []byte("require_secure_auth=0\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{})
	for _, r := range auditMail() {
		if r.Name == "mail_secure_auth" {
			if r.Status != "fail" {
				t.Errorf("secure_auth=0 should fail, got %q", r.Status)
			}
			return
		}
	}
	t.Error("mail_secure_auth result not found")
}

func TestAuditMailDovecotTLS_NoDovecot(t *testing.T) {
	withMockOS(t, &mockOS{
		stat:     func(name string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		readFile: func(name string) ([]byte, error) { return nil, os.ErrNotExist },
	})
	withMockCmd(t, &mockCmd{run: func(name string, args ...string) ([]byte, error) { return nil, fmt.Errorf("nope") }})
	for _, r := range auditMail() {
		if r.Name == "mail_dovecot_tls" && r.Status != "warn" {
			t.Errorf("no dovecot should warn, got %q", r.Status)
		}
	}
}

// ==========================================================================
// forwarder.go tests
// ==========================================================================

func TestIsPipeForwarderAutorespond(t *testing.T) {
	if isPipeForwarder("|/usr/local/cpanel/bin/autorespond arg1") {
		t.Error("autorespond should be safe")
	}
}

func TestIsPipeForwarderBoxtrapper(t *testing.T) {
	if isPipeForwarder("| /usr/local/cpanel/bin/boxtrapper deliver") {
		t.Error("boxtrapper should be safe")
	}
}

func TestIsPipeForwarderMailman(t *testing.T) {
	if isPipeForwarder("|/usr/local/cpanel/bin/mailman list_post") {
		t.Error("mailman should be safe")
	}
}

func TestIsExternalDest_AtSignAtEnd(t *testing.T) {
	if isExternalDest("user@", map[string]bool{"example.com": true}) {
		t.Error("trailing @ should not be external")
	}
}

func TestIsExternalDest_MultipleAtSigns(t *testing.T) {
	if isExternalDest("user@sub@example.com", map[string]bool{"example.com": true}) {
		t.Error("last @ domain is local, should not be external")
	}
}

func TestParseVfilterExternalDestsTabSeparated(t *testing.T) {
	dests := parseVfilterExternalDests("to\t\"admin@external.com\"\n", map[string]bool{"example.com": true})
	if len(dests) != 1 || dests[0] != "admin@external.com" {
		t.Errorf("tab to should work, got %v", dests)
	}
}

func TestParseVfilterExternalDestsUnclosedQuote(t *testing.T) {
	dests := parseVfilterExternalDests("to \"admin@external.com\n", map[string]bool{"example.com": true})
	if len(dests) != 0 {
		t.Error("unclosed quote should not yield results")
	}
}

func TestParseLocalDomainsContentVirtual(t *testing.T) {
	domains := parseLocalDomainsContent("example.com: alice\nexample.org: bob\n")
	if !domains["example.com"] || !domains["example.org"] {
		t.Error("should parse virtualdomains format")
	}
}

func TestParseLocalDomainsContentCaseInsensitive(t *testing.T) {
	domains := parseLocalDomainsContent("Example.COM\nFOO.ORG\n")
	if !domains["example.com"] || !domains["foo.org"] {
		t.Error("should lowercase domains")
	}
}

// ==========================================================================
// clean.go tests -- deeper branch coverage for surgical cleaning
// ==========================================================================

func TestRemoveIncludeInjectionsDevShm(t *testing.T) {
	out, removed := removeIncludeInjections("<?php\n@include('/dev/shm/backdoor.php');\necho 'legit';\n")
	if len(removed) == 0 {
		t.Fatal("expected removal for /dev/shm")
	}
	if !strings.Contains(out, "echo 'legit'") {
		t.Error("legitimate code removed")
	}
}

func TestRemoveIncludeInjectionsVarTmp(t *testing.T) {
	out, removed := removeIncludeInjections("<?php\n@include('/var/tmp/cache.php');\necho 'legit';\n")
	if len(removed) == 0 {
		t.Fatal("expected removal for /var/tmp")
	}
	if !strings.Contains(out, "echo 'legit'") {
		t.Error("legitimate code removed")
	}
}

func TestRemoveIncludeInjectionsRot13(t *testing.T) {
	out, removed := removeIncludeInjections("<?php\n@include(str_rot13('my_path'));\necho 'legit';\n")
	if len(removed) == 0 {
		t.Fatal("expected removal for str_rot13")
	}
	if !strings.Contains(out, "echo 'legit'") {
		t.Error("legitimate code removed")
	}
}

func TestRemoveIncludeInjectionsGzinflateInclude(t *testing.T) {
	out, removed := removeIncludeInjections("<?php\n@include(gzinflate(base64_decode('abc')));\necho 'legit';\n")
	if len(removed) == 0 {
		t.Fatal("expected removal for gzinflate")
	}
	if !strings.Contains(out, "echo 'legit'") {
		t.Error("legitimate code removed")
	}
}

func TestRemoveIncludeInjectionsVarWithoutObfuscation(t *testing.T) {
	input := "<?php\n$path = '/valid/path';\n@include($path)\n"
	out, removed := removeIncludeInjections(input)
	if len(removed) != 0 {
		t.Errorf("non-obfuscated var include should be kept: %v", removed)
	}
	if !strings.Contains(out, "@include($path)") {
		t.Error("should preserve non-obfuscated include")
	}
}

func TestRemoveIncludeInjectionsVarWithHexContext(t *testing.T) {
	_, removed := removeIncludeInjections("<?php\n$x = \"\\x41\\x42\\x43\";\n@include($x)\necho 1;\n")
	if len(removed) == 0 {
		t.Error("variable include with hex context should be removed")
	}
}

func TestRemovePrependInjectionNoCloseOpen(t *testing.T) {
	input := "<?php $data = 'string'; echo 'code';"
	out, removed := removePrependInjection(input)
	if len(removed) != 0 || out != input {
		t.Error("no ?><?php pattern should be untouched")
	}
}

func TestRemovePrependInjectionHighEntropyNoMaliciousPatterns(t *testing.T) {
	prefix := "<?php $data = '" + strings.Repeat("aB3$xZ9@mQ7!pL5&wK2", 20) + "';"
	input := prefix + "?><?php echo 'real'; ?>"
	out, removed := removePrependInjection(input)
	if len(removed) != 0 || out != input {
		t.Error("high entropy without malicious patterns should be untouched")
	}
}

func TestRemoveAppendInjectionWithEvalAfterClose(t *testing.T) {
	// Inject base64_decode after the legitimate ?> with no second closing ?>
	input := "<?php echo 1; ?>\nbase64_decode('malicious payload');"
	out, removed := removeAppendInjection(input)
	if len(removed) == 0 {
		t.Fatal("base64_decode after ?> should be removed")
	}
	if strings.Contains(out, "malicious") {
		t.Error("appended code still present")
	}
}

func TestRemoveAppendInjectionCleanAfterClose(t *testing.T) {
	input := "<?php echo 1; ?>\n\n\n"
	out, removed := removeAppendInjection(input)
	if len(removed) != 0 || out != input {
		t.Error("whitespace-only after ?> should be untouched")
	}
}

func TestRemoveAppendInjectionPSR12ShortFile(t *testing.T) {
	input := "<?php\necho 1;\n"
	out, removed := removeAppendInjection(input)
	if len(removed) != 0 || out != input {
		t.Error("short file should be untouched")
	}
}

func TestRemoveInlineEvalInjectionsLongLine(t *testing.T) {
	payload := "eval(base64_decode('" + strings.Repeat("QUJDRA==", 20) + "'));"
	input := "<?php\n" + payload + "\necho 'legit';\n"
	out, removed := removeInlineEvalInjections(input)
	if len(removed) == 0 {
		t.Fatal("long line should be removed")
	}
	if !strings.Contains(out, "echo 'legit'") {
		t.Error("legitimate code removed")
	}
}

func TestRemoveInlineEvalInjectionsGzuncompress(t *testing.T) {
	payload := "eval(gzuncompress(base64_decode('" + strings.Repeat("A", 100) + "')));"
	input := "<?php\n" + payload + "\necho 1;\n"
	out, removed := removeInlineEvalInjections(input)
	if len(removed) == 0 {
		t.Fatal("gzuncompress should be removed")
	}
	if !strings.Contains(out, "echo 1") {
		t.Error("legitimate code removed")
	}
}

func TestRemoveInlineEvalInjectionsStrRot13Long(t *testing.T) {
	payload := "eval(str_rot13('" + strings.Repeat("ABCD", 30) + "'));"
	input := "<?php\n" + payload + "\necho 1;\n"
	out, removed := removeInlineEvalInjections(input)
	if len(removed) == 0 {
		t.Fatal("str_rot13 should be removed")
	}
	if !strings.Contains(out, "echo 1") {
		t.Error("legitimate code removed")
	}
}

func TestRemoveMultiLayerBase64LegitimateCode(t *testing.T) {
	input := "<?php\n$x = base64_decode('dGVzdA==');\necho $x;\n"
	out, removed := removeMultiLayerBase64(input)
	if len(removed) != 0 || out != input {
		t.Error("single decode should be untouched")
	}
}

func TestRemoveChrPackInjectionsFewChrCalls(t *testing.T) {
	input := "<?php\n$x = chr(65).chr(66).chr(67);\necho $x;\n"
	out, removed := removeChrPackInjections(input)
	if len(removed) != 0 || out != input {
		t.Error("3 chr() calls should be kept")
	}
}

func TestRemoveHexVarInjectionsHarmless(t *testing.T) {
	payload := `echo "\x48\x65\x6c\x6c\x6f World from PHP script";`
	input := "<?php\n" + payload + "\necho 'done';\n"
	out, removed := removeHexVarInjections(input)
	if len(removed) != 0 {
		t.Errorf("harmless hex should not be removed: %v", removed)
	}
	if !strings.Contains(out, "done") {
		t.Error("content should be preserved")
	}
}

func TestShouldCleanWPAdminPath(t *testing.T) {
	if !ShouldCleanInsteadOfQuarantine("/home/user/public_html/wp-admin/includes/class-wp-screen.php") {
		t.Error("wp-admin should be cleaned")
	}
}

func TestShouldCleanThemeFile(t *testing.T) {
	if !ShouldCleanInsteadOfQuarantine("/home/user/public_html/wp-content/themes/flavor/functions.php") {
		t.Error("theme file should be cleaned")
	}
}

func TestShouldQuarantineUploadDir(t *testing.T) {
	if ShouldCleanInsteadOfQuarantine("/home/user/public_html/uploads/backdoor.php") {
		t.Error("uploads file should be quarantined")
	}
}

// ==========================================================================
// cpanel_logins.go tests
// ==========================================================================

func TestParseCpanelLoginWithAddressField(t *testing.T) {
	ip, account := parseCpanelLogin("[2026-04-12 10:00:00 +0000] info [cpaneld] 198.51.100.5 NEW admin:tok123 address=198.51.100.5")
	if ip != "198.51.100.5" || account != "admin" {
		t.Errorf("got ip=%q account=%q", ip, account)
	}
}

func TestParseCpanelLoginShortRest(t *testing.T) {
	ip, account := parseCpanelLogin("[2026-04-12 10:00:00 +0000] info [cpaneld] 1.2.3.4 X")
	if ip != "" || account != "" {
		t.Errorf("short rest should return empty, got ip=%q account=%q", ip, account)
	}
}

func TestParsePurgeAccountWithTokenField(t *testing.T) {
	account := parsePurgeAccount("[2026-04-12 10:38:18 +0200] info [security] internal PURGE alice:tok123 password_change")
	if account != "alice" {
		t.Errorf("got %q, want alice", account)
	}
}

func TestParsePurgeAccountEmptyAfterPurge(t *testing.T) {
	if got := parsePurgeAccount("[timestamp] internal PURGE"); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestParseSessionTimestampCloseBracketFirst(t *testing.T) {
	if ts := parseSessionTimestamp("]malformed["); !ts.IsZero() {
		t.Error("malformed bracket order should return zero time")
	}
}

func TestCheckCpanelFileManagerSaveFile(t *testing.T) {
	logData := "203.0.113.10 - alice [12/Apr/2026:10:00:00 +0000] \"POST /execute/fileman/save_file_content HTTP/1.1\" 200 512 \"-\" \"-\" 2083\n"
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if strings.Contains(name, "access_log") {
				tmp := t.TempDir() + "/al"
				_ = os.WriteFile(tmp, []byte(logData), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			if strings.Contains(name, "access_log") {
				return fakeFileInfo{name: "access_log", size: int64(len(logData))}, nil
			}
			return nil, os.ErrNotExist
		},
	})
	findings := CheckCpanelFileManager(context.Background(), &config.Config{}, nil)
	if len(findings) == 0 {
		t.Error("save_file_content from non-infra IP should produce findings")
	}
}

func TestCheckCpanelFileManagerRejected401(t *testing.T) {
	logData := "203.0.113.10 - alice [12/Apr/2026:10:00:00 +0000] \"POST /execute/fileman/upload_files HTTP/1.1\" 401 0 \"-\" \"-\" 2083\n"
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if strings.Contains(name, "access_log") {
				tmp := t.TempDir() + "/al"
				_ = os.WriteFile(tmp, []byte(logData), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			if strings.Contains(name, "access_log") {
				return fakeFileInfo{name: "access_log", size: int64(len(logData))}, nil
			}
			return nil, os.ErrNotExist
		},
	})
	findings := CheckCpanelFileManager(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("401 should be skipped, got %d findings", len(findings))
	}
}

func TestCheckCpanelLoginsSuppressed(t *testing.T) {
	logData := fmt.Sprintf("[%s] info [cpaneld] 203.0.113.5 NEW alice:tok1 address=203.0.113.5\n",
		time.Now().Add(-time.Minute).Format("2006-01-02 15:04:05 -0700"))
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if strings.Contains(name, "session_log") {
				tmp := t.TempDir() + "/sl"
				_ = os.WriteFile(tmp, []byte(logData), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			if strings.Contains(name, "session_log") {
				return fakeFileInfo{name: "session_log", size: int64(len(logData))}, nil
			}
			return nil, os.ErrNotExist
		},
	})
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	cfg := &config.Config{}
	cfg.Suppressions.SuppressCpanelLogin = true
	for _, f := range CheckCpanelLogins(context.Background(), cfg, store) {
		if f.Check == "cpanel_login" {
			t.Error("cpanel_login should be suppressed")
		}
	}
}

func TestCheckCpanelLoginsPasswordPurge(t *testing.T) {
	logData := fmt.Sprintf("[%s] info [security] internal PURGE alice:tok1 password_change\n",
		time.Now().Add(-time.Minute).Format("2006-01-02 15:04:05 -0700")) +
		fmt.Sprintf("[%s] info [security] internal PURGE alice:tok2 password_change\n",
			time.Now().Add(-30*time.Second).Format("2006-01-02 15:04:05 -0700"))
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if strings.Contains(name, "session_log") {
				tmp := t.TempDir() + "/sl"
				_ = os.WriteFile(tmp, []byte(logData), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			if strings.Contains(name, "session_log") {
				return fakeFileInfo{name: "session_log", size: int64(len(logData))}, nil
			}
			return nil, os.ErrNotExist
		},
	})
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	purgeCount := 0
	for _, f := range CheckCpanelLogins(context.Background(), &config.Config{}, store) {
		if f.Check == "cpanel_password_purge" {
			purgeCount++
		}
	}
	if purgeCount != 1 {
		t.Errorf("expected 1 deduplicated purge, got %d", purgeCount)
	}
}

func TestCheckCpanelLoginsLocalhostSkipped(t *testing.T) {
	logData := fmt.Sprintf("[%s] info [cpaneld] 127.0.0.1 NEW alice:tok1 address=127.0.0.1\n",
		time.Now().Add(-time.Minute).Format("2006-01-02 15:04:05 -0700"))
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if strings.Contains(name, "session_log") {
				tmp := t.TempDir() + "/sl"
				_ = os.WriteFile(tmp, []byte(logData), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			if strings.Contains(name, "session_log") {
				return fakeFileInfo{name: "session_log", size: int64(len(logData))}, nil
			}
			return nil, os.ErrNotExist
		},
	})
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	for _, f := range CheckCpanelLogins(context.Background(), &config.Config{}, store) {
		if f.Check == "cpanel_login" {
			t.Error("localhost should be skipped")
		}
	}
}

func TestHexToIPv4Loopback(t *testing.T) {
	if got := hexToIPv4("0100007F"); got != "127.0.0.1" {
		t.Errorf("got %q, want 127.0.0.1", got)
	}
}

func TestHexToIPv4TooShort(t *testing.T) {
	if got := hexToIPv4("0100"); got != "0100" {
		t.Errorf("short hex returned %q instead of as-is", got)
	}
}

func TestIsPortListeningTrueWithMockTCP(t *testing.T) {
	procTCP := "  sl  local_address rem_address   st\n   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0\n"
	withMockOS(t, &mockOS{readFile: func(name string) ([]byte, error) {
		if name == "/proc/net/tcp" {
			return []byte(procTCP), nil
		}
		return nil, os.ErrNotExist
	}})
	if !isPortListening(80) {
		t.Error("port 80 should be listening")
	}
}

func TestIsPortListeningFalseEstablished(t *testing.T) {
	procTCP := "  sl  local_address rem_address   st\n   0: 00000000:0050 00000000:0000 01 00000000:00000000 00:00000000 00000000 0\n"
	withMockOS(t, &mockOS{readFile: func(name string) ([]byte, error) {
		if name == "/proc/net/tcp" {
			return []byte(procTCP), nil
		}
		return nil, os.ErrNotExist
	}})
	if isPortListening(80) {
		t.Error("ESTABLISHED state should not be detected as listening")
	}
}

func TestIsPortListeningTcp6(t *testing.T) {
	procTCP6 := "  sl  local_address rem_address   st\n   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0\n"
	withMockOS(t, &mockOS{readFile: func(name string) ([]byte, error) {
		if name == "/proc/net/tcp6" {
			return []byte(procTCP6), nil
		}
		return nil, os.ErrNotExist
	}})
	if !isPortListening(443) {
		t.Error("port 443 on tcp6 should be listening")
	}
}

func TestGetListeningAddrFound(t *testing.T) {
	procTCP := "  sl  local_address rem_address   st\n   0: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0\n"
	withMockOS(t, &mockOS{readFile: func(name string) ([]byte, error) {
		if name == "/proc/net/tcp" {
			return []byte(procTCP), nil
		}
		return nil, os.ErrNotExist
	}})
	if addr := getListeningAddr(3306); addr != "0100007F" {
		t.Errorf("expected 0100007F, got %q", addr)
	}
}

func TestGetListeningAddrNotFound(t *testing.T) {
	procTCP := "  sl  local_address rem_address   st\n   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0\n"
	withMockOS(t, &mockOS{readFile: func(name string) ([]byte, error) {
		if name == "/proc/net/tcp" {
			return []byte(procTCP), nil
		}
		return nil, os.ErrNotExist
	}})
	if addr := getListeningAddr(3306); addr != "" {
		t.Errorf("expected empty, got %q", addr)
	}
}

func TestReadOSReleasePretty_Found(t *testing.T) {
	withMockOS(t, &mockOS{readFile: func(name string) ([]byte, error) {
		if name == "/etc/os-release" {
			return []byte("ID=ubuntu\nPRETTY_NAME=\"Ubuntu 24.04.2 LTS\"\n"), nil
		}
		return nil, os.ErrNotExist
	}})
	if got := readOSReleasePretty(); got != "Ubuntu 24.04.2 LTS" {
		t.Errorf("got %q", got)
	}
}

func TestReadOSReleasePretty_Missing(t *testing.T) {
	withMockOS(t, &mockOS{readFile: func(name string) ([]byte, error) { return nil, os.ErrNotExist }})
	if got := readOSReleasePretty(); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestEvaluateDistroEOL_EOLAlma7(t *testing.T) {
	results := evaluateDistroEOL(platform.Info{OS: platform.OSAlma, OSVersion: "7.9"}, "AlmaLinux 7.9")
	if len(results) != 1 || results[0].Status != "fail" {
		t.Errorf("Alma 7 should fail, got %v", results)
	}
}

func TestEvaluateDistroEOL_FallbackPrettyName(t *testing.T) {
	results := evaluateDistroEOL(platform.Info{OS: platform.OSAlma, OSVersion: "9.3"}, "")
	if len(results) != 1 || results[0].Status != "pass" {
		t.Errorf("Alma 9 should pass, got %v", results)
	}
	if !strings.Contains(results[0].Message, "almalinux") {
		t.Errorf("fallback message should contain OS name, got %q", results[0].Message)
	}
}

func TestParsePHPVersionTripleDotVersion(t *testing.T) {
	if major, minor := parsePHPVersion("8.2.15"); major != 8 || minor != 2 {
		t.Errorf("got %d.%d, want 8.2", major, minor)
	}
}

func TestParsePHPVersionSingleDigit(t *testing.T) {
	if major, minor := parsePHPVersion("7"); major != 0 || minor != 0 {
		t.Errorf("single digit should return 0,0, got %d,%d", major, minor)
	}
}

func TestParseCpanelConfigCommentsAndBlanks(t *testing.T) {
	withMockOS(t, &mockOS{readFile: func(name string) ([]byte, error) {
		return []byte("# comment\n\nalwaysredirecttossl=1\nresetpass=0\n"), nil
	}})
	conf := parseCpanelConfig("/var/cpanel/cpanel.config")
	if conf["alwaysredirecttossl"] != "1" || conf["resetpass"] != "0" {
		t.Errorf("unexpected config: %v", conf)
	}
}

// ==========================================================================
// Helper type
// ==========================================================================

type fakeFileInfoWithMode struct {
	name string
	size int64
	mode os.FileMode
}

func (f fakeFileInfoWithMode) Name() string       { return f.name }
func (f fakeFileInfoWithMode) Size() int64        { return f.size }
func (f fakeFileInfoWithMode) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfoWithMode) ModTime() time.Time { return time.Now() }
func (f fakeFileInfoWithMode) IsDir() bool        { return false }
func (f fakeFileInfoWithMode) Sys() interface{}   { return nil }
