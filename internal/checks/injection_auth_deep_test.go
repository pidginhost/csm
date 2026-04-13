package checks

import (
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// --- getAuditShadowInfo (auth.go:171, 12.5%) ----------------------------

func TestGetAuditShadowInfo_WithExeAndComm(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "grep" && len(args) > 0 && args[0] == "csm_shadow_change" {
				return []byte(`type=SYSCALL msg=audit(1712345678.123:456): arch=c000003e syscall=2 success=yes exit=0 exe="/usr/sbin/chpasswd" comm="chpasswd"` + "\n"), nil
			}
			return nil, nil
		},
	})

	info := getAuditShadowInfo()
	if !strings.Contains(info, "chpasswd") {
		t.Errorf("expected chpasswd in info, got %q", info)
	}
}

func TestGetAuditShadowInfo_NoAuditLog(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(string, ...string) ([]byte, error) {
			return nil, os.ErrNotExist
		},
	})

	info := getAuditShadowInfo()
	if info != "" {
		t.Errorf("expected empty, got %q", info)
	}
}

func TestGetAuditShadowInfo_EmptyOutput(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(string, ...string) ([]byte, error) {
			return []byte(""), nil
		},
	})

	info := getAuditShadowInfo()
	if info != "" {
		t.Errorf("expected empty, got %q", info)
	}
}

func TestGetAuditShadowInfo_HexComm(t *testing.T) {
	// "passwd" in hex
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			return []byte(`type=SYSCALL exe="/usr/bin/passwd" comm=706173737764` + "\n"), nil
		},
	})

	info := getAuditShadowInfo()
	if !strings.Contains(info, "passwd") {
		t.Errorf("expected passwd in info, got %q", info)
	}
}

// --- isInfraShadowChange (auth.go:387, 22.7%) ----------------------------

func TestIsInfraShadowChange_InfraIP(t *testing.T) {
	logData := "[2026-04-12 10:00:00] info [whostmgr] 10.0.0.1 PURGE admin:token password_change\n"
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if strings.Contains(name, "session_log") {
				tmp := t.TempDir() + "/session_log"
				_ = os.WriteFile(tmp, []byte(logData), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}
	if !isInfraShadowChange(cfg) {
		t.Error("expected true for infra IP")
	}
}

func TestIsInfraShadowChange_ExternalIP(t *testing.T) {
	logData := "[2026-04-12 10:00:00] info [xml-api] 203.0.113.5 PURGE admin:token password_change\n"
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if strings.Contains(name, "session_log") {
				tmp := t.TempDir() + "/session_log"
				_ = os.WriteFile(tmp, []byte(logData), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}
	if isInfraShadowChange(cfg) {
		t.Error("expected false for external IP")
	}
}

func TestIsInfraShadowChange_NoPurge(t *testing.T) {
	logData := "[2026-04-12 10:00:00] info [whostmgr] 10.0.0.1 LOGIN admin:token\n"
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if strings.Contains(name, "session_log") {
				tmp := t.TempDir() + "/session_log"
				_ = os.WriteFile(tmp, []byte(logData), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	if isInfraShadowChange(cfg) {
		t.Error("expected false when no PURGE events")
	}
}

func TestIsInfraShadowChange_NoFile(t *testing.T) {
	withMockOS(t, &mockOS{
		open: func(string) (*os.File, error) { return nil, os.ErrNotExist },
	})

	cfg := &config.Config{}
	if isInfraShadowChange(cfg) {
		t.Error("expected false when no session_log")
	}
}

func TestIsInfraShadowChange_InternalEvent(t *testing.T) {
	logData := "[2026-04-12 10:00:00] info [security] internal PURGE admin:token password_change\n"
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if strings.Contains(name, "session_log") {
				tmp := t.TempDir() + "/session_log"
				_ = os.WriteFile(tmp, []byte(logData), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	// "internal" events are counted as found (foundAny=true) and are not
	// checked against isInfraIP (continue before the check), so allInfra
	// stays true. Result: foundAny && allInfra == true.
	if !isInfraShadowChange(cfg) {
		t.Error("expected true when only internal events (they are safe)")
	}
}

// --- AutoQuarantineFiles (autoresponse.go:98, 3.5%) -----------------------

func TestAutoQuarantineFiles_SkipsNonCritical(t *testing.T) {
	withMockOS(t, &mockOS{
		lstat: func(string) (os.FileInfo, error) {
			return fakeFileInfo{name: "wso.php", size: 500}, nil
		},
	})

	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.QuarantineFiles = true

	findings := []alert.Finding{
		{Severity: alert.Warning, Check: "webshell", FilePath: "/home/alice/public_html/wso.php"},
	}
	actions := AutoQuarantineFiles(cfg, findings)
	if len(actions) != 0 {
		t.Errorf("expected 0 for non-critical, got %d", len(actions))
	}
}

func TestAutoQuarantineFiles_SkipsUnknownCheck(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.QuarantineFiles = true

	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "unknown_check", FilePath: "/home/alice/public_html/wso.php"},
	}
	actions := AutoQuarantineFiles(cfg, findings)
	if len(actions) != 0 {
		t.Errorf("expected 0 for unknown check, got %d", len(actions))
	}
}

func TestAutoQuarantineFiles_SkipsMissingFile(t *testing.T) {
	withMockOS(t, &mockOS{
		lstat: func(string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.QuarantineFiles = true

	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", FilePath: "/home/alice/public_html/wso.php"},
	}
	actions := AutoQuarantineFiles(cfg, findings)
	if len(actions) != 0 {
		t.Errorf("expected 0 for missing file, got %d", len(actions))
	}
}

func TestAutoQuarantineFiles_SkipsNoPath(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.QuarantineFiles = true

	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "no path here"},
	}
	actions := AutoQuarantineFiles(cfg, findings)
	if len(actions) != 0 {
		t.Errorf("expected 0 for no path, got %d", len(actions))
	}
}

// --- parseTimeMin (auth.go) -----------------------------------------------

func TestParseTimeMin(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"10:30", 630},
		{"0:05", 5},
		{"23:59", 1439},
		{"invalid", 0},
		{"", 0},
	}
	for _, tc := range tests {
		if got := parseTimeMin(tc.in); got != tc.want {
			t.Errorf("parseTimeMin(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
