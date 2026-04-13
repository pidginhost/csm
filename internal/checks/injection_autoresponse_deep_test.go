package checks

import (
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// --- getProcessUID --------------------------------------------------------

func TestGetProcessUID_Found(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if strings.Contains(name, "/proc/1234/status") {
				return []byte("Name:\ttest\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	if uid := getProcessUID("1234"); uid != "1000" {
		t.Errorf("got %q, want 1000", uid)
	}
}

func TestGetProcessUID_NotFound(t *testing.T) {
	withMockOS(t, &mockOS{readFile: func(string) ([]byte, error) { return nil, os.ErrNotExist }})
	if uid := getProcessUID("9999"); uid != "" {
		t.Errorf("got %q, want empty", uid)
	}
}

func TestGetProcessUID_NoUidLine(t *testing.T) {
	withMockOS(t, &mockOS{readFile: func(string) ([]byte, error) { return []byte("Name:\ttest\nGid:\t1000\n"), nil }})
	if uid := getProcessUID("1234"); uid != "" {
		t.Errorf("got %q, want empty", uid)
	}
}

// --- getProcessExe --------------------------------------------------------

func TestGetProcessExe_Found(t *testing.T) {
	withMockOS(t, &mockOS{
		readlink: func(name string) (string, error) {
			if strings.Contains(name, "/proc/1234/exe") {
				return "/usr/bin/python3", nil
			}
			return "", os.ErrNotExist
		},
	})
	if exe := getProcessExe("1234"); exe != "/usr/bin/python3" {
		t.Errorf("got %q", exe)
	}
}

func TestGetProcessExe_NotFound(t *testing.T) {
	withMockOS(t, &mockOS{readlink: func(string) (string, error) { return "", os.ErrNotExist }})
	if exe := getProcessExe("9999"); exe != "" {
		t.Errorf("got %q, want empty", exe)
	}
}

// --- isSafeProcess --------------------------------------------------------

func TestIsSafeProcess(t *testing.T) {
	tests := []struct {
		exe  string
		safe bool
	}{
		{"/usr/local/cpanel/whostmgrd", true},
		{"/usr/sbin/sshd", true},
		{"/usr/bin/python3", true},
		{"/opt/cpanel/ea-php82/root/usr/bin/php", true},
		{"/home/alice/.gsocket/gs-netcat", false},
		{"/tmp/botnet", false},
		{"", false},
	}
	for _, tc := range tests {
		if got := isSafeProcess(tc.exe); got != tc.safe {
			t.Errorf("isSafeProcess(%q) = %v, want %v", tc.exe, got, tc.safe)
		}
	}
}

// --- extractPID -----------------------------------------------------------

func TestExtractPID(t *testing.T) {
	tests := []struct {
		details, want string
	}{
		{"PID: 1234, user: alice", "1234"},
		{"PID: 56789", "56789"},
		{"no pid here", ""},
		{"", ""},
	}
	for _, tc := range tests {
		if got := extractPID(tc.details); got != tc.want {
			t.Errorf("extractPID(%q) = %q, want %q", tc.details, got, tc.want)
		}
	}
}

// --- extractFilePath ------------------------------------------------------

func TestExtractFilePath(t *testing.T) {
	tests := []struct {
		msg, want string
	}{
		{"Webshell at /home/alice/public_html/wso.php", "/home/alice/public_html/wso.php"},
		{"Found in /tmp/evil.php, size 1234", "/tmp/evil.php"},
		{"Found /dev/shm/.hidden with bad content", "/dev/shm/.hidden"},
		{"No path here", ""},
	}
	for _, tc := range tests {
		if got := extractFilePath(tc.msg); got != tc.want {
			t.Errorf("extractFilePath(%q) = %q, want %q", tc.msg, got, tc.want)
		}
	}
}

// --- AutoKillProcesses ----------------------------------------------------

func TestAutoKillProcesses_Disabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = false
	if actions := AutoKillProcesses(cfg, []alert.Finding{{Severity: alert.Critical, Check: "fake_kernel_thread"}}); len(actions) != 0 {
		t.Errorf("expected no actions when disabled, got %d", len(actions))
	}
}

func TestAutoKillProcesses_SkipsNonCritical(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(string) ([]byte, error) { return []byte("Uid:\t1000\n"), nil },
		readlink: func(string) (string, error) { return "/home/alice/.bad", nil },
	})
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.KillProcesses = true
	findings := []alert.Finding{
		{Severity: alert.Warning, Check: "fake_kernel_thread", PID: 12345},
		{Severity: alert.Critical, Check: "webshell", PID: 12346},
	}
	if actions := AutoKillProcesses(cfg, findings); len(actions) != 0 {
		t.Errorf("expected 0 actions, got %d", len(actions))
	}
}

func TestAutoKillProcesses_SkipsRootProcess(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(string) ([]byte, error) { return []byte("Name:\ttest\nUid:\t0\t0\t0\t0\n"), nil },
	})
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.KillProcesses = true
	findings := []alert.Finding{{Severity: alert.Critical, Check: "fake_kernel_thread", PID: 12345}}
	if actions := AutoKillProcesses(cfg, findings); len(actions) != 0 {
		t.Errorf("expected 0 for root, got %d", len(actions))
	}
}

func TestAutoKillProcesses_SkipsSafeProcess(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(string) ([]byte, error) { return []byte("Name:\ttest\nUid:\t1000\t1000\t1000\t1000\n"), nil },
		readlink: func(string) (string, error) { return "/usr/sbin/sshd", nil },
	})
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.KillProcesses = true
	findings := []alert.Finding{{Severity: alert.Critical, Check: "fake_kernel_thread", PID: 12345}}
	if actions := AutoKillProcesses(cfg, findings); len(actions) != 0 {
		t.Errorf("expected 0 for safe, got %d", len(actions))
	}
}

// --- AutoQuarantineFiles --------------------------------------------------

func TestAutoQuarantineFiles_Disabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = false
	if actions := AutoQuarantineFiles(cfg, []alert.Finding{{Check: "webshell"}}); len(actions) != 0 {
		t.Errorf("expected 0, got %d", len(actions))
	}
}

// --- AutoFixPermissions ---------------------------------------------------

func TestAutoFixPermissions_Disabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = false
	actions, keys := AutoFixPermissions(cfg, []alert.Finding{{Check: "world_writable_php"}})
	if len(actions) != 0 || len(keys) != 0 {
		t.Error("expected empty when disabled")
	}
}

func TestAutoFixPermissions_SkipsNonMatching(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.EnforcePermissions = true
	actions, keys := AutoFixPermissions(cfg, []alert.Finding{{Check: "webshell"}})
	if len(actions) != 0 || len(keys) != 0 {
		t.Error("expected empty for non-matching check")
	}
}

// --- InlineQuarantine (empty data) ----------------------------------------

func TestInlineQuarantine_EmptyData(t *testing.T) {
	f := alert.Finding{Check: "webshell", Message: "suspicious code"}
	_, ok := InlineQuarantine(f, "/nonexistent/file.php", nil)
	if ok {
		t.Error("expected false for nil data")
	}
}
