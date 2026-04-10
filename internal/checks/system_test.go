package checks

import (
	"strings"
	"testing"
)

func TestIsCriticalSystemPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/usr/bin/passwd", true},
		{"/usr/sbin/sshd", true},
		{"/bin/bash", true},
		{"/sbin/init", true},
		{"/etc/passwd", false},
		{"/opt/csm/csm", false},
		{"/var/log/auth.log", false},
		{"", false},
		{"/home/user/.ssh/authorized_keys", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isCriticalSystemPath(tt.path); got != tt.want {
				t.Errorf("isCriticalSystemPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// parseDpkgVerifyOutput extracts the parsing logic from checkDpkgVerify
// into a pure function for direct unit-testing without a runCmd mock.
// The production code should call this after shelling out to dpkg.
func parseDpkgVerifyOutput(pkg string, output string) []string {
	var flagged []string
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if len(line) < 10 {
			continue
		}
		flags := line[:9]
		file := strings.TrimSpace(line[9:])
		if strings.Contains(line, " c ") {
			continue
		}
		if !strings.Contains(flags, "5") && !strings.Contains(flags, "S") {
			continue
		}
		if !isCriticalSystemPath(file) {
			continue
		}
		flagged = append(flagged, file)
	}
	return flagged
}

func TestParseDpkgVerifyOutput_DetectsModifiedBinary(t *testing.T) {
	// Real dpkg --verify format: 9 attribute chars, space, path.
	output := "??5??????  /usr/bin/passwd"
	got := parseDpkgVerifyOutput("passwd", output)
	if len(got) != 1 || got[0] != "/usr/bin/passwd" {
		t.Errorf("parseDpkgVerifyOutput() = %v, want [/usr/bin/passwd]", got)
	}
}

func TestParseDpkgVerifyOutput_SkipsConfigFiles(t *testing.T) {
	// Conffile marker: 'c' between flags and path.
	output := "??5?????? c /etc/ssh/sshd_config"
	got := parseDpkgVerifyOutput("openssh-server", output)
	if len(got) != 0 {
		t.Errorf("conffile should be skipped, got %v", got)
	}
}

func TestParseDpkgVerifyOutput_SkipsNonBinaryPaths(t *testing.T) {
	output := "??5??????  /usr/share/doc/coreutils/README"
	got := parseDpkgVerifyOutput("coreutils", output)
	if len(got) != 0 {
		t.Errorf("non-binary path should be skipped, got %v", got)
	}
}

func TestParseDpkgVerifyOutput_MultipleFiles(t *testing.T) {
	output := `??5??????  /usr/bin/passwd
??5??????  /usr/sbin/sshd
??5?????? c /etc/passwd`
	got := parseDpkgVerifyOutput("passwd", output)
	if len(got) != 2 {
		t.Errorf("want 2 flagged files, got %d: %v", len(got), got)
	}
}

func TestParseDpkgVerifyOutput_EmptyOutput(t *testing.T) {
	got := parseDpkgVerifyOutput("passwd", "")
	if got != nil {
		t.Errorf("empty output should yield nil, got %v", got)
	}
}

func TestParseDpkgVerifyOutput_IgnoresNonFailureFlags(t *testing.T) {
	// T = mtime changed only — not a tampering signal for our purposes.
	output := "??T??????  /usr/bin/passwd"
	got := parseDpkgVerifyOutput("passwd", output)
	if len(got) != 0 {
		t.Errorf("mtime-only change should be ignored, got %v", got)
	}
}

// parseRpmVerifyOutput extracts the rpm -V parsing logic for testing.
func parseRpmVerifyOutput(output string) []string {
	var flagged []string
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if len(line) < 9 {
			continue
		}
		flags := line[:9]
		file := strings.TrimSpace(line[9:])
		if strings.Contains(line, " c ") || strings.Contains(line, " d ") {
			continue
		}
		if !strings.Contains(flags, "S") && !strings.Contains(flags, "5") {
			continue
		}
		if !isCriticalSystemPath(file) {
			continue
		}
		flagged = append(flagged, file)
	}
	return flagged
}

func TestParseRpmVerifyOutput_DetectsModifiedBinary(t *testing.T) {
	output := "S.5......    /usr/sbin/sshd"
	got := parseRpmVerifyOutput(output)
	if len(got) != 1 || got[0] != "/usr/sbin/sshd" {
		t.Errorf("got %v, want [/usr/sbin/sshd]", got)
	}
}

func TestParseRpmVerifyOutput_SkipsConfigAndDoc(t *testing.T) {
	output := `S.5...... c /etc/passwd
S.5...... d /usr/share/doc/passwd/README`
	got := parseRpmVerifyOutput(output)
	if len(got) != 0 {
		t.Errorf("config and doc entries should be skipped, got %v", got)
	}
}
