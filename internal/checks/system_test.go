package checks

import (
	"strings"
	"testing"
)

// parseDpkgVerifyOutput mirrors the flag/conffile parsing in checkDpkgVerify.
// It does NOT decide which files are reported by type -- production filters the
// parsed candidates through looksExecutableOrLibrary, so this pure helper
// returns every non-conffile size/checksum mismatch.
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

func TestParseDpkgVerifyOutput_ReturnsNonConfigMismatch(t *testing.T) {
	// Parsing no longer filters by path; checkDpkgVerify decides reporting by
	// file type. A non-conffile mismatch is returned at the parse layer.
	output := "??5??????  /usr/lib/x86_64-linux-gnu/libssl.so.3"
	got := parseDpkgVerifyOutput("libssl3", output)
	if len(got) != 1 || got[0] != "/usr/lib/x86_64-linux-gnu/libssl.so.3" {
		t.Errorf("non-conffile mismatch should be returned, got %v", got)
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
