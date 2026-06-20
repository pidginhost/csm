package checks

import (
	"fmt"
	"os"
	"strings"
)

// allowedUID0 are the system accounts that legitimately carry UID 0; the
// detector and the re-check share this list so they agree on what counts as
// "unauthorized".
var allowedUID0 = map[string]bool{
	"root": true, "sync": true, "shutdown": true,
	"halt": true, "operator": true,
}

// classifyUID0Line parses one /etc/passwd line and reports the account name and
// whether it is an unauthorized UID 0 account.
func classifyUID0Line(line string) (user string, unauthorized bool) {
	fields := strings.Split(line, ":")
	if len(fields) < 4 {
		return "", false
	}
	user = fields[0]
	return user, fields[2] == "0" && !allowedUID0[user]
}

// verifyUID0Account re-reads /etc/passwd and resolves the finding when the
// flagged account is gone, no longer UID 0, or now an allowed system account.
// Read-only; an unreadable /etc/passwd returns Checked:false rather than a
// false clear.
func verifyUID0Account(message string) VerifyResult {
	rest, ok := strings.CutPrefix(message, "Unauthorized UID 0 account: ")
	if !ok {
		return VerifyResult{Checked: false, Detail: "could not determine the account from the finding"}
	}
	user := strings.TrimSpace(rest)
	if user == "" {
		return VerifyResult{Checked: false, Detail: "could not determine the account from the finding"}
	}

	data, err := osFS.ReadFile("/etc/passwd")
	if err != nil {
		return VerifyResult{Checked: false, Detail: fmt.Sprintf("cannot read /etc/passwd: %v", err)}
	}
	for _, line := range strings.Split(string(data), "\n") {
		u, unauthorized := classifyUID0Line(line)
		if u != user {
			continue
		}
		if unauthorized {
			return VerifyResult{Checked: true, Resolved: false, Detail: fmt.Sprintf("%s is still an unauthorized UID 0 account", user)}
		}
		return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("%s is no longer an unauthorized UID 0 account", user)}
	}
	return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("account %s no longer exists", user)}
}

// verifySuidCleared re-stats a flagged SUID binary and resolves the finding
// when the file is gone or no longer carries the setuid bit. Bounded to the
// same roots scanForSUID covers (/home, /tmp, /dev/shm, /var/tmp).
func verifySuidCleared(path string) VerifyResult {
	if path == "" {
		return VerifyResult{Checked: false, Detail: "could not extract file path from finding"}
	}
	clean, info, exists, err := readOnlyFixPath(path, fixQuarantineAllowedRoots)
	if err != nil {
		return VerifyResult{Checked: false, Detail: err.Error()}
	}
	if !exists {
		return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("SUID binary no longer present: %s", clean)}
	}
	if !info.Mode().IsRegular() {
		return VerifyResult{Checked: false, Detail: "path is not a regular file; not auto-verifiable"}
	}
	if info.Mode()&os.ModeSetuid != 0 {
		return VerifyResult{Checked: true, Resolved: false, Detail: fmt.Sprintf("file is still setuid (mode %s)", info.Mode())}
	}
	return VerifyResult{Checked: true, Resolved: true, Detail: fmt.Sprintf("file is no longer setuid (mode %s)", info.Mode())}
}
