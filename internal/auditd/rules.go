package auditd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
)

type commandRunner func(name string, args ...string) error

func runCommand(name string, args ...string) error {
	// #nosec G204 -- production callers supply the fixed augenrules command or
	// the absolute executable returned by exec.LookPath, never user input.
	return exec.Command(name, args...).Run()
}

const rulesPath = "/etc/audit/rules.d/csm.rules"

const rules = `## Continuous Security Monitor - auditd rules

# Password/auth file changes
-w /etc/shadow -p wa -k csm_shadow_change
-w /etc/passwd -p wa -k csm_passwd_change
-w /etc/group -p wa -k csm_group_change

# SSH config and keys
-w /etc/ssh/sshd_config -p wa -k csm_sshd_change
-w /root/.ssh/authorized_keys -p wa -k csm_root_ssh_keys

# WHM API tokens
-w /var/cpanel/authn/api_tokens_v2/ -p wa -k csm_whm_api_tokens

# Crontab modifications
-w /var/spool/cron/ -p wa -k csm_crontab_change
-w /etc/cron.d/ -p wa -k csm_crond_change

# Password change commands
-w /usr/bin/passwd -p x -k csm_passwd_exec
-w /usr/sbin/chpasswd -p x -k csm_chpasswd_exec

# CSM binary self-protection
-w /opt/csm/csm -p wa -k csm_binary_tamper
-w /etc/csm/csm.yaml -p wa -k csm_config_tamper
-w /opt/csm/csm.yaml -p wa -k csm_config_tamper

# Execution from suspicious locations
-a always,exit -F arch=b64 -S execve -F dir=/tmp -k csm_exec_tmp
-a always,exit -F arch=b64 -S execve -F dir=/dev/shm -k csm_exec_shm

# User account modifications
-w /usr/sbin/useradd -p x -k csm_useradd
-w /usr/sbin/usermod -p x -k csm_usermod
-w /usr/sbin/userdel -p x -k csm_userdel

# AF_ALG socket creation — CVE-2026-31431 "Copy Fail" exploit signature.
# AF_ALG (numeric family 38) is essentially never used by cPanel/PHP
# workloads, so any non-system UID hitting socket(AF_ALG, ...) is suspicious.
# Filter on uid, not auid: service-launched PHP/cPanel workers commonly have
# unset audit login UID while still running as the account user.
# Two rules — b64 covers native 64-bit binaries, b32 closes the i386
# emulation evasion path on x86_64 hosts with 32-bit compat enabled.
-a always,exit -F arch=b64 -S socket -F a0=38 -F uid>=1000 -k csm_af_alg_socket
-a always,exit -F arch=b32 -S socket -F a0=38 -F uid>=1000 -k csm_af_alg_socket
`

func Deploy() error {
	return deployRules(rulesPath, runCommand)
}

func deployRules(path string, run commandRunner) error {
	// #nosec G306 -- /etc/audit/rules.d/csm.rules is read by the auditd
	// tooling (augenrules) on reload; 0640 keeps world-read off.
	if err := os.WriteFile(path, []byte(rules), 0640); err != nil {
		return err
	}
	return run("augenrules", "--load")
}

// EnsureDeployed compares the on-disk rules file to the embedded rules
// constant and re-runs Deploy if they differ. Used by the daemon at
// startup so a CSM upgrade that ships new auditd rules does not silently
// remain inactive when the package postinstall did not invoke Deploy.
//
// Returns (redeployed, err): redeployed=true when the file was updated,
// false when it already matched. err is non-nil only when an unexpected
// I/O failure occurred; a missing rules file is treated as "drift" and
// triggers Deploy.
func EnsureDeployed() (bool, error) {
	current, err := os.ReadFile(rulesPath)
	if err == nil && string(current) == rules {
		return false, nil
	}
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if err := Deploy(); err != nil {
		return false, err
	}
	return true, nil
}

func Remove() error {
	return removeRules(rulesPath, exec.LookPath, runCommand)
}

func removeRules(path string, lookPath func(string) (string, error), run commandRunner) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing audit rules: %w", err)
	}
	command, err := lookPath("augenrules")
	if errors.Is(err, exec.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("locating augenrules: %w", err)
	}
	if err := run(command, "--load"); err != nil {
		return fmt.Errorf("reloading audit rules: %w", err)
	}
	return nil
}
