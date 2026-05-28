package checks

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/state"
)

// CheckHealth verifies that CSM's dependencies are working.
// Reports on missing external commands, broken auditd, etc.
func CheckHealth(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding
	info := platform.Detect()

	// Required commands depend on the platform. On plain Linux hosts we
	// don't need Exim/cPanel-specific tooling.
	requiredCmds := platformRequiredCommands(info)
	for _, cmd := range requiredCmds {
		if _, err := cmdExec.LookPath(cmd); err != nil {
			findings = append(findings, alert.Finding{
				Severity: alert.Warning,
				Check:    "csm_health",
				Message:  fmt.Sprintf("Required command not found: %s", cmd),
				Details:  "Some checks will be skipped",
			})
		}
	}

	// Optional commands. Only complain about cPanel tools on cPanel hosts.
	optionalCmds := map[string]string{
		"wp": "WordPress core integrity check will be skipped",
	}
	if info.IsCPanel() {
		optionalCmds["whmapi1"] = "WHM API token check will be skipped"
	}
	for cmd, impact := range optionalCmds {
		if _, err := cmdExec.LookPath(cmd); err != nil {
			findings = append(findings, alert.Finding{
				Severity: alert.Warning,
				Check:    "csm_health",
				Message:  fmt.Sprintf("Optional command not found: %s", cmd),
				Details:  impact,
			})
		}
	}

	// Check auditd is running and has CSM rules
	out, _ := runCmd("auditctl", "-l")
	if out != nil {
		rules := string(out)
		if !strings.Contains(rules, "csm_shadow_change") {
			findings = append(findings, alert.Finding{
				Severity: alert.Warning,
				Check:    "csm_health",
				Message:  "auditd CSM rules not loaded",
				Details:  "Run 'csm install' to deploy auditd rules, then 'service auditd restart'",
			})
		}
	}

	if cfg != nil && cfg.BPFEnforcement.Enabled && cfg.BPFEnforcement.DirectSMTPEgress {
		switch active := bpf.ActiveKind("connection_tracker"); active {
		case bpf.BackendLegacy, bpf.BackendNone:
			message := "BPF enforcement enabled but connection tracker is running on legacy backend"
			if active == bpf.BackendNone {
				message = "BPF enforcement enabled but connection tracker has no active backend"
			}
			findings = append(findings, alert.Finding{
				Severity: alert.Warning,
				Check:    "csm_health",
				Message:  message,
				Details:  "bpf_enforcement.direct_smtp_egress requires the connection tracker BPF backend. Check kernel version, LSM availability, or CAP_BPF.",
			})
		}
	}

	// Check state directory is writable
	stateDir := "/var/lib/csm/state"
	if cfg != nil && cfg.StatePath != "" {
		stateDir = cfg.StatePath
	}
	testFile := filepath.Join(stateDir, ".health_check")
	if err := osFS.WriteFile(testFile, []byte("ok"), 0600); err != nil {
		findings = append(findings, alert.Finding{
			Severity: alert.High,
			Check:    "csm_health",
			Message:  fmt.Sprintf("State directory not writable: %s", stateDir),
			Details:  err.Error(),
		})
	} else {
		_ = osFS.Remove(testFile)
	}

	return findings
}

// platformRequiredCommands returns the external commands CSM needs on the
// detected platform. On plain Linux hosts Exim is not required.
func platformRequiredCommands(info platform.Info) []string {
	cmds := []string{"find", "auditctl"}
	if info.IsCPanel() {
		cmds = append(cmds, "exim")
	}
	return cmds
}
