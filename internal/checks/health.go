package checks

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/state"
)

// CheckHealth verifies that CSM's dependencies are working.
// Reports on missing external commands, broken auditd, etc.
func CheckHealth(_ *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	// Check required external commands exist
	requiredCmds := []string{"find", "exim", "auditctl"}
	for _, cmd := range requiredCmds {
		if _, err := exec.LookPath(cmd); err != nil {
			findings = append(findings, alert.Finding{
				Severity: alert.Warning,
				Check:    "csm_health",
				Message:  fmt.Sprintf("Required command not found: %s", cmd),
				Details:  "Some checks will be skipped",
			})
		}
	}

	// Check optional commands
	optionalCmds := map[string]string{
		"whmapi1": "WHM API token check will be skipped",
		"wp":      "WordPress core integrity check will be skipped",
	}
	for cmd, impact := range optionalCmds {
		if _, err := exec.LookPath(cmd); err != nil {
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

	// Check state directory is writable
	stateDir := "/opt/csm/state"
	testFile := stateDir + "/.health_check"
	if err := os.WriteFile(testFile, []byte("ok"), 0600); err != nil {
		findings = append(findings, alert.Finding{
			Severity: alert.High,
			Check:    "csm_health",
			Message:  fmt.Sprintf("State directory not writable: %s", stateDir),
			Details:  err.Error(),
		})
	} else {
		os.Remove(testFile)
	}

	return findings
}
