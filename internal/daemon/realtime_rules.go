package daemon

import (
	"fmt"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/signatures"
	"github.com/pidginhost/csm/internal/yara"
)

// reportRealtimeRuleCoverage raises a finding when a realtime engine is
// running with no rules. Both scanners treat a missing or empty rules
// directory as a successful load of nothing, so a mistyped rules_dir or an
// empty rule sync left every file write "scanned" against zero rules while
// the daemon looked healthy. yaraActive is false when no YARA backend is
// installed or its rules failed to compile; those states raise their own
// findings and are not repeated here.
func (d *Daemon) reportRealtimeRuleCoverage(yamlRules, yaraRules int, yaraActive bool) {
	var empty []string
	if yamlRules == 0 {
		empty = append(empty, "YAML")
	}
	if yaraActive && yaraRules == 0 {
		empty = append(empty, "YARA")
	}
	if len(empty) == 0 {
		return
	}
	rulesDir := "the configured rules directory"
	if cfg := d.currentCfg(); cfg != nil && cfg.Signatures.RulesDir != "" {
		rulesDir = cfg.Signatures.RulesDir
	}
	d.emitYaraFinding(alert.High, "realtime_rules_missing",
		fmt.Sprintf("Real-time file scanning has no %s rules loaded from %s; every file write is scanned against nothing until rules are installed and reloaded.",
			strings.Join(empty, " or "), rulesDir))
}

// reportRealtimeRuleCoverageNow reads the live engines and reports on them.
func (d *Daemon) reportRealtimeRuleCoverageNow() {
	yaraRules, yaraActive := 0, false
	if b := yara.Active(); b != nil {
		yaraActive = true
		yaraRules = b.RuleCount()
	}
	d.reportRealtimeRuleCoverage(yamlRuleCount(), yaraRules, yaraActive)
}

// yamlRuleCount returns the number of YAML rules the global scanner holds;
// no scanner at all counts as zero rules.
func yamlRuleCount() int {
	if s := signatures.Global(); s != nil {
		return s.RuleCount()
	}
	return 0
}
