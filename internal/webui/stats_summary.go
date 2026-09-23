package webui

import (
	"sort"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
)

// statsSummary is what the dashboard shows about the last 24 hours of
// history. The stats API and the dashboard page share it; it is recomputed
// only when history changes (see historyMemo).
type statsSummary struct {
	critical, high, warning                  int
	byCheck                                  map[string]int
	lastCritical                             time.Time
	atRisk                                   []map[string]interface{}
	autoBlocked, autoQuarantined, autoKilled int
	topAccounts                              []accountCount
	bruteForce                               map[string]interface{}
	recent                                   []alert.Finding // newest non-internal findings, at most 10
}

type accountCount struct {
	Account string `json:"account"`
	Count   int    `json:"count"`
}

func (s *Server) statsSummary24h() *statsSummary {
	return s.statsMemo.get(s.store.HistoryMark(), func() any {
		return summarizeHistory(s.store.ReadHistorySince(time.Now().Add(-24 * time.Hour)))
	}).(*statsSummary)
}

// summarizeHistory computes the summary from findings, newest first.
func summarizeHistory(findings []alert.Finding) *statsSummary {
	critical, high, warning := 0, 0, 0
	byCheck := make(map[string]int)

	for _, f := range findings {
		switch f.Severity {
		case alert.Critical:
			critical++
		case alert.High:
			high++
		case alert.Warning:
			warning++
		}
		byCheck[f.Check]++
	}

	// Most recent critical finding, for "time since last critical"
	// (findings are newest-first from ReadHistorySince).
	var lastCritical time.Time
	for _, f := range findings {
		if f.Severity == alert.Critical {
			lastCritical = f.Timestamp
			break
		}
	}

	// The dashboard's live feed: the newest findings, without internal checks.
	var recent []alert.Finding
	for _, f := range findings {
		if len(recent) == 10 {
			break
		}
		if !operatorFacingCheck(f.Check) {
			continue
		}
		recent = append(recent, f)
	}

	// Compute accounts at risk: accounts with critical/high findings in 24h
	accountRisk := make(map[string]int) // account -> highest severity
	// Auto-response summary: count actions by type in 24h
	autoBlocked, autoQuarantined, autoKilled := 0, 0, 0
	// Top targeted accounts
	accountHits := make(map[string]int)
	// Brute force summary
	bruteForceIPs := make(map[string]int)   // IP -> total attempts
	bruteForceTypes := make(map[string]int) // "wp-login" / "xmlrpc" -> count

	for _, f := range findings {
		// Extract account from finding path/message
		acct := extractAccountFromFinding(f)
		if acct != "" {
			accountHits[acct]++
			sev := int(f.Severity)
			if prev, ok := accountRisk[acct]; !ok || sev > prev {
				accountRisk[acct] = sev
			}
		}
		// Count auto-response actions
		switch f.Check {
		case "auto_block":
			autoBlocked++
		case "auto_response":
			if strings.Contains(f.Message, "quarantin") {
				autoQuarantined++
			} else if strings.Contains(f.Message, "kill") || strings.Contains(f.Message, "Kill") {
				autoKilled++
			}
		case "wp_login_bruteforce":
			bruteForceTypes["wp-login"]++
			if ip := checks.ExtractIPFromFinding(f); ip != "" {
				bruteForceIPs[ip]++
			}
		case "xmlrpc_abuse":
			bruteForceTypes["xmlrpc"]++
			if ip := checks.ExtractIPFromFinding(f); ip != "" {
				bruteForceIPs[ip]++
			}
		case "modsec_block_escalation", "modsec_csm_block_escalation":
			if strings.Contains(f.Message, "xmlrpc") || strings.Contains(f.Message, "900006") || strings.Contains(f.Message, "900007") {
				bruteForceTypes["xmlrpc-modsec"]++
			}
		}
	}

	// Accounts at risk: those with critical or high severity
	var atRisk []map[string]interface{}
	for acct, sev := range accountRisk {
		if sev >= int(alert.High) {
			atRisk = append(atRisk, map[string]interface{}{
				"account":  acct,
				"severity": sev,
				"findings": accountHits[acct],
			})
		}
	}
	// Sort by severity desc, then findings desc
	sort.Slice(atRisk, func(i, j int) bool {
		if atRisk[i]["severity"].(int) != atRisk[j]["severity"].(int) {
			return atRisk[i]["severity"].(int) > atRisk[j]["severity"].(int)
		}
		return atRisk[i]["findings"].(int) > atRisk[j]["findings"].(int)
	})
	if len(atRisk) > 50 {
		atRisk = atRisk[:50]
	}
	for _, a := range atRisk {
		a["severity"] = alert.Severity(a["severity"].(int)).String()
	}

	// Top targeted accounts (by finding count)
	var topAccounts []accountCount
	for acct, count := range accountHits {
		topAccounts = append(topAccounts, accountCount{acct, count})
	}
	sort.Slice(topAccounts, func(i, j int) bool {
		return topAccounts[i].Count > topAccounts[j].Count
	})
	if len(topAccounts) > 5 {
		topAccounts = topAccounts[:5]
	}

	return &statsSummary{
		critical:        critical,
		high:            high,
		warning:         warning,
		byCheck:         byCheck,
		lastCritical:    lastCritical,
		atRisk:          atRisk,
		autoBlocked:     autoBlocked,
		autoQuarantined: autoQuarantined,
		autoKilled:      autoKilled,
		topAccounts:     topAccounts,
		bruteForce:      buildBruteForceSummary(bruteForceIPs, bruteForceTypes),
		recent:          recent,
	}
}
