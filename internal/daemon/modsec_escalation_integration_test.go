package daemon

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// modsecApacheLine builds an Apache-style ModSecurity "Access denied" log line
// with the given rule ID, message, and space-separated tags.
func modsecApacheLine(ip, ruleID, msg, tags string) string {
	line := `[Wed Apr 01 15:15:05 2026] [error] [client ` + ip +
		`] ModSecurity: Access denied with code 403, [id "` + ruleID + `"] [msg "` + msg + `"]`
	for _, tg := range strings.Fields(tags) {
		line += ` [tag "` + tg + `"]`
	}
	line += ` [severity "CRITICAL"] [hostname "shop.example.ro"] [uri "/checkout"]`
	return line
}

func modsecFindingChecks(cfg *config.Config, lines []string) map[string]bool {
	seen := map[string]bool{}
	for _, line := range lines {
		for _, f := range parseModSecLogLineDeduped(line, cfg) {
			seen[f.Check] = true
		}
	}
	return seen
}

// Criteria 1 + 2: three low-confidence policy/anomaly denies from one IP do not
// auto-block, but emit one non-actioned low-confidence-burst finding.
func TestParseModSec_LowConfBurst_NoBan(t *testing.T) {
	resetModSecState()
	cfg := &config.Config{}
	line := modsecApacheLine("203.0.113.40", "210710",
		"COMODO WAF: Request content type is not allowed by policy", "")
	seen := modsecFindingChecks(cfg, []string{line, line, line})
	if seen["modsec_block_escalation"] || seen["modsec_csm_block_escalation"] {
		t.Fatal("low-confidence-only burst must not auto-block")
	}
	if !seen["modsec_low_confidence_burst"] {
		t.Fatal("expected a modsec_low_confidence_burst visibility finding")
	}
}

// Criterion 5: a burst mixing low-confidence policy rules with a high-confidence
// attack rule escalates at the normal bar.
func TestParseModSec_MixedHighEscalates(t *testing.T) {
	resetModSecState()
	cfg := &config.Config{}
	ip := "203.0.113.41"
	lines := []string{
		modsecApacheLine(ip, "210710", "Request content type is not allowed by policy", ""),
		modsecApacheLine(ip, "214930", "Inbound Points Exceeded|Total Incoming Points: 5", ""),
		modsecApacheLine(ip, "210381", "COMODO WAF: URL Encoding Abuse Attack Attempt", ""),
	}
	if !modsecFindingChecks(cfg, lines)["modsec_block_escalation"] {
		t.Fatal("a burst containing a high-confidence rule must escalate")
	}
}

// Criterion 6: an OWASP CRS inbound-anomaly-score rule (ID >= 910000) is NOT
// treated as high-confidence; three of them only emit the low-confidence burst.
func TestParseModSec_CRSAnomalyIsLowNotHigh(t *testing.T) {
	resetModSecState()
	cfg := &config.Config{}
	line := modsecApacheLine("203.0.113.43", "949110",
		"Inbound Anomaly Score Exceeded (Total Score: 5)", "anomaly-evaluation")
	seen := modsecFindingChecks(cfg, []string{line, line, line})
	if seen["modsec_block_escalation"] {
		t.Fatal("CRS anomaly-score rule must not auto-escalate at the normal bar")
	}
	if !seen["modsec_low_confidence_burst"] {
		t.Fatal("CRS anomaly-score burst should emit the low-confidence visibility finding")
	}
}

// Criterion 8: the attack class is read from the rule tags. A CRS SQLi rule with
// an attack-sqli tag classifies high and escalates.
func TestParseModSec_AttackTagEscalates(t *testing.T) {
	resetModSecState()
	cfg := &config.Config{}
	ip := "203.0.113.44"
	line := modsecApacheLine(ip, "942100",
		"SQL Injection Attack Detected via libinjection",
		"application-multi attack-sqli OWASP_CRS")
	if !modsecFindingChecks(cfg, []string{line, line, line})["modsec_block_escalation"] {
		t.Fatal("a rule tagged attack-sqli must classify high and escalate")
	}
}

// Criterion 10: an unclassified blocking rule raises a classifier-gap finding
// and remains escalation-eligible.
func TestParseModSec_UnknownRuleClassifierGap(t *testing.T) {
	resetModSecState()
	cfg := &config.Config{}
	line := modsecApacheLine("203.0.113.42", "211999", "Some unrecognised vendor rule", "")
	seen := modsecFindingChecks(cfg, []string{line})
	if !seen["modsec_classifier_gap"] {
		t.Fatal("first unknown blocking rule must raise modsec_classifier_gap")
	}
}

// Criterion 11: the existing store-backed no-escalate override still suppresses
// escalation for a configured rule ID, even a high-confidence one.
func TestParseModSec_StoreNoEscalateSuppresses(t *testing.T) {
	resetModSecState()
	sdb, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	prev := store.Global()
	store.SetGlobal(sdb)
	t.Cleanup(func() {
		store.SetGlobal(prev)
		_ = sdb.Close()
	})
	if err := sdb.AddModSecNoEscalateRule(942100); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	ip := "203.0.113.45"
	line := modsecApacheLine(ip, "942100",
		"SQL Injection Attack Detected", "attack-sqli")
	if modsecFindingChecks(cfg, []string{line, line, line, line})["modsec_block_escalation"] {
		t.Fatal("store-backed no-escalate rule must suppress escalation")
	}
}

func TestParseModSec_ExcludedRuleDoesNotClaimClassifierGap(t *testing.T) {
	resetModSecState()
	t.Cleanup(resetModSecState)
	sdb, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	prev := store.Global()
	store.SetGlobal(sdb)
	t.Cleanup(func() {
		store.SetGlobal(prev)
		_ = sdb.Close()
	})
	if err := sdb.AddModSecNoEscalateRule(211999); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	line := modsecApacheLine("203.0.113.45", "211999", "Unknown vendor rule", "")
	findings := parseModSecLogLineDeduped(line, cfg)
	if len(findings) != 1 || findings[0].Check != "modsec_block_realtime" {
		t.Fatalf("excluded rule findings = %v, want only the base deny", findings)
	}
	if err := sdb.RemoveModSecNoEscalateRule(211999); err != nil {
		t.Fatal(err)
	}
	// The base deny is still deduped, but the previously excluded rule must
	// report its gap immediately once escalation is enabled again.
	findings = parseModSecLogLineDeduped(line, cfg)
	if len(findings) != 1 || findings[0].Check != "modsec_classifier_gap" {
		t.Fatalf("re-enabled rule findings = %v, want only the classifier gap", findings)
	}
}

func TestParseModSec_ClassifierGapReminderSurvivesDedup(t *testing.T) {
	resetModSecState()
	t.Cleanup(resetModSecState)
	cfg := &config.Config{}
	line := modsecApacheLine("203.0.113.46", "211999", "Unknown vendor rule", "")
	findings := parseModSecLogLineDeduped(line, cfg)
	if len(findings) != 2 || findings[0].Check != "modsec_classifier_gap" || findings[1].Check != "modsec_block_realtime" {
		t.Fatalf("first hit findings = %v, want gap and base deny", findings)
	}
	modsecGapMu.Lock()
	modsecGapReported[211999] = time.Now().Add(-modsecClassifierGapInterval)
	modsecGapMu.Unlock()
	findings = parseModSecLogLineDeduped(line, cfg)
	if len(findings) != 1 || findings[0].Check != "modsec_classifier_gap" {
		t.Fatalf("deduped reminder findings = %v, want only the classifier gap", findings)
	}
	findings = parseModSecLogLineDeduped(line, cfg)
	if len(findings) != 1 || findings[0].Check != "modsec_block_escalation" {
		t.Fatalf("third deny findings = %v, want only escalation", findings)
	}
}

func TestParseModSec_ConcurrentClassifierGapDoesNotSuppressEscalation(t *testing.T) {
	resetModSecState()
	t.Cleanup(resetModSecState)
	const sources = 16
	cfg := &config.Config{}
	var gaps, escalations atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range sources {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			line := modsecApacheLine(fmt.Sprintf("203.0.113.%d", i+80), "211999", "Unknown vendor rule", "")
			for range modsecDefaultEscalationHits {
				for _, finding := range parseModSecLogLineDeduped(line, cfg) {
					switch finding.Check {
					case "modsec_classifier_gap":
						gaps.Add(1)
					case "modsec_block_escalation":
						escalations.Add(1)
					}
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	if n := gaps.Load(); n != 1 {
		t.Errorf("classifier gaps across %d concurrent sources = %d, want 1", sources, n)
	}
	if n := escalations.Load(); n != sources {
		t.Errorf("escalations = %d, want %d", n, sources)
	}
}

// An exploit-specific CSM rule escalates on its first deny even when the
// operator raised the hit threshold, and the message does not claim a count.
func TestParseModSec_SingleHitRuleEscalatesOnFirstDeny(t *testing.T) {
	resetModSecState()
	cfg := &config.Config{}
	cfg.Thresholds.ModSecEscalationHits = 10
	cfg.Thresholds.ModSecEscalationWindowMin = 120
	line := modsecApacheLine("203.0.113.63", "900133",
		"CSM VP: PHP session upload progress field (PHP2Shell)", "")
	var msg string
	for _, f := range parseModSecLogLineDeduped(line, cfg) {
		if f.Check == "modsec_csm_block_escalation" {
			msg = f.Message
		}
	}
	if msg == "" {
		t.Fatal("first deny of an exploit-specific rule must escalate")
	}
	if strings.Contains(msg, "10+") {
		t.Fatalf("single-hit escalation must not claim the hit threshold: %q", msg)
	}
}

// A tool-identifying User-Agent is distinct from an endpoint-only match.
func TestParseModSec_WP2ShellEscalatesOnFirstDeny(t *testing.T) {
	cfg := &config.Config{}
	cfg.Thresholds.ModSecEscalationHits = 10
	cfg.Thresholds.ModSecEscalationWindowMin = 120
	for _, server := range []string{"apache", "litespeed"} {
		t.Run(server, func(t *testing.T) {
			resetModSecState()
			t.Cleanup(resetModSecState)
			installModSecRegistryForTest(t, map[int]string{900122: "deny"})
			line := modsecApacheLine("203.0.113.65", "900122", "CSM: Blocked wp2shell exploit tool User-Agent", "")
			if server == "litespeed" {
				line = strings.Replace(liteSpeedTriggerLine210710, `"210710"`, `"900122"`, 1)
			}
			findings := parseModSecLogLineDeduped(line, cfg)
			if len(findings) != 2 || findings[0].Check != "modsec_csm_block_escalation" || findings[1].Check != "modsec_block_realtime" {
				t.Fatalf("first tool deny findings = %+v", findings)
			}
			if got := parseModSecLogLineDeduped(line, cfg); len(got) != 0 {
				t.Fatalf("repeated tool deny emitted duplicate findings: %+v", got)
			}
		})
	}
}

// The shipped URI-only rule also denies benign references and diagnostic
// requests. Those denies must retain the normal escalation policy.
func TestParseModSec_FileManagerRequiresRepeatedDenies(t *testing.T) {
	match := regexp.MustCompile(`SecRule REQUEST_URI "([^"]+)" \\\n\s+"id:900107,`).FindStringSubmatch(string(embeddedModSec))
	if len(match) != 2 {
		t.Fatal("missing WP File Manager URI rule")
	}
	uriRE, err := regexp.Compile(match[1])
	if err != nil {
		t.Fatal(err)
	}
	const connector = "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php"
	for _, tc := range []struct{ name, method, uri string }{
		{"owner_get", "GET", connector},
		{"health_check", "HEAD", connector},
		{"query_reference", "GET", "/help?file=" + connector},
		{"redirect_target", "GET", "/wp-login.php?redirect_to=" + connector},
		{"path_suffix", "GET", connector + ".txt"},
	} {
		for _, server := range []string{"apache", "litespeed"} {
			t.Run(tc.name+"/"+server, func(t *testing.T) {
				resetModSecState()
				t.Cleanup(resetModSecState)
				if !uriRE.MatchString(tc.uri) {
					t.Fatalf("shipped URI rule does not match fixture %q", tc.uri)
				}
				installModSecRegistryForTest(t, map[int]string{900107: "deny"})
				cfg := &config.Config{}
				cfg.Thresholds.ModSecEscalationHits = 10
				cfg.Thresholds.ModSecEscalationWindowMin = 120
				line := modsecApacheLine("203.0.113.66", "900107", "CSM VP: WP File Manager arbitrary upload", "")
				uri, _, _ := strings.Cut(tc.uri, "?")
				line = strings.Replace(line, `[uri "/checkout"]`, `[uri "`+uri+`"]`, 1)
				if server == "litespeed" {
					line = strings.Replace(liteSpeedTriggerLine210710, `"210710"`, `"900107"`, 1)
				}
				line += ` [data "` + tc.method + ` ` + tc.uri + `"]`
				for hit := 1; hit <= cfg.Thresholds.ModSecEscalationHits; hit++ {
					findings := parseModSecLogLineDeduped(line, cfg)
					switch hit {
					case 1:
						if len(findings) != 1 || findings[0].Check != "modsec_block_realtime" {
							t.Fatalf("first endpoint deny findings = %+v", findings)
						}
					case cfg.Thresholds.ModSecEscalationHits:
						if len(findings) != 1 || findings[0].Check != "modsec_csm_block_escalation" {
							t.Fatalf("endpoint denies at configured count did not escalate: %+v", findings)
						}
					default:
						if len(findings) != 0 {
							t.Fatalf("endpoint deny %d below configured count emitted findings: %+v", hit, findings)
						}
					}
				}
			})
		}
	}
}

// The per-rule escalation exclusion still wins over the single-hit table.
func TestParseModSec_StoreNoEscalateSuppressesSingleHit(t *testing.T) {
	for _, rule := range []int{900122, 900133} {
		t.Run(fmt.Sprint(rule), func(t *testing.T) {
			resetModSecState()
			t.Cleanup(resetModSecState)
			sdb, err := store.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			prev := store.Global()
			store.SetGlobal(sdb)
			t.Cleanup(func() {
				store.SetGlobal(prev)
				_ = sdb.Close()
			})
			if err := sdb.AddModSecNoEscalateRule(rule); err != nil {
				t.Fatal(err)
			}
			line := modsecApacheLine("203.0.113.64", fmt.Sprint(rule), "CSM exploit-specific deny", "")
			findings := parseModSecLogLineDeduped(line, &config.Config{})
			if len(findings) != 1 || findings[0].Check != "modsec_block_realtime" {
				t.Fatalf("excluded rule must retain only the WAF deny finding: %+v", findings)
			}
		})
	}
}
