package daemon

import "strings"

// modsecConfidence classifies how strongly a single ModSecurity deny indicates
// a real attack, independent of the rule's blocking action. It drives whether a
// deny may auto-escalate to a 24h firewall ban (high/unknown) or only counts
// toward the low-confidence visibility/backstop path (low). See
// docs/superpowers/specs/2026-06-27-modsec-escalation-fp-options.md.
type modsecConfidence int

const (
	// modsecConfUnknown is a blocking deny CSM cannot classify from the parsed
	// rule ID, message, or tags. Treated as escalation-eligible at the normal
	// bar (fail-secure) so a new vendor rule never gets a silent no-ban path.
	modsecConfUnknown modsecConfidence = iota
	// modsecConfLow is a policy/anomaly/scoring deny whose own rule is not proof
	// of hostile intent (content-type policy, anomaly score threshold). Never
	// auto-bans on its own at the normal bar; only via the low-confidence
	// backstop.
	modsecConfLow
	// modsecConfHigh is a specific attack/probe signal (SQLi, RCE, traversal,
	// URL-encoding abuse, CSM custom deny, scanner). Escalation-eligible at the
	// normal bar even when it is the only distinct rule.
	modsecConfHigh
)

func (c modsecConfidence) String() string {
	switch c {
	case modsecConfLow:
		return "low"
	case modsecConfHigh:
		return "high"
	default:
		return "unknown"
	}
}

// modsecKnownLowConfRules are vendor policy/anomaly/scoring rule IDs verified to
// fire on legitimate-but-unusual traffic as often as on attacks. They are
// low-confidence by exact ID, but a high-confidence attack signal in the same
// message/tags still overrides (see classifyModSecConfidence ordering). Do NOT
// add broad rule-ID ranges here; only exact, fixture-verified IDs.
var modsecKnownLowConfRules = map[int]bool{
	// COMODO CWAF policy/anomaly.
	210710: true, // request content-type not allowed by policy
	214930: true, // inbound points exceeded (anomaly threshold)
	211170: true, // outbound points / scoring
	211220: true, // outbound points / scoring
	// OWASP CRS policy/anomaly.
	920420: true, // request content-type not allowed
	920430: true, // HTTP protocol version not allowed (policy)
	949110: true, // inbound anomaly score exceeded
	959100: true, // outbound anomaly score exceeded
	980130: true, // anomaly score reporting
}

// modsecAttackMsgKeywords are lowercase substrings of vendor messages that name
// a specific attack/probe class. Presence means high-confidence.
var modsecAttackMsgKeywords = []string{
	"sql injection", "sqli", "remote command", "command injection",
	"os command", "remote code execution", "code execution", "code injection",
	"file inclusion", "lfi", "rfi", "cross-site scripting",
	"xss", "path traversal", "directory traversal", "url encoding abuse",
	"web shell", "webshell", "backdoor", "shellshock", "ssrf",
	"server-side request forgery", "session fixation", "remote file",
	"request smuggling", "response splitting", "crlf injection",
	"object injection", "template injection", "xxe", "xml external entity",
	"ldap injection", "nosql injection", "scanner", "exploit",
	"injection attack", "deserializ",
}

// modsecAttackTagKeywords are lowercase substrings of the ModSecurity rule tag
// taxonomy that name a specific attack class. "attack-protocol" and
// "attack-generic" are deliberately excluded: protocol/anomaly policy rules
// carry them but are low-confidence.
var modsecAttackTagKeywords = []string{
	"attack-sqli", "attack-rce", "attack-xss", "attack-lfi", "attack-rfi",
	"attack-injection", "attack-disclosure", "attack-fixation", "attack-ssrf",
	"attack-shell", "application-attack",
}

// modsecPolicyAnomalyKeywords are lowercase substrings that name a
// policy/anomaly/scoring decision (low-confidence) when no attack signal is
// present.
var modsecPolicyAnomalyKeywords = []string{
	"anomaly", "inbound points", "outbound points", "points exceeded",
	"total incoming points", "total inbound points", "content-type",
	"content type", "not allowed by policy", "not allowed by the policy",
	"protocol version", "score exceeded",
}

// classifyModSecConfidence classifies a single deny. Ordering is deliberate:
// a high-confidence attack signal always wins; CSM custom rules are high;
// otherwise an exact known-low ID or policy/anomaly wording (with no attack
// signal) is low; anything else is unknown (fail-secure, escalation-eligible).
//
// The modsec [severity] field is intentionally not an input: anomaly-scoring
// WAFs (COMODO CWAF) emit CRITICAL severity on benign policy/anomaly rules, so
// it is too noisy to separate attacks from policy hits. Rule ID, message, and
// tags carry the reliable signal.
func classifyModSecConfidence(ruleNum int, msg, tags string) modsecConfidence {
	lc := strings.ToLower(msg + " " + tags)

	// CSM custom rules are purpose-built attack/probe detections.
	if ruleNum >= 900000 && ruleNum <= 900999 {
		return modsecConfHigh
	}

	// Specific attack/probe evidence wins over any low signal.
	if containsAny(lc, modsecAttackMsgKeywords) || containsAny(strings.ToLower(tags), modsecAttackTagKeywords) {
		return modsecConfHigh
	}

	// Positive low evidence only: exact known-low ID or policy/anomaly wording.
	if modsecKnownLowConfRules[ruleNum] {
		return modsecConfLow
	}
	if containsAny(lc, modsecPolicyAnomalyKeywords) {
		return modsecConfLow
	}

	return modsecConfUnknown
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
