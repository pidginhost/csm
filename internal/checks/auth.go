package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
	"gopkg.in/yaml.v3"
)

func CheckShadowChanges(ctx context.Context, cfg *config.Config, store *state.Store) []alert.Finding {
	var findings []alert.Finding

	info, err := osFS.Stat("/etc/shadow")
	if err != nil {
		return nil
	}

	mtime := info.ModTime()
	mtimeKey := "_shadow_mtime"
	hashKey := "_shadow_hash"

	// Load current shadow entries (user:hash pairs, no sensitive data stored)
	currentEntries := parseShadowUsers()
	currentHash := hashBytes([]byte(fmt.Sprintf("%v", currentEntries)))

	prevMtimeRaw, mtimeExists := store.GetRaw(mtimeKey)
	prevHash, hashExists := store.GetRaw(hashKey)

	if mtimeExists {
		var lastMtime time.Time
		if err := json.Unmarshal([]byte(prevMtimeRaw), &lastMtime); err == nil {
			if mtime.After(lastMtime) {
				// Shadow file was modified - find what changed
				var details string
				if hashExists && prevHash != currentHash {
					changed := diffShadowChanges(store, currentEntries)
					if len(changed) > 0 {
						details = fmt.Sprintf("Previous: %s\nCurrent: %s\nAccounts changed: %s",
							lastMtime.Format("2006-01-02 15:04:05"),
							mtime.Format("2006-01-02 15:04:05"),
							strings.Join(changed, ", "))
					}
				}
				if details == "" {
					details = fmt.Sprintf("Previous: %s\nCurrent: %s",
						lastMtime.Format("2006-01-02 15:04:05"),
						mtime.Format("2006-01-02 15:04:05"))
				}

				// Check if within upcp window
				sev := alert.Critical
				if cfg.Suppressions.UPCPWindowStart != "" {
					now := time.Now()
					h, m := now.Hour(), now.Minute()
					nowMin := h*60 + m
					start := parseTimeMin(cfg.Suppressions.UPCPWindowStart)
					end := parseTimeMin(cfg.Suppressions.UPCPWindowEnd)
					if nowMin >= start && nowMin <= end {
						sev = alert.Warning
					}
				}

				// Check auditd for who made the change
				auditInfo := getAuditShadowInfo()
				if auditInfo != "" {
					details += "\n" + auditInfo
				}

				// Suppress alerts for password changes made by infra IPs
				// (admin-initiated password resets via WHM/xml-api), but only
				// when the explaining log event is newer than the shadow file's
				// last-seen mtime. A stale infra event from a prior change must
				// not mask a fresh, unexplained /etc/shadow edit.
				if isInfraShadowChange(cfg, lastMtime) {
					// Still update state, but don't alert
					goto storeState
				}

				// Separate root password change (higher severity)
				changed := diffShadowChanges(store, currentEntries)
				rootChanged := false
				userCount := 0
				for _, c := range changed {
					if c == "root" {
						rootChanged = true
					} else {
						userCount++
					}
				}

				if rootChanged {
					findings = append(findings, alert.Finding{
						Severity: alert.Critical,
						Check:    "root_password_change",
						Message:  "Root password changed",
						Details:  details,
					})
				}

				// Bulk password changes (5+ accounts at once)
				if userCount >= 5 {
					findings = append(findings, alert.Finding{
						Severity: alert.High,
						Check:    "bulk_password_change",
						Message:  fmt.Sprintf("Bulk password change: %d accounts modified", userCount),
						Details:  details,
					})
				} else {
					findings = append(findings, alert.Finding{
						Severity: sev,
						Check:    "shadow_change",
						Message:  "/etc/shadow modified",
						Details:  details,
					})
				}
			}
		}
	}

storeState:
	// Store current state
	mtimeData, _ := json.Marshal(mtime)
	store.SetRaw(mtimeKey, string(mtimeData))
	store.SetRaw(hashKey, currentHash)

	// Store per-user hashes for diff next time
	for user, hash := range currentEntries {
		store.SetRaw("_shadow_user:"+user, hash)
	}

	return findings
}

// parseShadowUsers reads /etc/shadow and returns a map of user -> password hash.
// Only stores a hash of the hash, not the actual password hash.
func parseShadowUsers() map[string]string {
	data, err := osFS.ReadFile("/etc/shadow")
	if err != nil {
		return nil
	}
	entries := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 2 || parts[0] == "" {
			continue
		}
		// Store a hash of the password field, not the field itself
		entries[parts[0]] = hashBytes([]byte(parts[1]))
	}
	return entries
}

// diffShadowChanges compares current entries against stored per-user hashes.
func diffShadowChanges(store *state.Store, current map[string]string) []string {
	var changed []string
	for user, hash := range current {
		prev, exists := store.GetRaw("_shadow_user:" + user)
		if exists && prev != hash {
			changed = append(changed, user)
		} else if !exists {
			changed = append(changed, user+" (new)")
		}
	}
	return changed
}

// getAuditShadowInfo checks auditd for recent shadow change events.
func getAuditShadowInfo() string {
	out, err := runCmd("grep", "csm_shadow_change", "/var/log/audit/audit.log")
	if err != nil || len(out) == 0 {
		return ""
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 {
		return ""
	}

	// Get the last event
	last := lines[len(lines)-1]

	// Extract exe= field
	exe := ""
	for _, part := range strings.Fields(last) {
		if strings.HasPrefix(part, "exe=") {
			exe = strings.Trim(strings.TrimPrefix(part, "exe="), "\"")
			break
		}
	}

	// Decode hex comm if present
	comm := ""
	for _, part := range strings.Fields(last) {
		if strings.HasPrefix(part, "comm=") {
			raw := strings.Trim(strings.TrimPrefix(part, "comm="), "\"")
			decoded := decodeHexString(raw)
			if decoded != "" {
				comm = decoded
			} else {
				comm = raw
			}
			break
		}
	}

	if exe != "" || comm != "" {
		return fmt.Sprintf("Changed by: %s (command: %s)", exe, comm)
	}
	return ""
}

// decodeHexString tries to decode a hex-encoded string (auditd encodes some comm fields).
func decodeHexString(s string) string {
	if len(s)%2 != 0 || len(s) < 4 {
		return ""
	}
	// Check if it looks like hex (all hex chars)
	for _, c := range s {
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return ""
		}
	}
	var result []byte
	for i := 0; i < len(s); i += 2 {
		// #nosec G115 -- hexVal returns 0..15; (h<<4)|h fits in a byte.
		b := byte(hexVal(s[i])<<4 | hexVal(s[i+1]))
		if b == 0 {
			break
		}
		result = append(result, b)
	}
	if len(result) == 0 {
		return ""
	}
	return string(result)
}

func CheckUID0Accounts(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	data, err := osFS.ReadFile("/etc/passwd")
	if err != nil {
		return nil
	}

	for _, line := range strings.Split(string(data), "\n") {
		user, unauthorized := classifyUID0Line(line)
		if unauthorized {
			findings = append(findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "uid0_account",
				Message:  fmt.Sprintf("Unauthorized UID 0 account: %s", user),
				Details:  line,
			})
		}
	}

	return findings
}

func CheckSSHKeys(ctx context.Context, cfg *config.Config, store *state.Store) []alert.Finding {
	if ctx == nil {
		ctx = context.Background()
	}
	var findings []alert.Finding

	// Check root authorized_keys
	rootKeys := "/root/.ssh/authorized_keys"
	if hash, err := hashFileContent(rootKeys); err == nil {
		key := "_ssh_root_keys_hash"
		prev, exists := store.GetRaw(key)
		if exists && prev != hash {
			findings = append(findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "ssh_keys",
				Message:  "Root authorized_keys modified",
				Details:  fmt.Sprintf("File: %s", rootKeys),
			})
		}
		store.SetRaw(key, hash)
	}

	// Check for new authorized_keys in /home. Rank by mtime desc so
	// recently-touched accounts are processed first when the check timeout
	// cuts iteration short.
	homes, _ := osFS.Glob("/home/*/.ssh/authorized_keys")
	for _, keyFile := range rankPathsByMtimeDesc(ctx, homes, accountScanMaxFiles(ctx, cfg)) {
		if ctx.Err() != nil {
			break
		}
		hash, err := hashFileContent(keyFile)
		if err != nil {
			continue
		}
		key := fmt.Sprintf("_ssh_user_keys:%s", keyFile)
		prev, exists := store.GetRaw(key)
		if exists && prev != hash {
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "ssh_keys",
				Message:  fmt.Sprintf("User authorized_keys modified: %s", keyFile),
			})
		}
		store.SetRaw(key, hash)
	}

	return findings
}

func CheckAPITokens(ctx context.Context, cfg *config.Config, store *state.Store) []alert.Finding {
	if ctx == nil {
		ctx = context.Background()
	}
	var findings []alert.Finding

	// WHM root API tokens
	if f, fire := checkWHMRootAPITokens(store); fire {
		findings = append(findings, f)
	}

	// User API tokens - read directly from disk instead of spawning uapi per user.
	// Token files are JSON at /home/<user>/.cpanel/api_tokens/<token_name>.
	// Rank account dirs by mtime desc so recently touched accounts are processed
	// first when the check timeout cuts iteration short.
	tokenDirs, _ := osFS.Glob("/home/*/.cpanel/api_tokens")
	for _, tokenDir := range rankPathsByMtimeDesc(ctx, tokenDirs, accountScanMaxFiles(ctx, cfg)) {
		if ctx.Err() != nil {
			break
		}
		user := filepath.Base(filepath.Dir(filepath.Dir(tokenDir)))
		tokenFiles, _ := osFS.Glob(filepath.Join(tokenDir, "*"))
		for _, tokenFile := range tokenFiles {
			if ctx.Err() != nil {
				return findings
			}
			tokenName := filepath.Base(tokenFile)
			data, err := osFS.ReadFile(tokenFile)
			if err != nil {
				continue
			}
			content := string(data)

			// Check for full access with no IP whitelist
			hasFullAccess := strings.Contains(content, `"has_full_access":1`) ||
				strings.Contains(content, `"has_full_access": 1`)
			noWhitelist := strings.Contains(content, `"whitelist_ips":null`) ||
				strings.Contains(content, `"whitelist_ips": null`) ||
				strings.Contains(content, `"whitelist_ips":[]`) ||
				strings.Contains(content, `"whitelist_ips": []`) ||
				!strings.Contains(content, "whitelist_ips")

			if hasFullAccess && noWhitelist {
				known := false
				for _, t := range cfg.Suppressions.KnownAPITokens {
					if tokenName == t {
						known = true
						break
					}
				}
				if !known {
					findings = append(findings, alert.Finding{
						Severity: alert.High,
						Check:    "api_tokens",
						Message:  fmt.Sprintf("User %s has full-access API token '%s' with no IP whitelist", user, tokenName),
						Details:  fmt.Sprintf("File: %s", tokenFile),
					})
				}
			}
		}
	}

	return findings
}

const (
	whmAPITokensStateKey = "_whm_api_tokens_state" // #nosec G101 -- bbolt state-store key name, not a credential
	whmAPITokensHashKey  = "_whm_api_tokens_hash"  // #nosec G101 -- bbolt state-store key name, not a credential
)

func checkWHMRootAPITokens(store *state.Store) (alert.Finding, bool) {
	out, err := runCmd("whmapi1", "api_token_list", "--output=json")
	if err == nil {
		if cur, ok := parseWHMTokenSig(out); ok {
			return checkStructuredWHMRootAPITokens(store, cur, nil)
		}
	}
	return checkWHMRootAPITokensLegacyHash(store)
}

func checkWHMRootAPITokensLegacyHash(store *state.Store) (alert.Finding, bool) {
	out, err := runCmd("whmapi1", "api_token_list")
	if err != nil {
		return alert.Finding{}, false
	}
	if cur, ok := parseWHMTokenSigYAML(out); ok {
		return checkStructuredWHMRootAPITokens(store, cur, out)
	}
	return checkWHMRootAPITokensLegacyHashOutput(store, out)
}

func checkWHMRootAPITokensLegacyHashOnly(store *state.Store) (alert.Finding, bool) {
	out, err := runCmd("whmapi1", "api_token_list")
	if err != nil {
		return alert.Finding{}, false
	}
	return checkWHMRootAPITokensLegacyHashOutput(store, out)
}

func checkStructuredWHMRootAPITokens(store *state.Store, cur tokenSig, legacyOut []byte) (alert.Finding, bool) {
	_, hadStructuredState := store.GetRaw(whmAPITokensStateKey)
	_, hadLegacyState := store.GetRaw(whmAPITokensHashKey)
	finding, fire := diffWHMTokens(store, cur)
	switch {
	case !hadStructuredState && hadLegacyState:
		// Migrating from the legacy hash: the tokens were already vetted under
		// the old scheme, so diff against the legacy hash rather than
		// re-flagging the whole set as new.
		var legacyFinding alert.Finding
		var legacyFire bool
		if legacyOut != nil {
			legacyFinding, legacyFire = checkWHMRootAPITokensLegacyHashOutput(store, legacyOut)
		} else {
			legacyFinding, legacyFire = checkWHMRootAPITokensLegacyHashOnly(store)
		}
		if legacyFire {
			finding, fire = legacyFinding, true
		}
	case !hadStructuredState && !hadLegacyState:
		// True first run with no prior state of any kind. A root API token
		// created by an attacker before CSM was installed would otherwise be
		// baselined as "known" and never alert. Surface the pre-existing
		// operator tokens for review.
		finding, fire = baselineWHMTokens(cur)
	}
	store.SetRaw(whmAPITokensStateKey, marshalTokenSig(cur))
	if legacyOut != nil {
		store.SetRaw(whmAPITokensHashKey, hashBytes(legacyOut))
	}
	return finding, fire
}

func checkWHMRootAPITokensLegacyHashOutput(store *state.Store, out []byte) (alert.Finding, bool) {
	hash := hashBytes(out)
	prev, exists := store.GetRaw(whmAPITokensHashKey)
	store.SetRaw(whmAPITokensHashKey, hash)
	if exists && prev != hash {
		return alert.Finding{
			Severity: alert.Critical,
			Check:    "api_tokens",
			Message:  "WHM root API tokens changed",
			Details:  "Run 'whmapi1 api_token_list' to review",
		}, true
	}
	return alert.Finding{}, false
}

// baselineWHMTokens reports pre-existing root API tokens on the very first
// scan. Routine cluster-managed trust tokens churn on their own and are
// expected, so a baseline made up only of those stays silent; any
// operator/full-access token present at baseline is surfaced for review so a
// token planted before CSM was installed cannot pass as "known".
func baselineWHMTokens(cur tokenSig) (alert.Finding, bool) {
	var operator []string
	for name, info := range cur {
		if isClusterManagedToken(info) || isClusterManagedTokenAddition(name, info) {
			continue
		}
		operator = append(operator, name)
	}
	if len(operator) == 0 {
		return alert.Finding{}, false
	}
	sort.Strings(operator)
	return alert.Finding{
		Severity: alert.High,
		Check:    "api_tokens",
		Message:  "Pre-existing WHM root API tokens present at baseline",
		Details:  "Review with 'whmapi1 api_token_list': " + strings.Join(operator, "; "),
	}, true
}

// tokenSig maps each WHM root API token name to the security traits compared
// between scans.
type tokenSig map[string]tokenInfo

type tokenInfo struct {
	FullAccess     bool `json:"full_access"`
	ClusterManaged bool `json:"cluster_managed"`
}

// isClusterManagedToken reports whether cPanel owns the token's lifecycle.
// DNS clustering creates, rotates, and deletes these on its own:
//   - reverse_trust_<uuid>: trust granted to a remote WHM peer
//   - <host>-trust (e.g. ns2-trust): local end of a trust relationship
//
// Their churn is routine and must not page like an attacker-created token.
func isClusterManagedToken(info tokenInfo) bool {
	return info.ClusterManaged && !info.FullAccess
}

func isClusterManagedTokenAddition(name string, info tokenInfo) bool {
	return strings.HasPrefix(name, "reverse_trust_") && isClusterManagedToken(info)
}

func clusterManagedFromACLs(name string, acls map[string]bool) bool {
	if strings.HasPrefix(name, "reverse_trust_") {
		return true
	}
	return strings.HasSuffix(name, "-trust") && acls["clustering"]
}

// parseWHMTokenSig decodes `whmapi1 api_token_list --output=json` into a
// tokenSig. A token whose value is not a JSON object or whose ACLs cannot be
// read is kept with FullAccess=false, so an unparsable entry never hides a
// token's presence. ok=false means the caller should use the legacy hash path.
func parseWHMTokenSig(out []byte) (tokenSig, bool) {
	var env struct {
		Data struct {
			Tokens map[string]json.RawMessage `json:"tokens"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out, &env); err != nil || env.Data.Tokens == nil {
		return nil, false
	}
	sig := make(tokenSig, len(env.Data.Tokens))
	for name, raw := range env.Data.Tokens {
		var t struct {
			ACLs map[string]json.RawMessage `json:"acls"`
		}
		_ = json.Unmarshal(raw, &t)
		acls := decodeWHMTokenACLs(t.ACLs)
		sig[name] = tokenInfo{
			FullAccess:     acls["all"],
			ClusterManaged: clusterManagedFromACLs(name, acls),
		}
	}
	return sig, true
}

func parseWHMTokenSigYAML(out []byte) (tokenSig, bool) {
	type yamlToken struct {
		ACLs map[string]any `yaml:"acls"`
	}
	type yamlTokenData struct {
		Tokens map[string]yamlToken `yaml:"tokens"`
	}
	var env struct {
		Data   yamlTokenData `yaml:"data"`
		Result struct {
			Data yamlTokenData `yaml:"data"`
		} `yaml:"result"`
	}
	if err := yaml.Unmarshal(out, &env); err != nil {
		return nil, false
	}
	tokens := env.Data.Tokens
	if tokens == nil {
		tokens = env.Result.Data.Tokens
	}
	if tokens == nil {
		return nil, false
	}

	sig := make(tokenSig, len(tokens))
	for name, raw := range tokens {
		acls := decodeWHMTokenYAMLACLs(raw.ACLs)
		sig[name] = tokenInfo{
			FullAccess:     acls["all"],
			ClusterManaged: clusterManagedFromACLs(name, acls),
		}
	}
	return sig, true
}

func decodeWHMTokenACLs(raw map[string]json.RawMessage) map[string]bool {
	acls := make(map[string]bool, len(raw))
	for name, value := range raw {
		acls[name] = decodeWHMTokenACL(value)
	}
	return acls
}

func decodeWHMTokenYAMLACLs(raw map[string]any) map[string]bool {
	acls := make(map[string]bool, len(raw))
	for name, value := range raw {
		acls[name] = decodeWHMTokenYAMLACL(value)
	}
	return acls
}

func decodeWHMTokenACL(raw json.RawMessage) bool {
	switch strings.TrimSpace(string(raw)) {
	case "1", "true", `"1"`, `"true"`:
		return true
	case "0", "false", `"0"`, `"false"`, "null", "":
		return false
	}

	var n json.Number
	if err := json.Unmarshal(raw, &n); err == nil {
		return n.String() == "1"
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s == "1" || strings.EqualFold(s, "true")
	}
	var b bool
	return json.Unmarshal(raw, &b) == nil && b
}

func decodeWHMTokenYAMLACL(raw any) bool {
	switch v := raw.(type) {
	case bool:
		return v
	case int:
		return v == 1
	case int64:
		return v == 1
	case uint64:
		return v == 1
	case float64:
		return v == 1
	case string:
		s := strings.TrimSpace(v)
		return s == "1" || strings.EqualFold(s, "true")
	default:
		return false
	}
}

// marshalTokenSig serializes a tokenSig deterministically (encoding/json sorts
// map keys), so an unchanged set always produces an identical stored string.
func marshalTokenSig(sig tokenSig) string {
	b, _ := json.Marshal(sig)
	return string(b)
}

func unmarshalTokenSig(raw string) (tokenSig, bool) {
	var sig tokenSig
	if err := json.Unmarshal([]byte(raw), &sig); err == nil {
		return sig, true
	}

	var legacy map[string]bool
	if err := json.Unmarshal([]byte(raw), &legacy); err != nil {
		return nil, false
	}
	sig = make(tokenSig, len(legacy))
	for name, all := range legacy {
		sig[name] = tokenInfo{
			FullAccess:     all,
			ClusterManaged: !all && (strings.HasPrefix(name, "reverse_trust_") || strings.HasSuffix(name, "-trust")),
		}
	}
	return sig, true
}

// diffWHMTokens compares the current token set against the previously stored
// one and returns a single finding when something changed. Severity splits on
// intent:
//   - Critical: any token added outside generated reverse_trust churn, any
//     non-cluster token removed, or ANY token gaining the full-access "all" ACL.
//   - Warning: only generated reverse_trust additions/removals or recorded
//     cluster trust removals changed. cPanel does this during normal DNS
//     clustering and it must not page.
//
// The first scan after the key is introduced just records a baseline.
func diffWHMTokens(store *state.Store, cur tokenSig) (alert.Finding, bool) {
	raw, exists := store.GetRaw(whmAPITokensStateKey)
	if !exists {
		return alert.Finding{}, false
	}
	prev, ok := unmarshalTokenSig(raw)
	if !ok {
		return alert.Finding{}, false
	}

	var critical, cluster []string
	for name, info := range cur {
		prevInfo, had := prev[name]
		if !had {
			if isClusterManagedTokenAddition(name, info) {
				cluster = append(cluster, "added "+name)
			} else {
				critical = append(critical, "added "+name)
			}
			continue
		}
		if info.FullAccess && !prevInfo.FullAccess {
			critical = append(critical, "escalated "+name+" to full access")
		}
	}
	for name, info := range prev {
		if _, still := cur[name]; still {
			continue
		}
		if isClusterManagedToken(info) {
			cluster = append(cluster, "removed "+name)
		} else {
			critical = append(critical, "removed "+name)
		}
	}

	switch {
	case len(critical) > 0:
		sort.Strings(critical)
		return alert.Finding{
			Severity: alert.Critical,
			Check:    "api_tokens",
			Message:  "WHM root API tokens changed",
			Details:  "Review with 'whmapi1 api_token_list': " + strings.Join(critical, "; "),
		}, true
	case len(cluster) > 0:
		sort.Strings(cluster)
		return alert.Finding{
			Severity: alert.Warning,
			Check:    "api_tokens",
			Message:  "WHM root cluster trust tokens changed",
			Details:  "cPanel DNS clustering churn (expected): " + strings.Join(cluster, "; "),
		}, true
	}
	return alert.Finding{}, false
}

// shadowMutatingWHMEndpoints lists WHM JSON-API endpoints whose handlers
// rewrite /etc/shadow as a side effect:
//   - suspendacct/unsuspendacct: lock/unlock password field, swap login shell
//   - passwd/forcepasswordchange: set or expire user password
//   - createacct/removeacct/killacct: add or remove the shadow entry entirely
//
// Hits on these endpoints from infra IPs explain shadow mtime changes
// without involving an attacker; hits from non-infra IPs do not.
var shadowMutatingWHMEndpoints = []string{
	"/json-api/suspendacct",
	"/json-api/unsuspendacct",
	"/json-api/passwd",
	"/json-api/forcepasswordchange",
	"/json-api/createacct",
	"/json-api/removeacct",
	"/json-api/killacct",
}

// isInfraShadowChange reports whether every recent log signal that could
// explain a /etc/shadow modification was originated by an infra IP. It
// fuses two sources:
//
//  1. session_log PURGE password_change events (WHM/cPanel sets a new
//     password, which goes through the session machinery).
//  2. successful api_tokens_log entries for shadow-mutating WHM JSON-API endpoints
//     (suspendacct, passwd, createacct, ...). The cPanel session log does
//     NOT record these because they are not session events, so the older
//     session-only check fired on every internal `suspendacct` call.
//
// Returns true only if at least one such event was seen AND every event in
// both sources came from an infra IP (or loopback / "internal"). Any
// successful external API call or unparseable source short-circuits to false
// so a stolen token or compromised neighbour does not get a free suppression.
// since is the shadow file's previously recorded mtime. Only log events newer
// than since can explain the modification under investigation; stale tail lines
// (a legit infra password change from days ago) must not suppress a fresh,
// unrelated /etc/shadow edit.
func isInfraShadowChange(cfg *config.Config, since time.Time) bool {
	sessFound, sessAllInfra := scanSessionLogShadow(cfg, since)
	tokFound, tokAllInfra := scanAPITokensLogShadow(cfg, since)
	return (sessFound || tokFound) && sessAllInfra && tokAllInfra
}

// parseCPanelLogTime reads the leading "[<timestamp>]" of a cPanel session_log
// or api_tokens_log line. Both the timezone-qualified form
// ("2006-01-02 15:04:05 -0700") and the older bare form ("2006-01-02 15:04:05",
// interpreted in the host's local zone) are accepted. Returns ok=false when no
// bracketed timestamp is present or it does not parse.
func parseCPanelLogTime(line string) (time.Time, bool) {
	open := strings.IndexByte(line, '[')
	if open < 0 {
		return time.Time{}, false
	}
	end := strings.IndexByte(line[open:], ']')
	if end < 0 {
		return time.Time{}, false
	}
	stamp := strings.TrimSpace(line[open+1 : open+end])
	for _, layout := range []string{"2006-01-02 15:04:05 -0700", "2006-01-02 15:04:05"} {
		if t, err := time.ParseInLocation(layout, stamp, time.Local); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func cpanelShadowLogAfterSince(ts, since time.Time) bool {
	if since.IsZero() {
		return true
	}
	// cPanel logs only whole seconds, while shadow mtimes can carry
	// subsecond precision. Treat the stored mtime's logged second as
	// in-window so an infra event at 10:00:00.900 is not rejected just
	// because the prior mtime was 10:00:00.500.
	return !ts.Before(since.Truncate(time.Second))
}

// scanSessionLogShadow walks the cPanel session log for PURGE password_change
// events and reports whether any were seen and whether every non-loopback,
// non-"internal" source IP belonged to the infra allowlist.
func scanSessionLogShadow(cfg *config.Config, since time.Time) (foundAny, allInfra bool) {
	allInfra = true
	lines := tailFile("/usr/local/cpanel/logs/session_log", 100)
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		if !strings.Contains(line, "PURGE") || !strings.Contains(line, "password_change") {
			continue
		}
		ts, ok := parseCPanelLogTime(line)
		if !ok {
			// A shadow-mutating line without a usable timestamp cannot prove
			// it is stale. Fail toward alerting instead of suppressing.
			foundAny = true
			allInfra = false
			return
		}
		if !cpanelShadowLogAfterSince(ts, since) {
			// Stale line cannot explain this modification.
			continue
		}
		foundAny = true

		// Format: [ts] info [xml-api|whostmgr|security] IP PURGE account:token password_change
		var ip string
		for _, tag := range []string{"[xml-api]", "[whostmgr]", "[security]"} {
			if idx := strings.Index(line, tag); idx >= 0 {
				rest := strings.TrimSpace(line[idx+len(tag):])
				fields := strings.Fields(rest)
				if len(fields) > 0 {
					ip = fields[0]
				}
				break
			}
		}
		if ip == "internal" {
			continue
		}
		if !isTrustedShadowSource(ip, cfg) {
			allInfra = false
			return
		}
	}
	return
}

// scanAPITokensLogShadow walks the WHM api_tokens_log for recent calls to
// JSON-API endpoints that rewrite /etc/shadow. Returns (foundAny, allInfra)
// with the same semantics as scanSessionLogShadow.
func scanAPITokensLogShadow(cfg *config.Config, since time.Time) (foundAny, allInfra bool) {
	allInfra = true
	lines := tailFile("/usr/local/cpanel/logs/api_tokens_log", 200)
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		if !lineHitsShadowEndpoint(line) {
			continue
		}
		if !apiTokensHTTPStatusOK(line) {
			continue
		}
		ts, ok := parseCPanelLogTime(line)
		if !ok {
			// A shadow-mutating line without a usable timestamp cannot prove
			// it is stale. Fail toward alerting instead of suppressing.
			foundAny = true
			allInfra = false
			return
		}
		if !cpanelShadowLogAfterSince(ts, since) {
			// Stale line cannot explain this modification.
			continue
		}
		foundAny = true
		ip := extractAPITokensHost(line)
		if ip == "internal" {
			continue
		}
		if !isTrustedShadowSource(ip, cfg) {
			allInfra = false
			return
		}
	}
	return
}

func lineHitsShadowEndpoint(line string) bool {
	path := extractAPITokensRequestPath(line)
	if path == "" {
		return false
	}
	for _, ep := range shadowMutatingWHMEndpoints {
		if path == ep {
			return true
		}
	}
	return false
}

func apiTokensHTTPStatusOK(line string) bool {
	status := extractAPITokensField(line, "HTTP Status: ['")
	return strings.HasPrefix(status, "2")
}

// extractAPITokensHost pulls the source IP out of the api_tokens_log line
// shape used by whostmgrd:
//
//	[ts] info [whostmgrd] Host: ['<ip>'] HTTP Status: [...], ...
func extractAPITokensHost(line string) string {
	return extractAPITokensField(line, "Host: ['")
}

func extractAPITokensRequestPath(line string) string {
	request := extractAPITokensField(line, "Request: ['")
	fields := strings.Fields(request)
	if len(fields) < 2 {
		return ""
	}
	path := fields[1]
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		path = path[:idx]
	}
	return path
}

func extractAPITokensField(line, marker string) string {
	idx := strings.Index(line, marker)
	if idx < 0 {
		return ""
	}
	rest := line[idx+len(marker):]
	end := strings.Index(rest, "']")
	if end < 0 {
		return ""
	}
	return rest[:end]
}

func isTrustedShadowSource(ip string, cfg *config.Config) bool {
	parsed := net.ParseIP(ip)
	if parsed != nil && parsed.IsLoopback() {
		return true
	}
	return isInfraIP(ip, cfg.InfraIPs)
}

func parseTimeMin(s string) int {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0
	}
	h := 0
	m := 0
	fmt.Sscanf(parts[0], "%d", &h)
	fmt.Sscanf(parts[1], "%d", &m)
	return h*60 + m
}
