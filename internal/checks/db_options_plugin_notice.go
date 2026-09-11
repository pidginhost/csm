package checks

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
)

// pluginNoticeSinkOptions are plugin status options whose contents WordPress
// renders into the admin dashboard as a notice. A stored cross-site scripting
// bug in the plugin turns one of these rows into a loader that runs with the
// privileges of whichever administrator opens the dashboard next.
//
// LiteSpeed Cache before 5.7.0.1 (CVE-2023-40000) lets an unauthenticated
// request write its CDN setup status, and the observed campaign puts a
// <script src> into cdn_setup_err, then into the rendered message list. Both
// rows hold plugin state, never site content, so markup that executes is
// proof of injection on its own.
var pluginNoticeSinkOptions = map[string]string{
	"litespeed.cdn_setup._summary":     "LiteSpeed Cache CDN setup status",
	"litespeed.admin_display.messages": "LiteSpeed Cache admin notices",
	"litespeed.admin_display.msg_pin":  "LiteSpeed Cache pinned admin notice",
}

// executableMarkupRe matches markup that runs code when a notice is rendered.
// Notice sinks legitimately carry layout markup -- LiteSpeed writes its own
// errors as a styled div -- so only the executing constructs count.
var executableMarkupRe = regexp.MustCompile(`(?i)<script[\s>]|<iframe[\s>]|javascript:|\bon(?:error|load|click|mouseover)\s*=|eval\s*\(\s*atob`)

const maxPluginNoticeBytes = 65536

// Notice lists can grow beyond a preview-sized read. Bound each value in bytes
// and carry its stored length so omitted content never looks like a clean scan.
// Hex preserves whitespace and stored escapes through the batch-row transport.
func checkWPPluginNotices(user string, creds wpDBCreds, prefix string) []alert.Finding {
	query := fmt.Sprintf(
		"SELECT option_name, OCTET_LENGTH(option_value), "+
			"CONCAT('x', HEX(LEFT(CAST(option_value AS BINARY), %d))) FROM %soptions "+
			"WHERE option_name IN (%s) LIMIT %d",
		maxPluginNoticeBytes, prefix, pluginNoticeSinkNameList(), len(pluginNoticeSinkOptions))
	var findings []alert.Finding
	for _, line := range runMySQLQuery(creds, query) {
		option, value, complete := parsePluginNoticeRow(line)
		if !complete {
			markCheckIncomplete(creds.queryCtx, "db_content")
			continue
		}
		if finding := pluginNoticeInjectionFinding(user, creds, prefix, option, value); finding != nil {
			findings = append(findings, *finding)
		}
	}
	return findings
}

func parsePluginNoticeRow(line string) (option, value string, complete bool) {
	parts := strings.SplitN(line, "\t", 3)
	if len(parts) != 3 {
		return "", "", false
	}
	size, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || size < 0 || size > maxPluginNoticeBytes {
		return "", "", false
	}
	encoded := parts[2]
	if !strings.HasPrefix(encoded, "x") || int64(len(encoded)-1) != 2*size {
		return "", "", false
	}
	decoded, err := hex.DecodeString(encoded[1:])
	if err != nil {
		return "", "", false
	}
	return parts[0], string(decoded), true
}

// pluginNoticeInjectionFinding reports executable markup stored in a plugin
// status option that WordPress renders as an admin notice. The option's
// identity carries the verdict: neither host reputation nor a first-seen
// baseline applies, so a payload that predates CSM's baseline and a loader on
// an ordinary HTTPS host are both reported.
func pluginNoticeInjectionFinding(user string, creds wpDBCreds, prefix, option, value string) *alert.Finding {
	name := strings.ToLower(strings.TrimSpace(option))
	sink, ok := pluginNoticeSinkOptions[name]
	if !ok {
		return nil
	}
	decoded := unescapeStoredSlashes(value)
	marker := executableMarkupRe.FindString(decoded)
	if marker == "" {
		return nil
	}

	detail := []string{
		fmt.Sprintf("Option: %s (%s)", option, sink),
		fmt.Sprintf("Executable markup: %s", strings.TrimSpace(marker)),
	}
	if hosts := externalScriptHosts(value); len(hosts) > 0 {
		detail = append(detail, fmt.Sprintf("Script host: %s", strings.Join(hosts, ", ")))
	}
	detail = append(detail,
		fmt.Sprintf("Content preview: %s", truncateDB(decoded, 200)),
		"This option holds plugin state, not site content. WordPress prints it in the dashboard, so the code runs for the next administrator who opens it.")

	return &alert.Finding{
		Severity: alert.Critical,
		Check:    "db_options_plugin_notice_injection",
		Message:  fmt.Sprintf("Executable markup stored in plugin notice option '%s' (account: %s)", option, user),
		Details:  dbContentFindingDetails(creds, prefix, detail...),
		DedupKey: dbContentDedupKey(user, creds, prefix, detail...),
	}
}

// pluginNoticeSinkNameList renders the sink names for a SQL IN clause.
func pluginNoticeSinkNameList() string {
	names := make([]string, 0, len(pluginNoticeSinkOptions))
	for name := range pluginNoticeSinkOptions {
		names = append(names, "'"+name+"'")
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
