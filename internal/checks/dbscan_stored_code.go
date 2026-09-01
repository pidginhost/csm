package checks

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
)

const (
	// A snippet is code a human wrote into a form; the ones that matter are far
	// smaller than this. The bound keeps one pathological row from dominating a
	// scan, and the hex encoding below doubles whatever is transferred.
	maxStoredCodeBytes = 65536
	maxStoredCodeRows  = 200
)

// checkWPStoredCode scans PHP that lives in the database rather than in a file.
//
// Snippet-manager plugins execute stored code by design, which makes the posts
// table an executable surface that no filesystem scan covers. On a live
// compromise a 17KB obfuscated backdoor ran on every request from a WPCode row
// while a full file sweep of the same account -- core checksums, eval chains,
// upload shells -- came back clean.
//
// Content is hex-encoded by the query because snippets contain newlines and
// tabs, which would otherwise break row parsing.
func checkWPStoredCode(user string, creds wpDBCreds, prefix string) []alert.Finding {
	scanner := contentSignatureScanner()
	if scanner == nil {
		return nil
	}

	// WPCode / Insert Headers and Footers. Code Snippets keeps its code in its
	// own table and is the next surface worth adding here.
	query := fmt.Sprintf(
		"SELECT ID, post_status, HEX(LEFT(post_content, %d)) FROM %sposts "+
			"WHERE post_type = 'wpcode' AND post_content <> '' "+
			"ORDER BY FIELD(post_status,'publish','draft','trash'), ID LIMIT %d",
		maxStoredCodeBytes, prefix, maxStoredCodeRows)

	var findings []alert.Finding
	for _, line := range runMySQLQuery(creds, query) {
		parts := strings.SplitN(strings.TrimSpace(line), "\t", 3)
		if len(parts) != 3 {
			continue
		}
		id, status := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		// MySQL HEX() always emits valid hex, so a decode error means the row
		// was truncated in transport. Scan whatever decoded rather than
		// dropping the row: a partially recovered payload still identifies a
		// backdoor, and silence here would read as "clean".
		code, _ := hex.DecodeString(strings.TrimSpace(parts[2]))
		if len(code) == 0 {
			continue
		}

		hits := scanner.ScanContent(code, ".php")
		if len(hits) == 0 {
			continue
		}

		// Only a published snippet runs. A draft is one click from running; a
		// trashed one is evidence of what was run before.
		severity := alert.Warning
		switch status {
		case "publish":
			severity = alert.Critical
		case "draft":
			severity = alert.High
		}

		names := make([]string, 0, len(hits))
		for _, h := range hits {
			names = append(names, h.RuleName)
		}
		findings = append(findings, alert.Finding{
			Severity: severity,
			Check:    "db_stored_code_execution",
			Message: fmt.Sprintf("Stored PHP snippet %s (%s) matches %s (account: %s)",
				id, status, strings.Join(names, ", "), user),
			Details: dbContentFindingDetails(creds.dbName, prefix,
				fmt.Sprintf("Snippet %s is stored in %sposts and executed by the snippet plugin, "+
					"so it is not visible to any filesystem scan.\nMatched: %s",
					id, prefix, strings.Join(names, ", "))),
		})
	}
	return findings
}
