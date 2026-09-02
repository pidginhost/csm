package checks

import (
	"encoding/hex"
	"fmt"
	"strconv"
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

type storedCodeRow struct {
	id          string
	status      string
	contentSize int64
	code        []byte
}

// parseStoredCodeRow decodes one tab-separated query row. ok remains true for
// a decoded prefix when the query or transport truncates it; complete tells the
// caller not to present that partial row as a complete scan.
func parseStoredCodeRow(line string) (row storedCodeRow, ok, complete bool) {
	parts := strings.SplitN(strings.TrimSpace(line), "\t", 4)
	if len(parts) != 4 {
		return row, false, false
	}
	contentSize, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || contentSize < 0 {
		return row, false, false
	}
	encodedCode := strings.TrimSpace(parts[3])
	code, decodeErr := hex.DecodeString(encodedCode)
	if len(code) == 0 {
		return row, false, false
	}
	return storedCodeRow{
		id:          strings.TrimSpace(parts[0]),
		status:      strings.TrimSpace(parts[1]),
		contentSize: contentSize,
		code:        code,
	}, true, decodeErr == nil && int64(len(code)) == contentSize
}

// checkWPStoredCode scans WPCode PHP that lives in the database rather than in
// a file.
//
// WPCode executes stored code by design, which makes the posts table an
// executable surface that no filesystem scan covers. On a live
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
		"SELECT p.ID, p.post_status, OCTET_LENGTH(p.post_content), "+
			"HEX(LEFT(CAST(p.post_content AS BINARY), %d)) FROM %sposts p "+
			"WHERE p.post_type = 'wpcode' AND p.post_content <> '' "+
			"AND EXISTS (SELECT 1 FROM %sterm_relationships tr "+
			"JOIN %sterm_taxonomy tt ON tt.term_taxonomy_id = tr.term_taxonomy_id "+
			"JOIN %sterms t ON t.term_id = tt.term_id "+
			"WHERE tr.object_id = p.ID AND tt.taxonomy = 'wpcode_type' "+
			"AND t.slug IN ('php', 'universal')) "+
			"ORDER BY CASE p.post_status WHEN 'publish' THEN 0 WHEN 'draft' THEN 1 "+
			"WHEN 'trash' THEN 2 ELSE 3 END, p.ID LIMIT %d",
		maxStoredCodeBytes, prefix, prefix, prefix, prefix, maxStoredCodeRows+1)

	var findings []alert.Finding
	rows := runMySQLQuery(creds, query)
	if len(rows) > maxStoredCodeRows {
		markCheckIncomplete(creds.queryCtx, "db_content")
		rows = rows[:maxStoredCodeRows]
	}
	for _, line := range rows {
		row, ok, complete := parseStoredCodeRow(line)
		if !complete {
			markCheckIncomplete(creds.queryCtx, "db_content")
		}
		if !ok {
			continue
		}
		// MySQL HEX() always emits valid hex, so a decode error means the row
		// was truncated in transport. Scan whatever decoded rather than
		// dropping the row: a partially recovered payload still identifies a
		// backdoor, and silence here would read as "clean".
		cacheDefeat, crawler := storedCloakComponents(row.code)
		hits := scanner.ScanContentWithSize(row.code, ".php", row.contentSize)
		if len(hits) == 0 {
			// No signature matched, but stored code that both defeats caching
			// and looks for a crawler is a cloak on its own terms.
			if cloak := storedCloakFindingWithComponents(user, creds, prefix, row, cacheDefeat, crawler); cloak != nil {
				findings = append(findings, *cloak)
			}
			continue
		}

		// Only a published snippet runs. A draft is one click from running; a
		// trashed one is evidence of what was run before.
		severity := alert.Warning
		switch row.status {
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
				row.id, row.status, strings.Join(names, ", "), user),
			Details: dbContentFindingDetails(creds, prefix,
				fmt.Sprintf("Snippet %s is stored in %sposts for WPCode, "+
					"so it is not visible to any filesystem scan.\nMatched: %s%s",
					row.id, prefix, strings.Join(names, ", "),
					storedCloakNote(cacheDefeat, crawler))),
		})
	}
	return findings
}
