package checks

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/mysqlclient"
)

const (
	maxTaxonomyRowsScanned    = 500
	maxTaxonomySamplesPerKind = 10
)

const (
	termNameURLPattern  = `^[[:space:]]*(https?://|www[.])[^[:space:]]+`
	termNameSpamPattern = `(^|[^a-z])(casino|casinos|kasino|gambling|betting|bookmaker|mostbet|viagra|cialis|pharmacy|pokies|slots|bahis)([^a-z]|$)`
)

// termNameIsURL matches a term whose name is a URL. Categories and tags are
// human labels; a URL in that field is put there by a link-farm kit, never by
// an editor.
var termNameIsURL = regexp.MustCompile(`(?i)` + termNameURLPattern)

// termNameSpamVocabulary covers gambling and pharmacy vocabulary in term
// names. It is bounded on word edges so "specialist" does not match "cialis".
var termNameSpamVocabulary = regexp.MustCompile(`(?i)` + termNameSpamPattern)

type spamTaxonomyRow struct {
	taxonomy string
	name     string
}

func parseSpamTaxonomyRow(line string) (spamTaxonomyRow, bool) {
	parts := strings.SplitN(strings.TrimRight(line, "\r\n"), "\t", 4)
	if len(parts) != 4 {
		return spamTaxonomyRow{}, false
	}
	name := strings.TrimSpace(mysqlclient.BatchUnescape(parts[3]))
	if name == "" {
		return spamTaxonomyRow{}, false
	}
	return spamTaxonomyRow{
		taxonomy: strings.TrimSpace(mysqlclient.BatchUnescape(parts[1])),
		name:     name,
	}, true
}

// checkWPSpamTaxonomy reports attacker-created taxonomy terms.
//
// Removing spam posts leaves their taxonomy behind, and a category archive is a
// public page: a spam taxonomy is a doorway network even with no posts attached.
// This was missed during a live cleanup -- the homepage still served gambling
// links after every spam post had been deleted.
func checkWPSpamTaxonomy(user string, creds wpDBCreds, prefix string) []alert.Finding {
	urlCandidate := fmt.Sprintf("LOWER(t.name) REGEXP '%s'", termNameURLPattern)
	spamCandidate := fmt.Sprintf("LOWER(t.name) REGEXP '%s'", termNameSpamPattern)
	query := fmt.Sprintf(
		"SELECT t.term_id, tt.taxonomy, tt.count, t.name FROM %sterms t "+
			"JOIN %sterm_taxonomy tt ON tt.term_id = t.term_id "+
			"WHERE %s OR %s ORDER BY CASE WHEN %s THEN 0 ELSE 1 END, t.term_id LIMIT %d",
		prefix, prefix, urlCandidate, spamCandidate, urlCandidate, maxTaxonomyRowsScanned+1)

	var urlNamed, keywordNamed []string
	var urlCount, keywordCount int
	rows := runMySQLQuery(creds, query)
	truncated := len(rows) > maxTaxonomyRowsScanned
	if truncated {
		markCheckIncomplete(creds.queryCtx, "db_content")
		rows = rows[:maxTaxonomyRowsScanned]
	}
	for _, line := range rows {
		row, ok := parseSpamTaxonomyRow(line)
		if !ok {
			markCheckIncomplete(creds.queryCtx, "db_content")
			continue
		}
		label := fmt.Sprintf("%q (%q)", row.name, row.taxonomy)
		switch {
		case termNameIsURL.MatchString(row.name):
			urlCount++
			if len(urlNamed) < maxTaxonomySamplesPerKind {
				urlNamed = append(urlNamed, label)
			}
		case termNameSpamVocabulary.MatchString(row.name):
			keywordCount++
			if len(keywordNamed) < maxTaxonomySamplesPerKind {
				keywordNamed = append(keywordNamed, label)
			}
		}
	}

	total := urlCount + keywordCount
	if total == 0 {
		return nil
	}

	details := []string{
		"Taxonomy terms can feed public archives, navigation and other rendered " +
			"content. Deleting spam posts does not remove them.",
	}
	if urlCount > 0 {
		details = append(details, taxonomySampleDetails("Named after a URL", urlNamed, urlCount))
	}
	if keywordCount > 0 {
		details = append(details, taxonomySampleDetails("Spam vocabulary", keywordNamed, keywordCount))
	}

	// A URL as a term name has no benign reading; vocabulary alone can be a
	// legitimate site writing about an industry.
	severity := alert.High
	if urlCount == 0 {
		severity = alert.Warning
	}

	return []alert.Finding{{
		Severity: severity,
		Check:    "db_spam_taxonomy",
		Message: fmt.Sprintf("%s spam taxonomy terms found in WordPress (account: %s)",
			spamCountLabel(total, truncated), user),
		Details: dbContentFindingDetails(creds.dbName, prefix, details...),
	}}
}

func taxonomySampleDetails(label string, samples []string, total int) string {
	if total > len(samples) {
		label += fmt.Sprintf(" (showing %d of %d)", len(samples), total)
	}
	return label + ": " + strings.Join(samples, ", ")
}
