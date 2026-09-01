package checks

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
)

const maxTaxonomyRowsScanned = 500

// termNameIsURL matches a term whose name is a URL. Categories and tags are
// human labels; a URL in that field is put there by a link-farm kit, never by
// an editor.
var termNameIsURL = regexp.MustCompile(`(?i)^\s*(?:https?://|www\.)\S+`)

// termNameSpamVocabulary is the gambling and pharmacy vocabulary already used
// by the post-content spam rules, applied to term names. Bounded on word
// edges so "specialist" does not match "cialis".
var termNameSpamVocabulary = regexp.MustCompile(
	`(?i)(?:^|[^a-z])(?:casino|casinos|kasino|gambling|betting|bookmaker|mostbet|viagra|cialis|pharmacy|pokies|slots|bahis)(?:[^a-z]|$)`)

// checkWPSpamTaxonomy reports attacker-created categories, tags and menu
// entries.
//
// Removing spam posts leaves their taxonomy behind, and a category archive is a
// public page: a spam taxonomy is a doorway network even with no posts attached.
// This was missed during a live cleanup -- the homepage still served gambling
// links after every spam post had been deleted.
func checkWPSpamTaxonomy(user string, creds wpDBCreds, prefix string) []alert.Finding {
	query := fmt.Sprintf(
		"SELECT t.term_id, tt.taxonomy, tt.count, t.name FROM %sterms t "+
			"JOIN %sterm_taxonomy tt ON tt.term_id = t.term_id LIMIT %d",
		prefix, prefix, maxTaxonomyRowsScanned)

	var urlNamed, keywordNamed []string
	for _, line := range runMySQLQuery(creds, query) {
		parts := strings.SplitN(strings.TrimRight(line, "\r\n"), "\t", 4)
		if len(parts) != 4 {
			continue
		}
		name := strings.TrimSpace(parts[3])
		if name == "" {
			continue
		}
		label := fmt.Sprintf("%s (%s)", name, strings.TrimSpace(parts[1]))
		switch {
		case termNameIsURL.MatchString(name):
			urlNamed = append(urlNamed, label)
		case termNameSpamVocabulary.MatchString(name):
			keywordNamed = append(keywordNamed, label)
		}
	}

	total := len(urlNamed) + len(keywordNamed)
	if total == 0 {
		return nil
	}

	details := []string{
		"A category or tag archive is a public page, so these terms are reachable " +
			"even with no posts attached. Deleting spam posts does not remove them.",
	}
	if len(urlNamed) > 0 {
		details = append(details, "Named after a URL: "+strings.Join(urlNamed, ", "))
	}
	if len(keywordNamed) > 0 {
		details = append(details, "Spam vocabulary: "+strings.Join(keywordNamed, ", "))
	}

	// A URL as a term name has no benign reading; vocabulary alone can be a
	// legitimate site writing about an industry.
	severity := alert.High
	if len(urlNamed) == 0 {
		severity = alert.Warning
	}

	return []alert.Finding{{
		Severity: severity,
		Check:    "db_spam_taxonomy",
		Message: fmt.Sprintf("%d spam categories/tags found in WordPress taxonomy (account: %s)",
			total, user),
		Details: dbContentFindingDetails(creds.dbName, prefix, details...),
	}}
}
