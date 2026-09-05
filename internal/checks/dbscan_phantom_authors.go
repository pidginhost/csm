package checks

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
)

// phantomAuthorFarmSize is the published-post count at which a phantom author
// is treated as a content farm rather than a likely orphan. A direct SQL user
// deletion can leave a small number of posts behind; a large group warrants a
// Critical alert.
const phantomAuthorFarmSize = 100

// maxPhantomAuthorsReported bounds the finding count across one installation,
// including all blogs in a multisite network.
const maxPhantomAuthorsReported = 25

// checkWPPhantomAuthors finds published posts whose post_author has no row in
// the network users table. postsPrefix and usersPrefix are kept separate so a
// multisite blog can join its own posts table to the shared users table.
// Callers derive both from resolveTablePrefix, appending only a numeric blog ID
// to postsPrefix, before either value reaches SQL construction.
//
// Doorway kits attribute their pages to invented author IDs and then install a
// filter that removes those IDs from admin queries, patching the post counts to
// match. The dashboard therefore shows a clean site while the posts are served
// to visitors and listed in crawler-facing sitemaps. The orphaned author ID is
// what the cloak cannot hide: it is a property of the data, not of the code
// doing the hiding, so it survives every renaming and re-obfuscation of the
// filter itself.
func checkWPPhantomAuthors(user string, creds wpDBCreds, postsPrefix, usersPrefix string, limit int) []alert.Finding {
	var findings []alert.Finding
	if limit <= 0 {
		return findings
	}

	query := fmt.Sprintf(
		"SELECT p.post_author, COUNT(*) AS c FROM %sposts p "+
			"LEFT JOIN %susers u ON u.ID = p.post_author "+
			"WHERE u.ID IS NULL AND p.post_author <> 0 "+
			"AND p.post_type = 'post' AND p.post_status = 'publish' "+
			"GROUP BY p.post_author ORDER BY c DESC LIMIT %d",
		postsPrefix, usersPrefix, limit)

	for _, line := range runMySQLQuery(creds, query) {
		parts := strings.SplitN(strings.TrimSpace(line), "\t", 2)
		if len(parts) != 2 {
			continue
		}
		authorID, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 64)
		if err != nil || authorID == 0 {
			continue
		}
		count, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 64)
		if err != nil || count == 0 {
			continue
		}

		severity := alert.Warning
		if count >= phantomAuthorFarmSize {
			severity = alert.Critical
		}
		postNoun := "posts"
		if count == 1 {
			postNoun = "post"
		}

		findings = append(findings, alert.Finding{
			Severity: severity,
			Check:    "db_phantom_post_author",
			Message: fmt.Sprintf("%d published %s are attributed to a non-existent user (account: %s, author ID %d)",
				count, postNoun, user, authorID),
			Details: dbContentFindingDetails(creds, postsPrefix,
				fmt.Sprintf("post_author = %d has no row in %susers.\n"+
					"A small number can remain after an administrator deletes a user directly in SQL. "+
					"Large groups can indicate hidden or injected content.",
					authorID, usersPrefix)),
			// Crossing into a content farm must alert even if the orphan group
			// was baselined or dismissed. Counts within either tier stay stable.
			DedupKey: dbContentDedupKey(user, creds, postsPrefix,
				"farm="+strconv.FormatBool(count >= phantomAuthorFarmSize),
				fmt.Sprintf("post_author = %d has no row in %susers.\n"+
					"A small number can remain after an administrator deletes a user directly in SQL. "+
					"Large groups can indicate hidden or injected content.",
					authorID, usersPrefix)),
		})
		if len(findings) >= limit {
			break
		}
	}

	return findings
}

// capPhantomAuthorFindings bounds one installation's alert volume after every
// multisite posts table has been checked. Critical farms take precedence over
// likely orphan warnings, so a noisy primary blog cannot hide a compromised
// secondary blog by consuming the cap first.
func capPhantomAuthorFindings(findings []alert.Finding, limit int) []alert.Finding {
	selected := make([]bool, len(findings))
	remaining := limit
	for i, finding := range findings {
		if remaining == 0 {
			break
		}
		if finding.Check == "db_phantom_post_author" && finding.Severity == alert.Critical {
			selected[i] = true
			remaining--
		}
	}
	for i, finding := range findings {
		if remaining == 0 {
			break
		}
		if finding.Check == "db_phantom_post_author" && !selected[i] {
			selected[i] = true
			remaining--
		}
	}

	out := make([]alert.Finding, 0, len(findings))
	for i, finding := range findings {
		if finding.Check != "db_phantom_post_author" || selected[i] {
			out = append(out, finding)
		}
	}
	return out
}
