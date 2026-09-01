package checks

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
)

// phantomAuthorFarmSize is the published-post count above which a phantom
// author is a content farm rather than an orphan. Deleting a WordPress user
// through the dashboard reassigns or removes their posts, so a handful of
// orphans can survive a hand-run SQL delete; thousands cannot.
const phantomAuthorFarmSize = 100

// maxPhantomAuthorsReported bounds the finding count so a heavily seeded farm
// cannot flood an operator's alert channel.
const maxPhantomAuthorsReported = 25

// checkWPPhantomAuthors finds published posts whose post_author has no row in
// the users table.
//
// Doorway kits attribute their pages to invented author IDs and then install a
// filter that removes those IDs from admin queries, patching the post counts to
// match. The dashboard therefore shows a clean site while the posts are served
// to visitors and listed in crawler-facing sitemaps. The orphaned author ID is
// what the cloak cannot hide: it is a property of the data, not of the code
// doing the hiding, so it survives every renaming and re-obfuscation of the
// filter itself.
func checkWPPhantomAuthors(user string, creds wpDBCreds, prefix string) []alert.Finding {
	var findings []alert.Finding

	query := fmt.Sprintf(
		"SELECT p.post_author, COUNT(*) AS c FROM %sposts p "+
			"LEFT JOIN %susers u ON u.ID = p.post_author "+
			"WHERE u.ID IS NULL AND p.post_author <> 0 "+
			"AND p.post_type = 'post' AND p.post_status = 'publish' "+
			"GROUP BY p.post_author ORDER BY c DESC LIMIT %d",
		prefix, prefix, maxPhantomAuthorsReported)

	for _, line := range runMySQLQuery(creds, query) {
		parts := strings.SplitN(strings.TrimSpace(line), "\t", 2)
		if len(parts) != 2 {
			continue
		}
		authorID, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil || authorID == 0 {
			continue
		}
		count, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil || count <= 0 {
			continue
		}

		severity := alert.High
		if count >= phantomAuthorFarmSize {
			severity = alert.Critical
		}

		findings = append(findings, alert.Finding{
			Severity: severity,
			Check:    "db_phantom_post_author",
			Message: fmt.Sprintf("%d published posts are attributed to a non-existent user (account: %s, author ID %d)",
				count, user, authorID),
			Details: dbContentFindingDetails(creds.dbName, prefix,
				fmt.Sprintf("post_author = %d has no row in %susers.\n"+
					"Posts attributed to an author that does not exist are not reachable through the "+
					"dashboard, but are served to visitors and can be listed in a sitemap.",
					authorID, prefix)),
		})
	}

	return findings
}
