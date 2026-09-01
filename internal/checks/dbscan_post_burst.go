package checks

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
)

const (
	// postBurstWindowDays is the recent period compared against everything the
	// site published before it.
	postBurstWindowDays = 365

	// postBurstMinSiteAgeDays keeps a young site quiet. A launch legitimately
	// produces its whole archive at once, and there is no history to judge it
	// against.
	postBurstMinSiteAgeDays = 400

	// postBurstMinRecent avoids reporting ordinary editorial activity on a very
	// quiet site, where any uptick is a large multiple of almost nothing.
	postBurstMinRecent = 50

	// postBurstRatio is how many times the site's entire prior output the recent
	// window must exceed. A steady publisher never reaches it; a doorway kit
	// clears it by an order of magnitude.
	postBurstRatio = 5
)

// checkWPPostVolumeBurst reports a site that suddenly publishes far more than
// it ever did before.
//
// This is the keyword-free half of spam detection. A live compromise published
// 508 posts across seven languages in under a year on a site that had managed
// 17 in the preceding seven; a gambling word list matched fewer than half of
// them, while the change in publishing rate separated spam from real content
// exactly. It says nothing about what the posts contain, which is the point --
// the next kit will use a different vocabulary.
func checkWPPostVolumeBurst(user string, creds wpDBCreds, prefix string) []alert.Finding {
	query := fmt.Sprintf(
		"SELECT DATEDIFF(NOW(), MIN(post_date)) AS site_age_days, "+
			"SUM(post_date < DATE_SUB(NOW(), INTERVAL %d DAY)) AS prior_posts, "+
			"SUM(post_date >= DATE_SUB(NOW(), INTERVAL %d DAY)) AS recent_posts "+
			"FROM %sposts WHERE post_type = 'post' AND post_status = 'publish'",
		postBurstWindowDays, postBurstWindowDays, prefix)

	rows := runMySQLQuery(creds, query)
	if len(rows) == 0 {
		return nil
	}
	parts := strings.SplitN(strings.TrimSpace(rows[0]), "\t", 3)
	if len(parts) != 3 {
		return nil
	}
	ageDays, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	prior, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	recent, err3 := strconv.Atoi(strings.TrimSpace(parts[2]))
	if err1 != nil || err2 != nil || err3 != nil {
		return nil
	}

	if ageDays < postBurstMinSiteAgeDays || recent < postBurstMinRecent {
		return nil
	}
	// prior == 0 on an established site means every post it has was published
	// in the recent window, which is the strongest form of this signal rather
	// than a division-by-zero edge case.
	if prior > 0 && recent < prior*postBurstRatio {
		return nil
	}

	return []alert.Finding{{
		Severity: alert.High,
		Check:    "db_post_volume_burst",
		Message: fmt.Sprintf("WordPress published %d posts in the last year against %d in the %d years before (account: %s)",
			recent, prior, ageDays/365, user),
		Details: dbContentFindingDetails(creds.dbName, prefix,
			fmt.Sprintf("Site has been publishing for %d days. A sudden flood on a long-quiet site is how "+
				"doorway spam arrives, and it is visible without knowing what language or vocabulary the "+
				"spam uses.\nReview the recent posts before acting: a genuine content migration looks the same.",
				ageDays)),
	}}
}
