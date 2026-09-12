package daemon

import (
	"github.com/pidginhost/csm/internal/health"
	"github.com/pidginhost/csm/internal/store"
)

// WordPressVerification supplies the same persisted coverage to the CLI and API.
func (d *Daemon) WordPressVerification() map[string]health.WPVerificationCounts {
	db := store.Global()
	if db == nil {
		return nil
	}
	result := make(map[string]health.WPVerificationCounts)
	for _, kind := range []string{"core", "plugins"} {
		rows, err := db.WPVerification(kind)
		if err != nil {
			result[kind] = health.WPVerificationCounts{Error: "verification history unavailable"}
			continue
		}
		if len(rows) == 0 {
			continue
		}
		var counts health.WPVerificationCounts
		for _, row := range rows {
			switch row.State {
			case "verified":
				counts.Verified++
			case "modified":
				counts.Modified++
			case "unverified":
				counts.Unverified++
			case "not_wordpress":
				counts.NotWordPress++
			default:
				counts.Unknown++
			}
			if row.AttemptAt.After(counts.LastAttempt) {
				counts.LastAttempt = row.AttemptAt
			}
		}
		result[kind] = counts
	}
	return result
}
