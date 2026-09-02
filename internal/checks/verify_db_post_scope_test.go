package checks

import (
	"strings"
	"testing"
)

// The detector reports at most five example post IDs, but the re-check used
// to re-read only those IDs: cleaning the five examples resolved a finding
// while the same injection sat in every other post. The re-check now searches
// the whole table by pattern, the way the detector found it.
func TestVerifyDBPostInjectionSearchesWholeTableNotSampledIDs(t *testing.T) {
	details := "Database: alice_wp\nAffected post IDs: 12, 34\nPattern: base64_decode"
	msg := "WordPress posts contain base64_decode in database content (account: alice, 2 posts)"
	withWPVerifyDiscovery(t, "alice", "alice_wp", "wp_")
	withRootQuery(t, func(_, query string, args ...any) ([]string, error) {
		if strings.Contains(query, "ID IN") {
			// The sampled posts were cleaned; nothing else was.
			return []string{"12\tclean body\t", "34\talso clean\t"}, nil
		}
		if strings.Contains(query, "LIKE") {
			for _, a := range args {
				if s, ok := a.(string); ok && strings.HasPrefix(s, "%base64") {
					return []string{"99\tstill bad base64_decode($x)\t"}, nil
				}
			}
			t.Fatalf("pattern search query carries no pattern argument: %s %v", query, args)
		}
		return nil, nil
	})
	res := verifyDBPostInjection(msg, details)
	if !res.Checked || res.Resolved {
		t.Fatalf("finding resolved although an unsampled post still carries the injection: %+v", res)
	}
}
