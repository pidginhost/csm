package checks

import (
	"encoding/base64"
	"strings"
	"testing"
)

// Decode pass must catch the malicious marker even when the attacker
// wraps it in a long base64 blob, up to the cap. Pins that the
// 16384-byte cap leaves enough room for a realistic payload to land
// inside the decode window without the cap silently chopping it.
func TestMatchCrontabPatternsDeep_CatchesMaliciousInsideCappedBlob(t *testing.T) {
	// Build ~12 KiB of decoded body that ends with the marker. Encoded
	// length is ~16 KiB, right at the cap boundary, so a tighter cap
	// would have chopped the trailing marker.
	body := strings.Repeat("legit-cron-comment-line\n", 500) + "base64 -d|bash"
	encoded := base64.StdEncoding.EncodeToString([]byte(body))
	if len(encoded) > crontabBase64BlobMaxBytes {
		t.Fatalf("encoded length %d exceeds cap %d; rebalance the test fixture", len(encoded), crontabBase64BlobMaxBytes)
	}

	cron := "* * * * * echo " + encoded + " | base64 -d | bash\n"

	matched := MatchCrontabPatternsDeep(cron)
	if !containsPattern(matched, "base64 -d|bash") {
		t.Errorf("decode pass missed marker inside %d-byte blob: matched=%v", len(encoded), matched)
	}
}

// A blob padded past the cap is recorded in the truncation counter so
// operators can spot the evasion attempt before it lands silently.
func TestMatchCrontabPatternsDeep_OverCapBlobIncrementsCounter(t *testing.T) {
	body := strings.Repeat("X", crontabBase64BlobMaxBytes*2)
	encoded := base64.StdEncoding.EncodeToString([]byte(body))
	if len(encoded) <= crontabBase64BlobMaxBytes {
		t.Fatalf("test fixture too small: encoded=%d cap=%d", len(encoded), crontabBase64BlobMaxBytes)
	}

	cron := "* * * * * echo " + encoded + "\n"

	before := scrapeSum(t, "csm_checks_crontab_truncated_total") +
		scrapeSum(t, "csm_checks_crontab_base64_truncated_total")
	_ = MatchCrontabPatternsDeep(cron)
	after := scrapeSum(t, "csm_checks_crontab_truncated_total") +
		scrapeSum(t, "csm_checks_crontab_base64_truncated_total")

	if after-before < 1 {
		t.Errorf("over-cap blob must increment truncation counter; before=%g after=%g", before, after)
	}
}

func containsPattern(list []string, want string) bool {
	for _, m := range list {
		if m == want {
			return true
		}
	}
	return false
}
