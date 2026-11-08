package checks

import "testing"

func TestExtractIPFromLogPureFTPDUsesOnlyPeerToken(t *testing.T) {
	cases := map[string]string{
		`Apr 11 10:00:00 host pure-ftpd: (?@client.example.com) [WARNING] Authentication failed for user [x 198.51.100.7]`:       "",
		`Apr 11 10:00:00 host pure-ftpd: (?@client.example.com) [WARNING] Authentication failed for user [x (a@198.51.100.7) y]`: "",
		`Apr 11 10:00:00 host pure-ftpd: (?@203.0.113.5) [WARNING] Authentication failed for user [x 198.51.100.7]`:              "203.0.113.5",
	}
	for line, want := range cases {
		if got := extractIPFromLog(line); got != want {
			t.Errorf("extractIPFromLog(%q) = %q, want %q", line, got, want)
		}
	}
}
