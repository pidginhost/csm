package checks

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func TestPureFTPDClientIPPureFTPDUsesOnlyPeerToken(t *testing.T) {
	cases := map[string]string{
		`Apr 11 10:00:00 host pure-ftpd: (?@client.example.com) [WARNING] Authentication failed for user [x 198.51.100.7]`:       "",
		`Apr 11 10:00:00 host pure-ftpd: (?@client.example.com) [WARNING] Authentication failed for user [x (a@198.51.100.7) y]`: "",
		`Apr 11 10:00:00 host pure-ftpd: (?@203.0.113.5) [WARNING] Authentication failed for user [x 198.51.100.7]`:              "203.0.113.5",
	}
	for line, want := range cases {
		if got := PureFTPDClientIP(line); got != want {
			t.Errorf("PureFTPDClientIP(%q) = %q, want %q", line, got, want)
		}
	}
}

func TestPureFTPDClientIPPureFTPDPeerPosition(t *testing.T) {
	for _, peer := range []string{"", "(unknown)", "(?@)", "(?@client.example.com)", "(?@203.0.113.5", "(?@client.example.com)junk"} {
		for _, user := range []string{"x 198.51.100.7 y", "x (a@198.51.100.7) y"} {
			line := "Apr 11 10:00:00 192.0.2.1 pure-ftpd[1]: " + peer + " [WARNING] Authentication failed for user [" + user + "]"
			if got := PureFTPDClientIP(line); got != "" {
				t.Errorf("PureFTPDClientIP(%q) = %q, want no address", line, got)
			}
		}
	}
}

func TestFTPScansUseOnlyPeerAddress(t *testing.T) {
	for _, stored := range []bool{false, true} {
		name := "legacy"
		if stored {
			name = "stored"
		}
		t.Run(name, func(t *testing.T) {
			var st *state.Store
			if stored {
				var err error
				st, err = state.Open(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = st.Close() })
			}
			prefix := time.Now().Format(time.RFC3339) + " 192.0.2.1 pure-ftpd[1]: "
			var lines []string
			for _, peer := range []string{"", "(unknown)", "(?@client.example.com)", "(?@)", "(?@203.0.113.5", "(?@203.0.113.9)", "(?@2001:db8::9)"} {
				for range ftpFailThreshold {
					lines = append(lines, prefix+peer+" [WARNING] Authentication failed for user [x 198.51.100.7 (a@198.51.100.8) y]")
				}
			}
			path := writeFollowFile(t, strings.Join(lines, "\n")+"\n")
			withMockOS(t, &mockOS{open: func(string) (*os.File, error) { return os.Open(path) }})
			findings := CheckFTPLogins(context.Background(), &config.Config{}, st)
			if len(findings) != 2 {
				t.Fatalf("findings = %+v, want only the two valid peers", findings)
			}
			seen := make(map[string]bool)
			for _, f := range findings {
				if f.Check != "ftp_bruteforce" || (f.SourceIP != "203.0.113.9" && f.SourceIP != "2001:db8::9") || seen[f.SourceIP] {
					t.Errorf("unexpected finding: %+v", f)
				}
				seen[f.SourceIP] = true
			}
			if stored {
				tracker := loadFTPFailTracker(st)
				if len(tracker.Buckets) != 2 || tracker.count("203.0.113.9") != ftpFailThreshold || tracker.count("2001:db8::9") != ftpFailThreshold {
					t.Errorf("unexpected persisted failures: %+v", tracker.Buckets)
				}
			}
		})
	}
}
