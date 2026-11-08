package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestParseFTPLogLineHostnamePeerIgnoresUsernameAddress(t *testing.T) {
	for _, user := range []string{"x 198.51.100.7", "x (a@198.51.100.7) y", "198.51.100.7"} {
		line := `Apr 11 10:00:00 host pure-ftpd: (?@client.example.com) [WARNING] Authentication failed for user [` + user + `]`
		if got := parseFTPLogLine(line, &config.Config{}); got != nil {
			t.Errorf("username %q produced %+v", user, got)
		}
	}
}
