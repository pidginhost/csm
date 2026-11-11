package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestMailVolumeCountsOnlyArrivals(t *testing.T) {
	withOwnerTable(t)
	quoted := `2026-01-01 10:00:00 1abc23-000456-AB <= "first last"@example.com U=nobody P=local S=100` + "\n"
	reply := `2026-01-01 10:00:01 1abc23-000457-AB ** victim@example.net R=dkim_lookuphost: SMTP error from remote mail server: 550 rejected <= x@example.org` + "\n"
	body := strings.Repeat(quoted, perAccountMailThreshold) + strings.Repeat(reply, perAccountMailThreshold)
	withMockOS(t, &mockOS{open: openTempLog(t, body)})

	got := CheckMailPerAccount(context.Background(), &config.Config{}, nil)
	if len(got) != 1 || got[0].Domain != "example.com" {
		t.Fatalf("want one finding for the quoted sender's domain, none for delivery replies; got %+v", got)
	}
}
