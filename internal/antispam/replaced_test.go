package antispam

import (
	"strings"
	"testing"
	"time"
)

func TestBackupNameRoundTrip(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, p := range []string{"/etc/rspamd/local.d/milter_headers.conf", "/etc/rspamd/local.d/maps.d/a-b.map", RoundcubeIncludePath} {
		name := BackupName(p, at.In(time.FixedZone("east", 3*3600)))
		if !strings.HasPrefix(name, "20260102T030405Z_") || strings.Contains(name, "/") {
			t.Errorf("%s -> backup name %q", p, name)
		}
		got, ok := ParseBackupName(name)
		if !ok || got != p {
			t.Fatalf("%s -> %q %v", p, got, ok)
		}
	}
	for _, bad := range []string{"x", "20260102T030405Z_relative", "nottime_%2Fetc%2Fx", "20260102T030405Z_%2Fetc%2F..%2Fx",
		".20260102T030405Z_%2Fetc%2Fx.123.csmtmp", "20260102T030405Z_%zz", "20260102T030405Z_"} {
		if _, ok := ParseBackupName(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}
