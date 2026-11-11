package checks

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/attackdb"
)

func TestCpanelProxyReputationDoesNotUseLoggedAddress(t *testing.T) {
	for _, ip := range []string{"192.0.2.66", "2001:db8::66"} {
		for name, suffix := range map[string]string{
			"dated":        `- [11/09/2026:12:00:00 -0000] "GET /execute/Themes/list HTTP/1.1" 401 0`,
			"undated":      `- [bad] "GET /execute/Themes/list HTTP/1.1" 401 0`,
			"user content": `x [11/10/2026:09:00:00 -0000] "y [11/09/2026:12:00:00 -0000] "GET /execute/Themes/list HTTP/1.1" 401 0`,
			"broken tail":  `- [11/09/2026:12:00:00 -0000] "GET /execute/Themes/list HTTP/1.1"`,
		} {
			t.Run(ip+"/"+name, func(t *testing.T) {
				cfg := listIPs(t, ip)
				sightingLogs(t, map[string]string{reputationWHMAccessLog: ip + " proxy " + suffix + "\n"})
				ips, records := collectRecentSightings(cfg, time.Now())
				if len(ips) != 0 || len(records) != 0 {
					t.Errorf("proxy record supplied reputation candidates: %v, sightings: %v", ips, records)
				}
				db := attackdb.NewForTest(nil)
				for _, f := range CheckIPReputation(context.Background(), cfg, nil) {
					if f.Check == "ip_reputation" {
						t.Errorf("proxy record supplied an IP reputation finding: %+v", f)
					}
					db.RecordFinding(f)
				}
				if got := db.LookupIP(ip); got != nil {
					t.Fatalf("proxy record supplied address history: %+v", got)
				}
			})
		}
	}
}

func TestCpanelProxyReputationPreservesDirectSightings(t *testing.T) {
	at := time.Now().Add(-time.Minute).Truncate(time.Second)
	const ip = "192.0.2.66"
	for _, user := range []string{"-", "proxy"} {
		t.Run(user, func(t *testing.T) {
			cfg := listIPs(t, ip)
			direct := staleSessionAccessLine(ip, user, cpanelUTCStamp(at), "/execute/Themes/list", "401")
			proxy := strings.Replace(direct, " - ", " proxy ", 1)
			paths := sightingLogs(t, map[string]string{reputationWHMAccessLog: direct + "\n" + proxy + "\n"})
			ips, records := collectRecentSightings(cfg, time.Now())
			if len(ips) != 1 || ips[ip] != "cPanel/WHM access" || len(records) != 1 {
				t.Fatalf("direct sighting changed: %v, records: %v", ips, records)
			}
			f := reputationFindingFor(t, CheckIPReputation(context.Background(), cfg, nil), ip)
			wantScanObservation(t, f, ProducerReputationScan, syslogTestRef(t, paths[reputationWHMAccessLog], 0, direct), at)
			if _, _, err := mintScanFinding(t, f); err != nil {
				t.Fatalf("direct sighting lost admission evidence: %v", err)
			}
		})
	}
}
