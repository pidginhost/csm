package checks

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/mysqlclient"
)

type findingIDBlocker struct {
	outcomeStubBlocker
	ids          []string
	subnetIDs    []string
	permanentIDs []string
	live         map[string]bool
}

func TestDatabaseSessionBlockRetainsDatabaseFindingID(t *testing.T) {
	for _, check := range []string{"db_options_injection", "db_siteurl_hijack"} {
		t.Run(check, func(t *testing.T) {
			persistentFS := osFS
			withDatabaseCoverageInstalls(t, map[string]string{
				"/home/alice/public_html/wp-config.php": databaseCoverageConfig("site"),
			}, nil)
			mysqlclient.SetPerAccountQueryForTest(func(_ context.Context, _ mysqlclient.Creds, query string, _ ...any) ([]string, error) {
				switch {
				case strings.Contains(query, "SELECT option_value"):
					return []string{`<script src="http://192.0.2.1/payload.js"></script>`}, nil
				case strings.Contains(query, "SELECT meta_value FROM wp_usermeta"):
					return []string{`a:1:{s:2:"ip";s:10:"192.0.2.10";}`}, nil
				}
				return nil, nil
			})
			t.Cleanup(func() { mysqlclient.SetPerAccountQueryForTest(nil) })
			cfg := pendingTestConfig(t)
			cfg.AutoResponse.CleanDatabase = true
			b := &findingIDBlocker{outcomeStubBlocker: outcomeStubBlocker{err: errors.New("engine unavailable")}}
			applyBlockTestSetup(t, b)
			f := alert.Finding{Check: check, Severity: alert.High, Timestamp: time.Unix(123, 0), Message: "database compromise", Details: "Database: site\nOption: injected_option"}
			AutoRespondDBMalware(cfg, []alert.Finding{f})
			want := alert.FindingID(f)
			if len(b.ids) != 1 || b.ids[0] != want {
				t.Fatalf("database response IDs = %q, want original finding %s", b.ids, want)
			}
			b.err = nil
			b.outcome = firewall.BlockOutcomeLive
			// Discovery's fake filesystem hides all non-config reads. Retry
			// against the real state file written by the failed block attempt.
			osFS = persistentFS
			AutoBlockIPs(cfg, nil)
			if len(b.ids) != 2 || b.ids[1] != want {
				t.Fatalf("database retry lost original finding: %q", b.ids)
			}
		})
	}
}

func (b *findingIDBlocker) BlockIPOutcomeWithFindingID(ip, reason string, ttl time.Duration, id string) (firewall.BlockOutcome, error) {
	b.ids = append(b.ids, id)
	outcome, err := b.BlockIPOutcome(ip, reason, ttl)
	if err == nil && outcome == firewall.BlockOutcomeLive && b.live != nil {
		b.live[ip] = true
	}
	return outcome, err
}

func (b *findingIDBlocker) BlockSubnet(string, string, time.Duration) error {
	b.subnetIDs = append(b.subnetIDs, "")
	return nil
}
func (b *findingIDBlocker) BlockSubnetWithFindingID(_, _ string, _ time.Duration, id string) error {
	b.subnetIDs = append(b.subnetIDs, id)
	return nil
}
func (b *findingIDBlocker) PromoteToPermanentBlockWithFindingID(_, _ string, id string) error {
	b.permanentIDs = append(b.permanentIDs, id)
	return nil
}

func TestAutoBlockRetainsOriginalFindingIDAcrossRetry(t *testing.T) {
	cfg := pendingTestConfig(t)
	b := &findingIDBlocker{outcomeStubBlocker: outcomeStubBlocker{err: errors.New("engine unavailable")}}
	applyBlockTestSetup(t, b)
	f := alert.Finding{Check: "wp_login_bruteforce", Severity: alert.High, SourceIP: "192.0.2.10", Timestamp: time.Unix(123, 0), Message: "192.0.2.10 " + strings.Repeat("evidence ", 30)}
	want := alert.NewAuditEvent("host.example.com", f).FindingID
	AutoBlockIPs(cfg, []alert.Finding{f})
	if len(b.ids) != 1 || b.ids[0] != want {
		t.Fatalf("initial attempt IDs = %q, want %s", b.ids, want)
	}
	if len(loadBlockState(cfg.StatePath).Pending) != 1 {
		t.Fatal("failed attempt was not persisted for retry")
	}
	b.err = nil
	b.outcome = firewall.BlockOutcomeLive
	AutoBlockIPs(cfg, nil)
	if len(b.ids) != 2 || b.ids[1] != want {
		t.Fatalf("retry lost original finding ID: %v", b.ids)
	}
}

func TestAutoSubnetBlocksRetainFindingID(t *testing.T) {
	for _, check := range []string{"smtp_subnet_spray", "mail_subnet_spray", "http_asn_crawl"} {
		t.Run(check, func(t *testing.T) {
			cfg := pendingTestConfig(t)
			b := &findingIDBlocker{}
			applyBlockTestSetup(t, b)
			f := alert.Finding{Check: check, Severity: alert.Critical, Timestamp: time.Unix(123, 0), Message: "Subnet evidence from 192.0.2.0/24: activity", CIDRs: []string{"192.0.2.0/24"}}
			AutoBlockIPs(cfg, []alert.Finding{f})
			want := alert.NewAuditEvent("host.example.com", f).FindingID
			if len(b.subnetIDs) != 1 || b.subnetIDs[0] != want {
				t.Fatalf("subnet action IDs = %q, want %s", b.subnetIDs, want)
			}
		})
	}
}

func TestPermanentPromotionRetainsLatestFindingID(t *testing.T) {
	cfg := pendingTestConfig(t)
	cfg.AutoResponse.PermBlock = true
	cfg.AutoResponse.PermBlockCount = config.MinBlockEscalationCount
	b := &findingIDBlocker{outcomeStubBlocker: outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}}
	applyBlockTestSetup(t, b)
	f := alert.Finding{Check: "wp_login_bruteforce", Severity: alert.High, SourceIP: "192.0.2.10", Message: "repeated login abuse"}
	for i := range config.MinBlockEscalationCount {
		f.Timestamp = time.Unix(int64(123+i), 0)
		AutoBlockIPs(cfg, []alert.Finding{f})
	}
	if len(b.permanentIDs) != 1 || b.permanentIDs[0] != alert.FindingID(f) {
		t.Fatalf("promotion IDs = %q, want final source finding", b.permanentIDs)
	}
}

func (b *findingIDBlocker) IsBlocked(ip string) bool { return b.live[ip] }

func TestNetblockRetainsLatestContributingFindingID(t *testing.T) {
	cfg := pendingTestConfig(t)
	cfg.AutoResponse.NetBlock = true
	cfg.AutoResponse.NetBlockThreshold = config.MinBlockEscalationCount
	b := &findingIDBlocker{outcomeStubBlocker: outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}, live: make(map[string]bool)}
	applyBlockTestSetup(t, b)
	seed := &blockState{}
	for i := 1; i < config.MinBlockEscalationCount; i++ {
		ip := fmt.Sprintf("192.0.2.%d", i)
		seed.IPs = append(seed.IPs, blockedIP{IP: ip, BlockedAt: time.Unix(1, 0)})
		b.live[ip] = true
	}
	saveBlockState(cfg.StatePath, seed)
	f := alert.Finding{Check: "wp_login_bruteforce", Severity: alert.High, SourceIP: "192.0.2.100", Timestamp: time.Unix(123, 0), Message: "new contributing observation"}
	AutoBlockIPs(cfg, []alert.Finding{f})
	want := alert.FindingID(f)
	if len(b.subnetIDs) != 1 || b.subnetIDs[0] != want {
		t.Fatalf("netblock IDs = %q, want latest contributing finding %s", b.subnetIDs, want)
	}
	// A later reconciliation with only persisted evidence retains the same link.
	AutoBlockIPs(cfg, nil)
	if len(b.subnetIDs) != 2 || b.subnetIDs[1] != want {
		t.Fatalf("persisted netblock evidence lost its cause: %q", b.subnetIDs)
	}
}
