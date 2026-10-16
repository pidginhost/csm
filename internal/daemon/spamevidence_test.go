package daemon

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/antispam/reconcile"
	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/ipmap"
)

const evidencePrefix = "2026-10-13 09:00:00 1xF5ol-00000000SdK-2TMA "

func spamLine(ip string) string {
	return evidencePrefix + `CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=200 action="reject" decision=reject ip=` + ip
}

func TestRecorderSkipsExcludedSenders(t *testing.T) {
	as := config.AntispamConfig{Enabled: true, RejectScore: 15, TagScore: 6}
	none := func(netip.Addr) int { return 0 }
	never := func(a netip.Addr) bool { return a == netip.MustParseAddr("203.0.113.70") }
	if ip, v := spamEvidence(spamLine("198.51.100.70"), as, never, none); v != ipmap.SpamVerdict || ip != "198.51.100.70" {
		t.Fatalf("public sender = %q, %v", ip, v)
	}
	for _, ip := range []string{"203.0.113.70", "10.1.2.3", "127.0.0.1", "192.0.2.255", ""} {
		if _, v := spamEvidence(spamLine(ip), as, never, none); v != ipmap.NoVerdict {
			t.Errorf("%q recorded", ip)
		}
	}
	as.Enabled = false
	if _, v := spamEvidence(spamLine("198.51.100.70"), as, never, none); v != ipmap.NoVerdict {
		t.Fatal("recorded with antispam disabled")
	}
}

// The map's own weight is subtracted before judging, so CSM's listing
// cannot turn a borderline message into new spam evidence (spec 7.2).
func TestRecorderSubtractsTheMapWeight(t *testing.T) {
	as := config.AntispamConfig{Enabled: true, RejectScore: 15, TagScore: 6}
	line := strings.Replace(spamLine("198.51.100.71"), "score=200", "score=170", 1)
	never := func(netip.Addr) bool { return false }
	if _, v := spamEvidence(line, as, never, func(netip.Addr) int { return ipmap.Drop.Tenths() }); v != ipmap.NoVerdict {
		t.Fatalf("170 - 40 recorded as %v", v)
	}
	if _, v := spamEvidence(line, as, never, func(netip.Addr) int { return 0 }); v != ipmap.SpamVerdict {
		t.Fatalf("170 without a listing = %v", v)
	}
}

func TestAntispamWiresTheIPMap(t *testing.T) {
	d := newTestDaemon(t)
	r := d.withIPMap(reconcile.Reconciler{})
	if r.IPMap.Write == nil || r.IPMap.Remove == nil || r.Feeds == nil || d.antispamFeeds != r.Feeds || d.ipmapWriter.Load() == nil {
		t.Fatalf("IP map hooks: %+v, feeds %p/%p, writer %v", r.IPMap, r.Feeds, d.antispamFeeds, d.ipmapWriter.Load())
	}
}

// A map CSM cannot write raises antispam_ip_map; the next good write
// clears it (spec 6.2, 8.5).
func TestRefreshIPMapReportsAWriteFailure(t *testing.T) {
	d := newTestDaemon(t)
	prevPath, prevGroup := antispamIPMapPath, antispamRspamdGroup
	t.Cleanup(func() { antispamIPMapPath, antispamRspamdGroup = prevPath, prevGroup })
	antispamIPMapPath = filepath.Join(t.TempDir(), "csm_ip.map")
	gid := -1
	antispamRspamdGroup = func(context.Context) int { return gid }
	d.withIPMap(reconcile.Reconciler{})
	cfg := &config.Config{StatePath: d.cfg.StatePath}
	cfg.EmailProtection.Antispam = config.AntispamConfig{Enabled: true, RspamdSocket: testScanSocket, RejectScore: 15, TagScore: 6,
		Feeds: config.AntispamFeedsConfig{Enabled: []string{antispam.FeedCSMIPMap}}}
	useActiveConfig(t, cfg)

	d.refreshIPMap(context.Background(), time.Now())
	if got := latestChecks(d)[reconcile.CheckIPMap]; got != 1 {
		t.Fatalf("write failure findings = %d, want 1", got)
	}
	gid = os.Getgid()
	if wrote := d.refreshIPMap(context.Background(), time.Now()); !wrote {
		t.Fatal("the map was not written once rspamd's group was known")
	}
	if got := latestChecks(d)[reconcile.CheckIPMap]; got != 0 {
		t.Fatalf("findings after a good write = %d, want 0", got)
	}
	if info, err := os.Stat(antispamIPMapPath); err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("map file %v, %v", info, err)
	}
}

func useTestAttackDB(t *testing.T) *attackdb.DB {
	t.Helper()
	prev := attackdb.Global()
	adb := attackdb.NewForTest(nil)
	attackdb.SetGlobal(adb)
	t.Cleanup(func() { attackdb.SetGlobal(prev) })
	return adb
}

func TestEximLogRecordsSpamEvidence(t *testing.T) {
	d := newTestDaemon(t)
	adb := useTestAttackDB(t)
	cfg := &config.Config{}
	cfg.EmailProtection.Antispam = config.AntispamConfig{Enabled: true, RejectScore: 15, TagScore: 6}
	d.handleEximLine(spamLine("198.51.100.72"), alert.Observation{}, cfg)
	if rec := adb.LookupIP("198.51.100.72"); rec == nil || rec.Mail == nil || rec.Mail.Spam != 1 {
		t.Fatalf("record after a spam scan: %+v", rec)
	}
}
