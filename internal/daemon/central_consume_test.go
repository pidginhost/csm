package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/challenge"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/reporting"
)

func TestCentralFirebreakProtects(t *testing.T) {
	cfg := &config.Config{}
	cfg.InfraIPs = []string{"10.10.10.0/24"}
	cfg.Firewall = &firewall.FirewallConfig{InfraIPs: []string{"45.76.1.0/24"}}
	d := New(cfg, nil, nil, "")
	fb := d.centralFirebreak()

	for _, ip := range []string{"127.0.0.1", "10.10.10.5", "45.76.1.7", "192.0.2.7", "198.51.100.10", "203.0.113.9", "198.18.0.1", "198.19.255.254", "2001:db8::1", "::1", "fe80::1", "not-an-ip"} {
		if !fb(ip) {
			t.Errorf("firebreak(%q) = false, want protected", ip)
		}
	}
	for _, ip := range []string{"46.76.1.1", "8.8.8.8"} {
		if fb(ip) {
			t.Errorf("firebreak(%q) = true, want actionable", ip)
		}
	}
}

func TestStartCentralConsumeWarnsOnlyForUnknownAction(t *testing.T) {
	prevHook := alert.CentralHook
	prevWriter := log.Writer()
	prevFlags := log.Flags()
	t.Cleanup(func() {
		alert.SetCentralHook(prevHook)
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
	})

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	t.Setenv("CSM_TEST_CENTRAL_PUB", hex.EncodeToString(pub))

	tests := []struct {
		action string
		warn   bool
	}{
		{action: ""},
		{action: string(reporting.ActionOff)},
		{action: string(reporting.ActionChallenge)},
		{action: string(reporting.ActionBlockIfLocalCorroborated)},
		{action: "unknown", warn: true},
	}
	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			var buf bytes.Buffer
			log.SetOutput(&buf)
			log.SetFlags(0)
			alert.SetCentralHook(nil)

			cfg := &config.Config{}
			cfg.Reputation.Central.Enabled = true
			cfg.Reputation.Central.SetURL = "https://central.example/decisions"
			cfg.Reputation.Central.PubkeyEnv = "CSM_TEST_CENTRAL_PUB"
			cfg.Reputation.Central.Action = tt.action
			d := New(cfg, nil, nil, "")
			if loop := d.startCentralConsume(); loop == nil {
				t.Fatal("enabled consumer returned nil loop")
			}

			gotWarn := strings.Contains(buf.String(), "unrecognized action")
			if gotWarn != tt.warn {
				t.Fatalf("unrecognized-action warning = %v, want %v; log=%q", gotWarn, tt.warn, buf.String())
			}
		})
	}
}

func TestStartCentralConsumeDisabledClearsHook(t *testing.T) {
	prev := alert.CentralHook
	alert.SetCentralHook(func(alert.Finding) {})
	t.Cleanup(func() { alert.SetCentralHook(prev) })

	d := New(&config.Config{}, nil, nil, "")
	if loop := d.startCentralConsume(); loop != nil {
		t.Fatal("disabled consumer returned a loop")
	}
	if alert.CentralHook != nil {
		t.Fatal("disabled consumer left a stale hook")
	}
}

func TestStartCentralConsumeMisconfiguredReturnsNil(t *testing.T) {
	cfg := &config.Config{}
	cfg.Reputation.Central.Enabled = true // but no set_url
	d := New(cfg, nil, nil, "")
	if loop := d.startCentralConsume(); loop != nil {
		t.Fatal("misconfigured consumer returned a loop")
	}
}

// The default must sit within reach of the central's corroborated scores, or
// a locally corroborated block would never fire without operator tuning.
func TestCentralDefaultBlockThresholdIsReachable(t *testing.T) {
	if centralBlockThreshold != 60 {
		t.Fatalf("default central block threshold = %d, want 60", centralBlockThreshold)
	}
}

func TestStartCentralConsumeDefaultsThresholdAndClearsHook(t *testing.T) {
	prev := alert.CentralHook
	t.Cleanup(func() { alert.SetCentralHook(prev) })

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	snap := reporting.ScoredSnapshot{Version: 1, Entries: []reporting.ScoredEntry{
		{IP: "45.76.1.1", Score: centralBlockThreshold - 1, Classes: []reporting.Class{reporting.ClassBruteforce}, LastSeen: time.Unix(1_700_000_000, 0).UTC()},
	}}
	payload, ok := reporting.MarshalScoredSnapshot(snap)
	if !ok {
		t.Fatal("marshal snapshot")
	}
	pulled := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sig := ed25519.Sign(priv, payload)
		w.Header().Set("X-CSM-Signature", "ed25519="+hex.EncodeToString(sig))
		w.Header().Set("X-CSM-Kind", "snapshot")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
		select {
		case pulled <- struct{}{}:
		default:
		}
	}))
	t.Cleanup(srv.Close)

	cfg := &config.Config{}
	cfg.Reputation.Central.Enabled = true
	cfg.Reputation.Central.SetURL = srv.URL + "/decisions"
	cfg.Reputation.Central.PubkeyEnv = "CSM_TEST_CENTRAL_PUB"
	cfg.Reputation.Central.Action = string(reporting.ActionBlockIfLocalCorroborated)
	t.Setenv("CSM_TEST_CENTRAL_PUB", hex.EncodeToString(pub))

	d := New(cfg, nil, nil, "")
	d.ipList = challenge.NewIPList(filepath.Join(t.TempDir(), "iplist", "challenge_ips.txt"))
	loop := d.startCentralConsume()
	if loop == nil {
		t.Fatal("enabled consumer returned nil loop")
	}
	if alert.CentralHook == nil {
		t.Fatal("enabled consumer did not install hook")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		loop()
	}()
	t.Cleanup(func() {
		select {
		case <-d.stopCh:
		default:
			close(d.stopCh)
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("central loop did not stop")
		}
	})

	select {
	case <-pulled:
	case <-time.After(time.Second):
		t.Fatal("central consumer did not pull initial set")
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		alert.CentralHook(alert.Finding{Check: "pam_bruteforce", SourceIP: "45.76.1.1"})
		if d.ipList.Contains("45.76.1.1") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !d.ipList.Contains("45.76.1.1") {
		t.Fatal("score below default block threshold should challenge, not block")
	}

	close(d.stopCh)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("central loop did not stop")
	}
	if alert.CentralHook != nil {
		t.Fatal("central loop did not clear hook on stop")
	}
}

// centralStoreWith builds a CentralStore populated from a signed snapshot served
// by a throwaway server, returning the store and the firebreak.
func centralStoreWith(t *testing.T, entries []reporting.ScoredEntry) *reporting.CentralStore {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	snap := reporting.ScoredSnapshot{Version: 1, Entries: entries}
	payload, ok := reporting.MarshalScoredSnapshot(snap)
	if !ok {
		t.Fatal("marshal snapshot")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sig := ed25519.Sign(priv, payload)
		w.Header().Set("X-CSM-Signature", "ed25519="+hex.EncodeToString(sig))
		w.Header().Set("X-CSM-Kind", "snapshot")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}))
	t.Cleanup(srv.Close)
	store := reporting.NewCentralStore(reporting.NewPuller(srv.Client(), srv.URL+"/decisions", hex.EncodeToString(pub)))
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	return store
}

func TestApplyCentralChallengesListedIP(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	d.ipList = challenge.NewIPList(filepath.Join(t.TempDir(), "iplist", "challenge_ips.txt"))

	store := centralStoreWith(t, []reporting.ScoredEntry{
		{IP: "45.76.1.1", Score: 90, Classes: []reporting.Class{reporting.ClassBruteforce}, LastSeen: time.Unix(1_700_000_000, 0).UTC()},
	})
	fb := d.centralFirebreak()
	d.applyCentral(store, reporting.ActionChallenge, 80, fb, alert.Finding{Check: "pam_bruteforce", SourceIP: "45.76.1.1"})

	if !d.ipList.Contains("45.76.1.1") {
		t.Fatal("listed IP was not challenged")
	}
}

func TestApplyCentralRespectsFirebreak(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	d.ipList = challenge.NewIPList(filepath.Join(t.TempDir(), "iplist", "challenge_ips.txt"))

	// 203.0.113.5 is in the set but is a documentation range -> firebreak.
	store := centralStoreWith(t, []reporting.ScoredEntry{
		{IP: "203.0.113.5", Score: 99, Classes: []reporting.Class{reporting.ClassBruteforce}, LastSeen: time.Unix(1_700_000_000, 0).UTC()},
	})
	fb := d.centralFirebreak()
	d.applyCentral(store, reporting.ActionChallenge, 80, fb, alert.Finding{Check: "pam_bruteforce", SourceIP: "203.0.113.5"})

	if d.ipList.Contains("203.0.113.5") {
		t.Fatal("firebreak-protected IP was challenged")
	}
}

// Non-public sources are never reported or acted on. The central service
// refuses them, so reporting one would only be dropped and counted as a loss,
// and an attacker can choose such source addresses.
func TestCentralFirebreakExcludesNonPublicRanges(t *testing.T) {
	fb := New(&config.Config{}, nil, nil, "").centralFirebreak()
	for _, group := range [][]*net.IPNet{nonPublicNets, documentationNets} {
		for _, prefix := range group {
			// The last address of the IETF assignment range is outside the
			// Teredo exception. It also exercises each excluded upper bound.
			ip := append(net.IP(nil), prefix.IP...)
			for i := range ip {
				ip[i] |= ^prefix.Mask[i]
			}
			if !fb(ip.String()) {
				t.Errorf("firebreak does not protect %s", prefix)
			}
		}
	}
	for _, ip := range []net.IP{net.IPv4zero, net.IPv4bcast, net.IPv6linklocalallnodes, net.IPv6loopback} {
		if !fb(ip.String()) {
			t.Errorf("firebreak does not protect non-public source %s", ip)
		}
	}
	ipv4 := net.ParseIP("192.0.2.1").To4()
	nat64 := append(net.IP(nil), nat64Net.IP...)
	copy(nat64[12:], ipv4)
	sixToFour := append(net.IP(nil), sixToFourNet.IP...)
	copy(sixToFour[2:6], ipv4)
	sources := []string{ipv4.String(), "::ffff:" + ipv4.String(), nat64.String(), sixToFour.String()}
	for _, ip := range sources {
		if !fb(ip) {
			t.Errorf("embedded documentation address was not protected: %s", ip)
		}
	}

	// Use documentation IPv4 as the public fixture without publishing real
	// routable hosts. Teredo remains outside the IETF assignment exclusion.
	saved := documentationNets
	documentationNets = nil
	t.Cleanup(func() { documentationNets = saved })
	teredo := append(net.IP(nil), teredoNet.IP...)
	teredo[len(teredo)-1] = 1
	for _, ip := range append(sources, teredo.String()) {
		if fb(ip) {
			t.Errorf("firebreak protects actionable fixture %s", ip)
		}
	}
}

func TestApplyCentralIgnoresUnlistedIP(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	d.ipList = challenge.NewIPList(filepath.Join(t.TempDir(), "iplist", "challenge_ips.txt"))
	store := centralStoreWith(t, []reporting.ScoredEntry{
		{IP: "45.76.1.1", Score: 90, Classes: []reporting.Class{reporting.ClassBruteforce}, LastSeen: time.Unix(1_700_000_000, 0).UTC()},
	})
	fb := d.centralFirebreak()
	d.applyCentral(store, reporting.ActionChallenge, 80, fb, alert.Finding{Check: "pam_bruteforce", SourceIP: "8.8.8.8"})
	if d.ipList.Contains("8.8.8.8") {
		t.Fatal("unlisted IP was challenged")
	}
}

func TestPlanCentralActionIgnoresResponseAndHealthFindings(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")

	for _, finding := range []alert.Finding{
		{Check: "auto_block", Message: "AUTO-BLOCK: 45.76.1.1 blocked (expires in 24h0m0s)"},
		{Check: "auto_block", Message: "AUTO-BLOCK [dry-run]: 45.76.1.1 would be blocked (expires in 24h0m0s)"},
		{Check: "reputation_quota_exhausted", Message: "AbuseIPDB quota exhausted"},
		{Check: "threat_feed_stale", Message: "Threat intelligence feeds stale"},
	} {
		finding.SourceIP = "45.76.1.1"
		if action, ok := d.planCentralAction(nil, reporting.ActionBlockIfLocalCorroborated, 80, nil, finding); ok {
			t.Fatalf("%s finding planned central action %+v", finding.Check, action)
		}
	}
}

// Central intel acts on a listed address only when the local finding names
// it as an attacker. An outbound check's SourceIP is the remote end of a
// local connection, and a customer login or an advisory is not attacker
// evidence either.
func TestPlanCentralActionRequiresAddressEvidence(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	store := centralStoreWith(t, []reporting.ScoredEntry{
		{IP: "198.51.100.20", Score: 95, Classes: []reporting.Class{reporting.ClassBruteforce}, LastSeen: time.Unix(1_700_000_000, 0).UTC()},
	})
	notProtected := func(string) bool { return false }
	for _, c := range []struct {
		check string
		sev   alert.Severity
		want  bool
	}{
		{"bad_asn_outbound", alert.High, false},
		{"backdoor_port_outbound", alert.Critical, false},
		{"cpanel_login_realtime", alert.Critical, false},
		{"modsec_warning_realtime", alert.High, false},
		{"mail_account_compromised", alert.High, false},
		{"xmlrpc_abuse", alert.High, true},
		{"mail_account_compromised", alert.Critical, true},
	} {
		f := alert.Finding{Check: c.check, Severity: c.sev, SourceIP: "198.51.100.20"}
		action, ok := d.planCentralAction(store, reporting.ActionBlockIfLocalCorroborated, 80, notProtected, f)
		if ok != c.want {
			t.Errorf("%s %s: planned %v (%+v), want %v", c.check, c.sev, ok, action, c.want)
		}
		if ok && (action.decision != reporting.DecisionBlock || action.ip != "198.51.100.20") {
			t.Errorf("%s %s: action = %+v, want a block of the listed address", c.check, c.sev, action)
		}
	}
}

func TestLogCentralBlockFailureSuppressesProtectedIPError(t *testing.T) {
	prevWriter := log.Writer()
	prevFlags := log.Flags()
	t.Cleanup(func() {
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
	})

	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetFlags(0)

	logCentralBlockFailure("45.76.1.92", firewall.ErrIPProtected)
	if buf.Len() != 0 {
		t.Fatalf("protected-IP central refusal logged as block failure: %q", buf.String())
	}

	logCentralBlockFailure("45.76.1.92", errors.New("nft failed"))
	if !strings.Contains(buf.String(), "central-intel: block 45.76.1.92 failed: nft failed") {
		t.Fatalf("non-protected central failure was not logged: %q", buf.String())
	}
}

func TestStartCentralConsumeSignerMustSign(t *testing.T) {
	prevHook, prevWriter, prevFlags := alert.CentralHook, log.Writer(), log.Flags()
	t.Cleanup(func() {
		alert.SetCentralHook(prevHook)
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
	})
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	t.Setenv("CSM_TEST_CENTRAL_PUB", hex.EncodeToString(pub))
	_, nodePriv, _ := ed25519.GenerateKey(rand.Reader)
	t.Setenv("CSM_TEST_NODE_KEY", hex.EncodeToString(nodePriv))
	t.Setenv("CSM_TEST_BAD_KEY", "abcd")
	t.Setenv("CSM_TEST_UNSET_KEY", "")
	t.Setenv("CSM_TEST_NON_HEX_KEY", strings.Repeat("z", ed25519.PrivateKeySize*2))
	t.Setenv("CSM_TEST_SEED_KEY", hex.EncodeToString(nodePriv.Seed()))
	inconsistentKey := append(ed25519.PrivateKey(nil), nodePriv...)
	inconsistentKey[ed25519.SeedSize] ^= 1
	t.Setenv("CSM_TEST_INCONSISTENT_KEY", hex.EncodeToString(inconsistentKey))

	target := func(name, transport, keyEnv string) reportTargetConfig {
		return reportTargetConfig{Name: name, URL: "https://central.example/report", Transport: transport,
			NodeID: "n_000000000000000000000001", KeyID: "k_000000000000000000000002", KeyEnv: keyEnv}
	}
	for _, c := range []struct {
		name    string
		targets []reportTargetConfig
		on      bool
	}{
		{"usable key", []reportTargetConfig{target("central", "ed25519", "CSM_TEST_NODE_KEY")}, true},
		{"no such target", []reportTargetConfig{target("other", "ed25519", "CSM_TEST_NODE_KEY")}, false},
		{"two targets", []reportTargetConfig{target("central", "ed25519", "CSM_TEST_NODE_KEY"), target("central", "ed25519", "CSM_TEST_NODE_KEY")}, false},
		{"hmac target", []reportTargetConfig{target("central", "hmac", "CSM_TEST_NODE_KEY")}, false},
		{"key unset", []reportTargetConfig{target("central", "ed25519", "CSM_TEST_UNSET_KEY")}, false},
		{"key malformed", []reportTargetConfig{target("central", "ed25519", "CSM_TEST_BAD_KEY")}, false},
		{"key not hex", []reportTargetConfig{target("central", "ed25519", "CSM_TEST_NON_HEX_KEY")}, false},
		{"seed without public key", []reportTargetConfig{target("central", "ed25519", "CSM_TEST_SEED_KEY")}, false},
		{"inconsistent public key", []reportTargetConfig{target("central", "ed25519", "CSM_TEST_INCONSISTENT_KEY")}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			log.SetOutput(&buf)
			log.SetFlags(0)
			alert.SetCentralHook(nil)
			cfg := &config.Config{}
			cfg.Reputation.Central.Enabled = true
			cfg.Reputation.Central.SetURL = "https://central.example/decisions"
			cfg.Reputation.Central.PubkeyEnv = "CSM_TEST_CENTRAL_PUB"
			cfg.Reputation.Central.AuthTarget = "central"
			cfg.Reputation.Report.Targets = c.targets
			loop := New(cfg, nil, nil, "").startCentralConsume()
			if strings.Contains(buf.String(), hex.EncodeToString(nodePriv)) || strings.Contains(buf.String(), hex.EncodeToString(inconsistentKey)) {
				t.Fatal("log printed the node key")
			}
			if (loop != nil) != c.on || (alert.CentralHook != nil) != c.on {
				t.Fatalf("consumer on=%v hook=%v, want %v; log=%q", loop != nil, alert.CentralHook != nil, c.on, buf.String())
			}
			if mentions := strings.Contains(buf.String(), "reputation.central.auth_target"); mentions == c.on {
				t.Fatalf("log = %q; the auth_target line must appear only when the consumer stays off", buf.String())
			}
			if !c.on && strings.Count(buf.String(), "\n") != 1 {
				t.Fatalf("rejected signer must emit exactly one log line, got %q", buf.String())
			}
		})
	}
}

func TestLogCentralRefreshError(t *testing.T) {
	prevWriter, prevFlags := log.Writer(), log.Flags()
	t.Cleanup(func() {
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
	})
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetFlags(0)
	logCentralRefreshError("refresh failed", fmt.Errorf("pull: %w", reporting.ErrPullUnauthorized))
	logCentralRefreshError("refresh failed", errors.New("boom"))
	want := "central-intel: pull unauthorized; check node enrollment, node clock and reputation.central.auth_target\n" +
		"central-intel: refresh failed: boom\n"
	if buf.String() != want {
		t.Fatalf("log = %q, want %q", buf.String(), want)
	}
}

func TestStartCentralConsumeSignsWithReportingDisabled(t *testing.T) {
	prevHook := alert.CentralHook
	t.Cleanup(func() { alert.SetCentralHook(prevHook) })
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, nodeKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CSM_TEST_CENTRAL_PUB", hex.EncodeToString(pub))
	t.Setenv("CSM_TEST_NODE_KEY", hex.EncodeToString(nodeKey))

	requests := make(chan *http.Request, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Clone(context.Background())
		w.WriteHeader(http.StatusNotModified)
	}))
	t.Cleanup(srv.Close)
	cfg := &config.Config{}
	cfg.Reputation.Report.Enabled = false
	cfg.Reputation.Report.Targets = []reportTargetConfig{
		{Name: "other", URL: srv.URL + "/report", Transport: "hmac"},
		{Name: "central", URL: srv.URL + "/report", Transport: "ed25519",
			NodeID: "n_000000000000000000000001", KeyID: "k_000000000000000000000002", KeyEnv: "CSM_TEST_NODE_KEY"},
	}
	cfg.Reputation.Central.Enabled = true
	cfg.Reputation.Central.SetURL = srv.URL + "/decisions"
	cfg.Reputation.Central.PubkeyEnv = "CSM_TEST_CENTRAL_PUB"
	cfg.Reputation.Central.AuthTarget = "central"
	d := New(cfg, nil, nil, "")
	loop := d.startCentralConsume()
	if loop == nil {
		t.Fatal("signed consumption must not require reporting to be enabled")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		loop()
	}()
	t.Cleanup(func() {
		close(d.stopCh)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("central consumer did not stop")
		}
	})

	var req *http.Request
	select {
	case req = <-requests:
	case <-time.After(5 * time.Second):
		t.Fatal("central consumer did not pull")
	}
	target := cfg.Reputation.Report.Targets[1]
	if req.Method != http.MethodGet || req.URL.Path != "/decisions" || req.URL.RawQuery != "" || req.ContentLength != 0 {
		t.Fatal("initial pull must be a bodiless GET of the full scored set")
	}
	if req.Header.Get("X-CSM-Node") != target.NodeID || req.Header.Get("X-CSM-Key") != target.KeyID {
		t.Fatal("pull did not use the selected target's identity")
	}
	if req.Header.Get("Authorization") != "" {
		t.Fatal("pull must not carry bearer authorization")
	}
	ts, err := strconv.ParseInt(req.Header.Get("X-CSM-Timestamp"), 10, 64)
	if err != nil {
		t.Fatal("pull has no valid timestamp")
	}
	nonce := req.Header.Get("X-CSM-Nonce")
	if raw, decodeErr := hex.DecodeString(nonce); decodeErr != nil || len(raw) != 16 {
		t.Fatal("pull has no valid nonce")
	}
	expected, err := reporting.SignEd25519(reporting.Envelope{
		NodeID: target.NodeID, KeyID: target.KeyID, Method: http.MethodGet,
		Path: "/decisions", BodyHash: reporting.HashBody(nil), Timestamp: ts, Nonce: nonce,
	}, nodeKey)
	if err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("X-CSM-Signature") != "ed25519="+hex.EncodeToString(expected) {
		t.Fatal("pull was not signed with the selected target's node key")
	}
}

func TestCentralRefreshLogsVersion(t *testing.T) {
	prevWriter, prevFlags := log.Writer(), log.Flags()
	t.Cleanup(func() {
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
	})
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetFlags(0)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	snap := reporting.ScoredSnapshot{Version: 7, Entries: []reporting.ScoredEntry{{
		IP: "203.0.113.5", Score: 80, Classes: []reporting.Class{reporting.ClassBruteforce},
		LastSeen: time.Unix(1_700_000_000, 0).UTC(),
	}}}
	payload, ok := reporting.MarshalScoredSnapshot(snap)
	if !ok {
		t.Fatal("marshal snapshot")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-CSM-Signature", "ed25519="+hex.EncodeToString(ed25519.Sign(priv, payload)))
		w.Header().Set("X-CSM-Kind", "snapshot")
		_, _ = w.Write(payload)
	}))
	defer srv.Close()
	store := reporting.NewCentralStore(reporting.NewPuller(srv.Client(), srv.URL+"/decisions", hex.EncodeToString(pub)))
	if err := centralRefresh(store)(context.Background()); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "central-intel: refresh complete (version=7)\n" {
		t.Fatalf("log = %q", buf.String())
	}
}
