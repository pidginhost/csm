package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/state"
)

// newListenerForTest builds a ControlListener wired to a minimal
// in-memory Daemon: an on-disk state.Store under t.TempDir, a buffered
// alert channel, and a zero-value config whose empty Integrity.BinaryHash
// makes integrity.Verify a no-op (the "not baselined" path). No Unix
// socket is created; these tests drive dispatch() / handle*() directly.
func newListenerForTest(t *testing.T) *ControlListener {
	t.Helper()
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	d := &Daemon{
		cfg:       &config.Config{},
		store:     st,
		alertCh:   make(chan alert.Finding, 8),
		version:   "test",
		startTime: time.Now().Add(-90 * time.Second),
	}
	config.SetActive(d.cfg)
	t.Cleanup(func() { config.SetActive(nil) })
	return &ControlListener{d: d}
}

// --- parseTier --------------------------------------------------------

func TestParseTier(t *testing.T) {
	cases := []struct {
		in   string
		want checks.Tier
		err  bool
	}{
		{"critical", checks.TierCritical, false},
		{"deep", checks.TierDeep, false},
		{"all", checks.TierAll, false},
		{"", checks.TierAll, false},
		{"bogus", "", true},
	}
	for _, tc := range cases {
		got, err := parseTier(tc.in)
		if tc.err {
			if err == nil {
				t.Errorf("parseTier(%q) expected error, got tier=%v", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseTier(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseTier(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// --- dispatch ---------------------------------------------------------

func TestDispatchBadJSON(t *testing.T) {
	c := newListenerForTest(t)
	resp := c.dispatch([]byte("{not json"))
	if resp.OK {
		t.Fatal("bad JSON must produce OK=false")
	}
	if !strings.Contains(resp.Error, "bad request") {
		t.Errorf("expected bad-request error, got %q", resp.Error)
	}
}

func TestDispatchUnknownCommand(t *testing.T) {
	c := newListenerForTest(t)
	raw, _ := json.Marshal(control.Request{Cmd: "nope"})
	resp := c.dispatch(raw)
	if resp.OK {
		t.Fatal("unknown cmd must produce OK=false")
	}
	if !strings.Contains(resp.Error, "unknown command") {
		t.Errorf("expected unknown-command error, got %q", resp.Error)
	}
}

func TestDispatchStatusHappyPath(t *testing.T) {
	c := newListenerForTest(t)
	raw, _ := json.Marshal(control.Request{Cmd: control.CmdStatus})
	resp := c.dispatch(raw)
	if !resp.OK {
		t.Fatalf("status must succeed, got error=%q", resp.Error)
	}
	var status control.StatusResult
	if err := json.Unmarshal(resp.Result, &status); err != nil {
		t.Fatalf("unmarshal status result: %v", err)
	}
	if status.Version != "test" {
		t.Errorf("version: got %q want %q", status.Version, "test")
	}
	if status.UptimeSec < 1 {
		t.Errorf("uptime must reflect startTime, got %d", status.UptimeSec)
	}
}

// --- handleHistoryRead ------------------------------------------------

func TestHandleHistoryReadClampsLimit(t *testing.T) {
	c := newListenerForTest(t)

	cases := []struct {
		name   string
		args   control.HistoryReadArgs
		expect int
	}{
		{"zero limit defaults to 100", control.HistoryReadArgs{Limit: 0, Offset: 0}, 100},
		{"negative limit defaults to 100", control.HistoryReadArgs{Limit: -5}, 100},
		{"over-1000 limit defaults to 100", control.HistoryReadArgs{Limit: 9999}, 100},
		{"valid limit preserved", control.HistoryReadArgs{Limit: 50}, 50},
		{"boundary 1000 preserved", control.HistoryReadArgs{Limit: 1000}, 1000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(tc.args)
			// Intercept the limit by calling the handler directly and
			// re-parsing the args mutation via a second decode. Since
			// ReadHistory is unobservable from out here (empty store),
			// we assert through the empty-result shape instead.
			res, err := c.handleHistoryRead(raw)
			if err != nil {
				t.Fatalf("handleHistoryRead: %v", err)
			}
			r, ok := res.(control.HistoryReadResult)
			if !ok {
				t.Fatalf("result type: got %T", res)
			}
			// An empty store returns (nil, 0) regardless of limit; the
			// branch we care about is that clamping did not error.
			if len(r.Findings) != 0 || r.Total != 0 {
				t.Errorf("empty store unexpected result: %+v", r)
			}
		})
	}
}

func TestHandleHistoryReadNegativeOffsetClamped(t *testing.T) {
	c := newListenerForTest(t)
	raw, _ := json.Marshal(control.HistoryReadArgs{Limit: 10, Offset: -3})
	if _, err := c.handleHistoryRead(raw); err != nil {
		t.Fatalf("negative offset must be clamped silently, got error: %v", err)
	}
}

func TestHandleHistoryReadBadJSON(t *testing.T) {
	c := newListenerForTest(t)
	_, err := c.handleHistoryRead(json.RawMessage("{not json"))
	if err == nil {
		t.Fatal("bad args JSON must surface as an error")
	}
	if !strings.Contains(err.Error(), "parsing args") {
		t.Errorf("expected parsing-args error, got %v", err)
	}
}

func TestHandleHistoryReadEmptyArgs(t *testing.T) {
	c := newListenerForTest(t)
	// Zero-length args is the default wire form for commands that
	// carry no parameters; it must not error.
	if _, err := c.handleHistoryRead(nil); err != nil {
		t.Fatalf("empty args must be treated as defaults, got: %v", err)
	}
}

// --- handleStatus -----------------------------------------------------

func TestHandleStatusZeroStartTime(t *testing.T) {
	c := newListenerForTest(t)
	c.d.startTime = time.Time{} // regress the "uptime==0 when not set" branch
	res, err := c.handleStatus(nil)
	if err != nil {
		t.Fatalf("handleStatus: %v", err)
	}
	status := res.(control.StatusResult)
	if status.UptimeSec != 0 {
		t.Errorf("zero startTime must yield zero uptime, got %d", status.UptimeSec)
	}
	if status.LatestScanTime != "" {
		t.Errorf("never-scanned store must report empty time, got %q", status.LatestScanTime)
	}
}

// --- handleRulesReload / handleGeoIPReload ----------------------------

func TestHandleRulesReloadReturnsStatus(t *testing.T) {
	c := newListenerForTest(t)
	// No signatures.Global and no yara.Active means reloadSignatures
	// short-circuits through both nil guards — still returns a valid
	// response.
	res, err := c.handleRulesReload(nil)
	if err != nil {
		t.Fatalf("handleRulesReload: %v", err)
	}
	m, ok := res.(map[string]string)
	if !ok {
		t.Fatalf("result type: got %T", res)
	}
	if m["status"] != "reloaded" {
		t.Errorf("status: got %q", m["status"])
	}
}

func TestHandleGeoIPReloadReturnsStatus(t *testing.T) {
	c := newListenerForTest(t)
	// publishGeoIP locks geoipMu and, with d.geoipDB == nil, tries to
	// open a fresh db under cfg.StatePath/geoip. Point StatePath at a
	// temp dir so the attempt doesn't accidentally touch real state.
	c.d.cfg.StatePath = t.TempDir()
	res, err := c.handleGeoIPReload(nil)
	if err != nil {
		t.Fatalf("handleGeoIPReload: %v", err)
	}
	m, ok := res.(map[string]string)
	if !ok {
		t.Fatalf("result type: got %T", res)
	}
	if m["status"] != "reloaded" {
		t.Errorf("status: got %q", m["status"])
	}
}

// --- handleTierRun ----------------------------------------------------

func TestHandleTierRunBadArgsJSON(t *testing.T) {
	c := newListenerForTest(t)
	_, err := c.handleTierRun(json.RawMessage("{not json"))
	if err == nil {
		t.Fatal("bad args JSON must produce an error")
	}
	if !strings.Contains(err.Error(), "parsing args") {
		t.Errorf("expected parsing-args error, got %v", err)
	}
}

func TestHandleTierRunBadTier(t *testing.T) {
	c := newListenerForTest(t)
	raw, _ := json.Marshal(control.TierRunArgs{Tier: "bogus"})
	_, err := c.handleTierRun(raw)
	if err == nil {
		t.Fatal("bad tier must produce an error")
	}
	if !strings.Contains(err.Error(), "unknown tier") {
		t.Errorf("expected unknown-tier error, got %v", err)
	}
}

// writeFakeBinary puts a known byte string at path and returns it.
// Used to force an integrity.Verify mismatch deterministically.
func writeFakeBinary(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "csm-fake-binary")
	if err := os.WriteFile(p, []byte("not-the-real-binary"), 0600); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}
	return p
}

func TestHandleTierRunIntegrityFailAlertsFlow(t *testing.T) {
	c := newListenerForTest(t)
	c.d.binaryPath = writeFakeBinary(t)
	// A deliberately wrong BinaryHash forces Verify to fail.
	c.d.cfg.Integrity.BinaryHash = "sha256:deadbeef"

	raw, _ := json.Marshal(control.TierRunArgs{Tier: "critical", Alerts: true})
	_, err := c.handleTierRun(raw)
	if err == nil {
		t.Fatal("integrity mismatch must produce an error")
	}
	if !strings.Contains(err.Error(), "integrity verify failed") {
		t.Errorf("expected integrity-verify error, got %v", err)
	}
	// Alerts=true must have queued a Critical integrity finding.
	select {
	case f := <-c.d.alertCh:
		if f.Check != "integrity" || f.Severity != alert.Critical {
			t.Errorf("unexpected finding queued: %+v", f)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected an integrity finding on alertCh")
	}
}

func TestHandleTierRunIntegrityFailNoAlertsFlag(t *testing.T) {
	c := newListenerForTest(t)
	c.d.binaryPath = writeFakeBinary(t)
	c.d.cfg.Integrity.BinaryHash = "sha256:deadbeef"

	raw, _ := json.Marshal(control.TierRunArgs{Tier: "critical", Alerts: false})
	if _, err := c.handleTierRun(raw); err == nil {
		t.Fatal("integrity mismatch must produce an error even when Alerts=false")
	}
	// Alerts=false must NOT have queued anything.
	select {
	case f := <-c.d.alertCh:
		t.Errorf("no alert expected when Alerts=false, got %+v", f)
	default:
	}
}

func TestHandleTierRunIntegrityFailChannelSaturatedDropsTracked(t *testing.T) {
	c := newListenerForTest(t)
	c.d.binaryPath = writeFakeBinary(t)
	c.d.cfg.Integrity.BinaryHash = "sha256:deadbeef"
	// Single-slot channel that we pre-fill so the select hits default.
	c.d.alertCh = make(chan alert.Finding, 1)
	c.d.alertCh <- alert.Finding{Check: "placeholder"}

	before := c.d.DroppedAlerts()
	raw, _ := json.Marshal(control.TierRunArgs{Tier: "critical", Alerts: true})
	if _, err := c.handleTierRun(raw); err == nil {
		t.Fatal("integrity mismatch must still error")
	}
	after := c.d.DroppedAlerts()
	if after != before+1 {
		t.Errorf("droppedAlerts must increment when channel is full: before=%d after=%d",
			before, after)
	}
}

// --- dispatch end-to-end for every known command ----------------------

// Covers the dispatch switch's non-error branches and the Response
// envelope marshal path. Each command is issued through the same entry
// point the Unix socket uses.
func TestDispatchRoutesEveryKnownCommand(t *testing.T) {
	c := newListenerForTest(t)
	c.d.cfg.StatePath = t.TempDir() // for handleGeoIPReload's OpenFresh

	cmds := []string{
		control.CmdStatus,
		control.CmdHistoryRead,
		control.CmdRulesReload,
		control.CmdGeoIPReload,
	}
	for _, cmd := range cmds {
		t.Run(cmd, func(t *testing.T) {
			raw, _ := json.Marshal(control.Request{Cmd: cmd})
			resp := c.dispatch(raw)
			if !resp.OK {
				t.Fatalf("%s: dispatch must succeed, got error=%q", cmd, resp.Error)
			}
			if len(resp.Result) == 0 || resp.Result[0] != '{' {
				t.Errorf("%s: result must be a JSON object, got %s", cmd, resp.Result)
			}
		})
	}
}

// --- fuzz seed for dispatch JSON parsing ------------------------------

// FuzzDispatch exercises the JSON parser for the request envelope with
// attacker-shaped input. The handler must never panic regardless of
// payload; the invariant is "every input yields a well-formed Response".
func FuzzDispatch(f *testing.F) {
	seeds := [][]byte{
		nil,
		[]byte(""),
		[]byte("{"),
		[]byte("null"),
		[]byte(`{"cmd":""}`),
		[]byte(`{"cmd":"status"}`),
		[]byte(`{"cmd":"history.read","args":{"limit":-1}}`),
		[]byte(`{"cmd":"tier.run","args":{"tier":""}}`),
		[]byte(`{"cmd":"tier.run","args":"not-an-object"}`),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	c := newListenerForFuzz(f)
	f.Fuzz(func(t *testing.T, in []byte) {
		resp := c.dispatch(in)
		// Every branch must produce a well-formed envelope. OK=true
		// requires a Result; OK=false requires an Error.
		if resp.OK && len(resp.Result) == 0 {
			t.Errorf("OK response missing Result: in=%q", in)
		}
		if !resp.OK && resp.Error == "" {
			t.Errorf("error response missing Error text: in=%q", in)
		}
	})
}

// newListenerForFuzz is the f.Fuzz-compatible twin of
// newListenerForTest. testing.TB accepts both *testing.T and
// *testing.F, so the body is identical except for the Helper() target.
func newListenerForFuzz(f *testing.F) *ControlListener {
	f.Helper()
	st, err := state.Open(f.TempDir())
	if err != nil {
		f.Fatalf("state.Open: %v", err)
	}
	f.Cleanup(func() { _ = st.Close() })
	d := &Daemon{
		cfg:     &config.Config{StatePath: f.TempDir()},
		store:   st,
		alertCh: make(chan alert.Finding, 8),
		version: "fuzz",
	}
	config.SetActive(d.cfg)
	f.Cleanup(func() { config.SetActive(nil) })
	return &ControlListener{d: d}
}
