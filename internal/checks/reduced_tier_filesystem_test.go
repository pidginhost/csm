package checks

import (
	"context"
	"slices"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func reducedDeepCheckNames() map[string]bool {
	names := map[string]bool{}
	for _, nc := range reducedDeepChecks() {
		names[nc.name] = true
	}
	return names
}

// The reduced deep tier drops the filesystem checks the realtime monitor is
// assumed to cover, but the fanotify mask carries no FAN_MOVED_TO on any kernel
// and loses FAN_CREATE on EL8. A file renamed into place - an unpacked archive,
// a staged install, most droppers - raises no event, so the periodic content
// scans are the only thing that ever meets it. This is the same reasoning that
// already keeps the rolling PHP content scan and the file index in this tier.
func TestReducedDeepTierKeepsRenameBlindContentScans(t *testing.T) {
	names := reducedDeepCheckNames()
	for _, want := range []string{"webshells", "htaccess", "phishing"} {
		if !names[want] {
			t.Errorf("reduced deep tier omits %q: a file renamed into place is never scanned while the file monitor is active", want)
		}
	}
}

// filesystem is worse than rename-blind: it reports a setuid binary from the
// file mode, and chmod raises no close-write event at all, so no realtime path
// can ever observe one. Dropping this check from the tier the daemon actually
// runs leaves setuid detection with no coverage whatsoever.
func TestReducedDeepTierKeepsFilesystem(t *testing.T) {
	if !reducedDeepCheckNames()["filesystem"] {
		t.Fatal("reduced deep tier omits filesystem: a setuid binary is set by chmod, which raises no file-monitor event, so nothing else reports it")
	}
}

// exposed_files confirms a finding with a live request to the vhost, so no file
// event can stand in for it either. It has no realtime counterpart at all.
func TestReducedDeepTierKeepsExposedFiles(t *testing.T) {
	if !reducedDeepCheckNames()["exposed_files"] {
		t.Fatal("reduced deep tier omits exposed_files: an exposed backup or dump is only confirmed by probing the vhost, which no file event replaces")
	}
}

// A tier that runs a check must also be able to retire what it emitted, or a
// finding whose file is gone stays in the latest set forever.
func TestLatestPurgeCheckNamesForReducedDeepCoversRestoredChecks(t *testing.T) {
	names := LatestPurgeCheckNamesForReducedDeep()
	for _, want := range []string{"suid_binary", "backdoor_binary", "webshell", "htaccess_injection", "phishing_page", "web_exposed_db_dump"} {
		if !slices.Contains(names, want) {
			t.Errorf("reduced deep purge names missing %q", want)
		}
	}
}

// exposed_files confirms every candidate with a live request to the customer's
// vhost. Running it on each deep cycle would multiply that traffic against
// customer sites for findings the registry classes as posture, which do not
// change between cycles. It is throttled instead, so restoring it to the tier
// buys deterministic coverage without raising the probe rate.
func TestExposedFilesIsThrottled(t *testing.T) {
	min, ok := checkThrottleMin["exposed_files"]
	if !ok {
		t.Fatal("exposed_files is not throttled: its live vhost probes would run on every deep cycle")
	}
	if min < 60 {
		t.Fatalf("exposed_files throttle is %d minutes, too short to keep probe volume off customer vhosts", min)
	}
}

// Throttling must not cost coverage: a cycle that skips the check leaves its
// findings alone rather than retiring them, which is what keeps a skipped
// cycle from clearing a real exposure.
func TestThrottledCheckSkipDoesNotRetireItsFindings(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	exposure := alert.Finding{
		Check:    "web_exposed_db_dump",
		Severity: alert.Critical,
		Message:  "exposed dump",
		FilePath: "/home/a/public_html/db.sql",
	}
	ran := 0
	checks := []namedCheck{
		{"exposed_files", func(context.Context, *config.Config, *state.Store) []alert.Finding {
			ran++
			return []alert.Finding{exposure}
		}},
	}
	cfg := &config.Config{}

	findings, purge := runParallel(cfg, st, checks, "test", false)
	StoreLatestScanFindingsWithCoverage(st, purge, findings, nil)
	if ran != 1 {
		t.Fatalf("first cycle ran the check %d time(s), want 1", ran)
	}
	if !containsFindingCheck(st.LatestFindings(), "web_exposed_db_dump") {
		t.Fatalf("first cycle did not record the exposure: %+v", st.LatestFindings())
	}

	// Second cycle inside the throttle window: the check is skipped, and the
	// exposure it found last time must survive the cycle that did not look.
	findings, purge = runParallel(cfg, st, checks, "test", false)
	StoreLatestScanFindingsWithCoverage(st, purge, findings, nil)
	if ran != 1 {
		t.Fatalf("throttled check ran again inside its window (%d runs)", ran)
	}
	if !containsFindingCheck(st.LatestFindings(), "web_exposed_db_dump") {
		t.Fatalf("a throttled, skipped cycle retired the exposure: %+v", st.LatestFindings())
	}
}
