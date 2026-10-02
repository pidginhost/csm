package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

const testPAMBootID = "6f1d7b0e-2c4a-4f3e-9b8a-1c2d3e4f5a6b"

func observingPAMListener(t *testing.T) (*PAMListener, chan alert.Finding) {
	t.Helper()
	prev := pamBootID
	pamBootID = func() string { return testPAMBootID }
	t.Cleanup(func() { pamBootID = prev })
	cfg := &config.Config{}
	cfg.Thresholds.PAMBruteforceThreshold = 2
	cfg.Thresholds.CredStuffingDistinctAccounts = 50
	alertCh := make(chan alert.Finding, 8)
	return &PAMListener{
		cfg:      cfg,
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
		stuffing: newCredentialStuffingDetector(50, 10*time.Minute, nil),
	}, alertCh
}

// A brute-force finding names the failure that crossed the threshold: the
// module's pid and clock on this boot.
func TestPAMFailureCarriesItsObservation(t *testing.T) {
	p, alertCh := observingPAMListener(t)
	p.processEvent("FAIL ip=192.0.2.60 user=alice service=sshd pid=4242 ts=1790000000.100000000")
	p.processEvent("FAIL ip=192.0.2.60 user=alice service=sshd pid=4243 ts=1790000001.200000000")
	got := drainForCheck(alertCh, "pam_bruteforce")
	if got == nil {
		t.Fatal("no pam_bruteforce finding")
	}
	want := alert.Observation{Producer: "pam_socket", Stream: "pam:" + testPAMBootID, Cursor: "4243:1790000001.200000000", ObservedAt: time.Unix(1790000001, 200000000)}
	if got.Observation != want {
		t.Fatalf("observation %+v, want %+v", got.Observation, want)
	}
}

// Reusing a pid later on the same boot still names a different event;
// a re-report of the same wire event keeps its complete reference.
func TestPAMFailurePIDReuseKeepsDistinctObservations(t *testing.T) {
	_, _ = observingPAMListener(t)
	a := pamObservation("4242", "1790000000.100000000")
	b := pamObservation("4242", "1790000001.100000000")
	if a == (alert.Observation{}) || b == (alert.Observation{}) || a.Stream != b.Stream || a.Cursor == b.Cursor || a != pamObservation("4242", "1790000000.100000000") {
		t.Fatalf("pid reuse/re-report identities %+v and %+v", a, b)
	}
}

// A line from an older module, or with an identity that does not parse,
// still counts but carries no observation.
func TestPAMFailureWithoutIdentityHasNoObservation(t *testing.T) {
	for name, suffix := range map[string]string{
		"older module":    "",
		"pid not numeric": " pid=abc ts=1790000000.100000000",
		"no fraction":     " pid=4242 ts=1790000000",
		"short fraction":  " pid=4242 ts=1790000000.12",
		"negative time":   " pid=4242 ts=-1.000000000",
		"zero time":       " pid=4242 ts=0.000000000",
	} {
		t.Run(name, func(t *testing.T) {
			p, alertCh := observingPAMListener(t)
			p.processEvent("FAIL ip=192.0.2.61 user=alice service=sshd" + suffix)
			p.processEvent("FAIL ip=192.0.2.61 user=alice service=sshd" + suffix)
			got := drainForCheck(alertCh, "pam_bruteforce")
			if got == nil || got.Observation != (alert.Observation{}) {
				t.Fatalf("finding %+v, want one without an observation", got)
			}
		})
	}
}

// Without a boot identity the stream is unknown, so no observation.
func TestPAMFailureWithoutBootIDHasNoObservation(t *testing.T) {
	p, alertCh := observingPAMListener(t)
	pamBootID = func() string { return "" }
	p.processEvent("FAIL ip=192.0.2.62 user=alice service=sshd pid=4242 ts=1790000000.100000000")
	p.processEvent("FAIL ip=192.0.2.62 user=alice service=sshd pid=4243 ts=1790000001.100000000")
	if got := drainForCheck(alertCh, "pam_bruteforce"); got == nil || got.Observation != (alert.Observation{}) {
		t.Fatalf("finding %+v, want one without an observation", got)
	}
}

// The boot identity is the kernel's boot UUID; anything else is no identity.
func TestReadPAMBootID(t *testing.T) {
	for content, want := range map[string]string{
		testPAMBootID + "\n":                     testPAMBootID,
		"6F1D7B0E-2C4A-4F3E-9B8A-1C2D3E4F5A6B\n": "",
		"short\n":                                "",
		"------------------------------------\n": "",
		"6f1d7b0e-2c4a4-f3e-9b8a-1c2d3e4f5a6b\n": "",
		"6f1d7b0e 2c4a 4f3e 9b8a 1c2d3e4f5a6b\n": "",
	} {
		path := filepath.Join(t.TempDir(), "boot_id")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := readPAMBootID(path); got != want {
			t.Errorf("boot id from %q = %q, want %q", content, got, want)
		}
	}
	if got := readPAMBootID(filepath.Join(t.TempDir(), "missing")); got != "" {
		t.Errorf("missing boot id = %q", got)
	}
}
