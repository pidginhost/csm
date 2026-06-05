package reporting

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/processctx"
)

func allClasses() map[Class]bool {
	return map[Class]bool{
		ClassBruteforce:         true,
		ClassPHPRelay:           true,
		ClassCredentialStuffing: true,
		ClassBadASNEgress:       true,
	}
}

var ts = time.Unix(1_700_000_000, 0).UTC()

func TestClassifyKnownAndUnknown(t *testing.T) {
	if c, ok := Classify("pam_bruteforce"); !ok || c != ClassBruteforce {
		t.Fatalf("pam_bruteforce -> %q %v", c, ok)
	}
	if c, ok := Classify("email_php_relay_abuse"); !ok || c != ClassPHPRelay {
		t.Fatalf("php relay -> %q %v", c, ok)
	}
	if _, ok := Classify("some_random_check"); ok {
		t.Fatal("unknown check classified")
	}
}

func TestConsiderReportsConfirmedAbuse(t *testing.T) {
	g := Gate{Enabled: allClasses()}
	f := alert.Finding{Check: "pam_bruteforce", Severity: alert.Critical, SourceIP: "203.0.113.5", Timestamp: ts}
	r, ok := g.Consider(f)
	if !ok {
		t.Fatal("confirmed abuse not reported")
	}
	if r.IP != "203.0.113.5" || r.Class != ClassBruteforce || r.Count != 1 {
		t.Fatalf("report = %+v", r)
	}
	if !r.FirstSeen.Equal(ts) || !r.LastSeen.Equal(ts) {
		t.Fatalf("times = %v..%v", r.FirstSeen, r.LastSeen)
	}
}

func TestConsiderNormalizesIPv4MappedAddress(t *testing.T) {
	g := Gate{Enabled: allClasses()}
	f := alert.Finding{Check: "pam_bruteforce", Severity: alert.Critical, SourceIP: "::ffff:203.0.113.5", Timestamp: ts}
	r, ok := g.Consider(f)
	if !ok {
		t.Fatal("IPv4-mapped address not reported")
	}
	if r.IP != "203.0.113.5" {
		t.Fatalf("IP = %q, want central canonical key 203.0.113.5", r.IP)
	}
}

func TestConsiderSkipsNonCritical(t *testing.T) {
	g := Gate{Enabled: allClasses()}
	for _, sev := range []alert.Severity{alert.Warning, alert.High} {
		f := alert.Finding{Check: "pam_bruteforce", Severity: sev, SourceIP: "203.0.113.5", Timestamp: ts}
		if _, ok := g.Consider(f); ok {
			t.Fatalf("severity %v reported, want skip", sev)
		}
	}
}

func TestConsiderSkipsDisabledClass(t *testing.T) {
	g := Gate{Enabled: map[Class]bool{ClassPHPRelay: true}} // bruteforce not enabled
	f := alert.Finding{Check: "pam_bruteforce", Severity: alert.Critical, SourceIP: "203.0.113.5", Timestamp: ts}
	if _, ok := g.Consider(f); ok {
		t.Fatal("disabled class reported")
	}
}

func TestConsiderSkipsUnknownCheck(t *testing.T) {
	g := Gate{Enabled: allClasses()}
	f := alert.Finding{Check: "file_permission_warning", Severity: alert.Critical, SourceIP: "203.0.113.5", Timestamp: ts}
	if _, ok := g.Consider(f); ok {
		t.Fatal("unknown check reported")
	}
}

func TestConsiderRequiresValidIP(t *testing.T) {
	g := Gate{Enabled: allClasses()}
	for _, ip := range []string{"", "not-an-ip", "host.example"} {
		f := alert.Finding{Check: "pam_bruteforce", Severity: alert.Critical, SourceIP: ip, Timestamp: ts}
		if _, ok := g.Consider(f); ok {
			t.Fatalf("reported with bad IP %q", ip)
		}
	}
}

func TestConsiderRequiresTimestamp(t *testing.T) {
	g := Gate{Enabled: allClasses()}
	f := alert.Finding{Check: "pam_bruteforce", Severity: alert.Critical, SourceIP: "203.0.113.5"}
	if _, ok := g.Consider(f); ok {
		t.Fatal("reported with zero timestamp")
	}
}

// The serialized report must never carry tenant/domain/mailbox/path/process
// data, even though the source finding does.
func TestMinimizedReportLeaksNoPII(t *testing.T) {
	g := Gate{Enabled: allClasses()}
	f := alert.Finding{
		Check:     "email_php_relay_abuse",
		Severity:  alert.Critical,
		SourceIP:  "203.0.113.5",
		Timestamp: ts,
		TenantID:  "cpuser123",
		Domain:    "victim.example",
		Mailbox:   "ceo@victim.example",
		Path:      "/home/cpuser123/public_html/shell.php",
		Details:   "secret details",
		CPUser:    "cpuser123",
		MsgIDs:    []string{"abc@host"},
		Process: &processctx.ProcessContext{
			PID:     4242,
			UID:     1001,
			Account: "cpuser123",
			Comm:    "evil-worker",
			Exe:     "/tmp/payload",
			Cmdline: []string{"/tmp/payload", "--mailbox=ceo@victim.example"},
		},
	}
	r, ok := g.Consider(f)
	if !ok {
		t.Fatal("not reported")
	}
	body, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, leak := range []string{"cpuser123", "victim.example", "ceo@victim.example", "shell.php", "secret details", "abc@host", "evil-worker", "/tmp/payload"} {
		if bytes.Contains(body, []byte(leak)) {
			t.Fatalf("report leaked %q: %s", leak, body)
		}
	}
	wantJSON := "" +
		`{"ip":"203.0.113.5","class":"php_relay","count":1,` +
		`"first_seen":"2023-11-14T22:13:20Z",` +
		`"last_seen":"2023-11-14T22:13:20Z"}`
	if string(body) != wantJSON {
		t.Fatalf("report JSON = %s, want exactly %s", body, wantJSON)
	}
	// Exactly the minimal field set.
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	wantKeys := map[string]bool{"ip": true, "class": true, "count": true, "first_seen": true, "last_seen": true}
	for k := range got {
		if !wantKeys[k] {
			t.Fatalf("unexpected field %q in report", k)
		}
	}
	if len(got) != len(wantKeys) {
		t.Fatalf("report keys = %v, want exactly %v", got, wantKeys)
	}
}

func TestNoopReporter(t *testing.T) {
	var r Reporter = Noop{}
	r.Enqueue(Report{IP: "203.0.113.5"}) // must not panic
}
