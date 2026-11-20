package daemon

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

// Reading a delayed request must not let a recent direct connection hide
// the forged peer recorded when that request was made.
func TestHTTPWatchersUseRequestTimeForPeerVerdicts(t *testing.T) {
	at := time.Now().Add(-90 * time.Minute).Truncate(time.Second)
	cfg := &config.Config{}
	cfg.Thresholds.XMLRPCThreshold = 3
	previous := checks.CurrentHTTPRewrite()
	checks.SetHTTPRewrite(checks.HTTPRewrite{State: checks.RewriteActive})
	t.Cleanup(func() { checks.SetHTTPRewrite(previous) })
	for i, tc := range []struct {
		name, check, format string
		producer            admission.ProducerID
		handler             LogLineHandler
		count               int
		dated               bool
	}{
		{"wp", "wp_login_bruteforce", `%s - - [%s] "POST /wp-login.php HTTP/1.1" 200 10 "-" "-"`, checks.ProducerAccessLog, parseAccessLogBruteForce, 10, true},
		{"xmlrpc", "xmlrpc_abuse", `%s - - [%s] "POST /xmlrpc.php HTTP/1.1" 200 10 "-" "-"`, checks.ProducerAccessLog, parseAccessLogBruteForce, 3, true},
		{"admin", "admin_panel_bruteforce", `%s - - [%s] "POST /phpmyadmin/index.php HTTP/1.1" 200 10 "-" "-"`, checks.ProducerAccessLog, parseAccessLogBruteForce, 10, true},
		{"undated access", "wp_login_bruteforce", `%s - - [%s] "POST /wp-login.php HTTP/1.1" 200 10 "-" "-"`, checks.ProducerAccessLog, parseAccessLogBruteForce, 10, false},
		{"apache", "modsec_block_escalation", `[client %s] ModSecurity: Access denied with code 403 [id "941100"]`, checks.ProducerModSecLog, parseModSecLogLineDeduped, 3, true},
		{"nginx", "modsec_block_escalation", `[client %s] ModSecurity: Access denied with code 403 [id "941100"]`, checks.ProducerModSecLog, parseModSecLogLineDeduped, 3, true},
		{"litespeed", "modsec_block_escalation", `[%s:5555-1#APVH_example.test] [MODSEC] Access denied with code 403 [id "941100"]`, checks.ProducerModSecLog, parseModSecLogLineDeduped, 3, true},
		{"undated modsec", "modsec_block_escalation", `[client %s] ModSecurity: Access denied with code 403 [id "941100"]`, checks.ProducerModSecLog, parseModSecLogLineDeduped, 3, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetAccessLogTrackerState()
			resetModSecCounters()
			t.Cleanup(resetAccessLogTrackerState)
			t.Cleanup(resetModSecCounters)
			ip := fmt.Sprintf("203.0.113.%d", 210+i)
			client := netip.MustParseAddr(ip)
			checks.ObserveWebPeer(at, netip.MustParseAddr("192.0.2.250"), client, cfg)
			checks.ObserveWebPeer(time.Now(), client, client, cfg)
			var line string
			if tc.producer == checks.ProducerAccessLog {
				stamp := at.Format("02/Jan/2006:15:04:05 -0700")
				if !tc.dated {
					stamp = "invalid"
				}
				line = fmt.Sprintf(tc.format, ip, stamp)
			} else {
				line = fmt.Sprintf(tc.format, ip)
				switch tc.name {
				case "apache":
					line = at.In(time.Local).Format("[Mon Jan 02 15:04:05 2006] [error] ") + line
				case "nginx":
					line = at.In(time.Local).Format("2006/01/02 15:04:05") + " [error] 1#1: " + line
				case "litespeed":
					line = at.In(time.Local).Format("2006-01-02 15:04:05") + " [INFO] [1] " + line
				}
			}
			w, path, ch := observingWatcher(t, tc.producer)
			w.handler, w.cfg = tc.handler, cfg
			appendLog(t, path, strings.Repeat(line+"\n", tc.count))
			w.readNewLines()
			var got []alert.Finding
			for _, f := range drainObservedFindings(ch) {
				if f.Check == tc.check {
					got = append(got, f)
				}
			}
			if len(got) != 1 {
				t.Fatalf("findings = %+v, want one %s", got, tc.check)
			}
			f := got[0]
			wantCause := admission.CauseForgedClient
			if tc.dated {
				if f.Observation.Producer != string(tc.producer) || !f.Observation.ObservedAt.Equal(at) ||
					!sameRef(f.Observation, recordRef(t, path, int64((tc.count-1)*(len(line)+1)), line)) {
					t.Errorf("observation = %+v, want triggering record at %v", f.Observation, at)
				}
			} else {
				wantCause = admission.CauseRewrittenLog
				if f.Observation != (alert.Observation{}) {
					t.Errorf("undated observation = %+v, want none", f.Observation)
				}
			}
			if _, _, err := checks.AdmissionEvidence(f); admission.CauseOf(err) != wantCause {
				t.Errorf("admission = %v, want %v", err, wantCause)
			}
		})
	}
}
