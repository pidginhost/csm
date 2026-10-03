package daemon

import (
	"fmt"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

// Every fixed log that feeds address evidence names its producer, so its
// findings carry an observation; the cPanel access log also gets the
// observed handler its held findings need.
func TestFixedLogSpecsNameTheirProducers(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	exim := func(string, alert.Observation, *config.Config) []alert.Finding { return nil }
	for _, c := range []struct {
		info platform.Info
		exim bool
		want map[string]admission.ProducerID
	}{
		{platform.Info{OS: platform.OSAlma, Panel: platform.PanelCPanel}, true, map[string]admission.ProducerID{
			"/var/log/secure":                    checks.ProducerSSHLog,
			"/usr/local/cpanel/logs/session_log": "",
			"/usr/local/cpanel/logs/access_log":  checks.ProducerCpanelAccessLog,
			"/var/log/messages":                  checks.ProducerFTPLog,
			eximMainlogPath:                      checks.ProducerEximLog,
		}},
		{platform.Info{OS: platform.OSUbuntu}, false, map[string]admission.ProducerID{
			"/var/log/auth.log": checks.ProducerSSHLog,
		}},
	} {
		t.Run(fmt.Sprint(c.info.OS), func(t *testing.T) {
			got := map[string]admission.ProducerID{}
			for _, s := range d.fixedLogSpecs(c.info, exim, c.exim) {
				got[s.path] = s.producer
				if s.handler == nil {
					t.Errorf("%s has no handler", s.path)
				}
				// The exim log hands each line's observation to the SMTP
				// tracker, so its spray constituents name their lines.
				if (s.path == "/usr/local/cpanel/logs/access_log" || s.path == eximMainlogPath) != (s.observed != nil) {
					t.Errorf("%s observed handler set = %v", s.path, s.observed != nil)
				}
			}
			if fmt.Sprint(got) != fmt.Sprint(c.want) {
				t.Fatalf("specs %v, want %v", got, c.want)
			}
		})
	}
}
