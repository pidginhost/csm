package daemon

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/maillog"
)

// Only paired SMTP failures supply SMTP spray roots through the mail reader;
// Dovecot verdicts, other services and hosts reading Exim cannot supply them.
func TestPostfixSprayRootsFromMailDispatch(t *testing.T) {
	for name, tc := range map[string]struct {
		verdict, result, exim bool
		tag                   string
		wantSpray             bool
	}{
		"paired":         {verdict: true, result: true, tag: "postfix/smtpd[99]", wantSpray: true},
		"verdict alone":  {verdict: true},
		"warning alone":  {result: true, tag: "postfix/smtpd[99]"},
		"dovecot result": {verdict: true, result: true, tag: "dovecot"},
		"smtp client":    {verdict: true, result: true, tag: "postfix/smtp[99]"},
		"exim host":      {verdict: true, result: true, tag: "postfix/smtpd[99]", exim: true},
	} {
		t.Run(name, func(t *testing.T) {
			d, clock := newPairingDaemon(t, &config.Config{})
			d.smtpAuthFromExim = tc.exim
			wantObservations := map[string]alert.Observation{}
			var sprays []alert.Finding
			cursor := 0
			dispatch := func(message string) alert.Observation {
				cursor++
				clock.advance(time.Second)
				pos := maillog.Position{Stream: "m:7:e.0", Cursor: strconv.Itoa(cursor), ObservedAt: clock.Now()}
				line := maillog.Line{Message: clock.Now().Format(time.RFC3339) + " mail " + message, Position: pos}
				if !d.dispatchMailLogLine(line, d.handleMailLine) {
					t.Fatal("mail dispatch refused")
				}
				for {
					select {
					case f := <-d.alertCh:
						if f.Check == "smtp_subnet_spray" {
							sprays = append(sprays, f)
						}
					default:
						return alert.Observation{Producer: string(checks.ProducerMailLog), Stream: pos.Stream, Cursor: pos.Cursor, ObservedAt: pos.ObservedAt}
					}
				}
			}
			for i := 1; i <= 8; i++ {
				ip := fmt.Sprintf("203.0.113.%d", i)
				if tc.verdict {
					dispatch("dovecot: auth: sql(alice@example.test," + ip + "): Password mismatch")
				}
				if tc.result {
					wantObservations[ip] = dispatch(tc.tag + ": warning: unknown[" + ip + "]: SASL LOGIN authentication failed: authentication failure")
				}
			}
			if !tc.wantSpray {
				if len(sprays) != 0 || smtpCalls(d) != 0 {
					t.Fatalf("unpaired source counted %d SMTP failures and emitted %+v", smtpCalls(d), sprays)
				}
				return
			}
			if len(sprays) != 1 || smtpCalls(d) != 8 {
				t.Fatalf("paired source counted %d SMTP failures and emitted %+v", smtpCalls(d), sprays)
			}
			spray := sprays[0]
			if len(spray.SprayConstituents) != 8 || len(spray.CIDRs) != 1 || spray.CIDRs[0] != "203.0.113.0/24" {
				t.Fatalf("spray did not retain the counted addresses: %+v", spray)
			}
			reg, err := admission.NewRegistry(checks.AdmissionPolicy)
			if err != nil {
				t.Fatal(err)
			}
			var producer *admission.Producer
			for _, entry := range checks.ProducerTable() {
				if entry.Spec.ID == checks.ProducerMailLog {
					producer, err = reg.Register(entry.Spec)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			for _, c := range spray.SprayConstituents {
				want, ok := wantObservations[c.Address]
				if !ok || c.Observation != want || c.Attribution != admission.AttributionPeer || !c.LastSeen.Equal(want.ObservedAt) {
					t.Fatalf("constituent %+v, want its Postfix result %+v", c, want)
				}
				delete(wantObservations, c.Address)
				root := spray
				root.SourceIP, root.Observation, root.Attribution = c.Address, c.Observation, c.Attribution
				id, input, err := checks.AdmissionEvidence(root)
				if err != nil || id != checks.ProducerMailLog || input.Parser != (admission.ParserRef{Name: "dovecot", Version: 1}) {
					t.Fatalf("mail evidence changed its producer/parser: %s %+v: %v", id, input, err)
				}
				evidence, err := producer.Mint(input)
				if err != nil {
					t.Fatalf("Postfix spray root refused: %v", err)
				}
				data, err := evidence.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				retained, err := admission.UnmarshalEvidence(data)
				if err != nil || retained.ID() != evidence.ID() || !retained.SameExceptFinding(evidence) {
					t.Fatalf("retained root changed: %v", err)
				}
			}
			if len(wantObservations) != 0 {
				t.Fatalf("missing roots for %v", wantObservations)
			}
		})
	}
}
