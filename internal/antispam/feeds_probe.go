package antispam

import (
	"slices"
	"strings"
)

// ProbeQuery is one DNS question the feed probe asks. Name can hold the
// DQS key: it must never reach a log line or a finding.
type ProbeQuery struct {
	Feed   string
	Zone   Zone
	Name   string
	Listed bool
}

// ProbeAnswer is what a resolver said, without any error text: Go's DNS
// errors print the query name.
type ProbeAnswer struct {
	Addrs    []string
	NXDomain bool
	// Failed is a timeout, SERVFAIL, REFUSED or network error.
	Failed bool
}

// ProbeStatus classifies one probe answer.
type ProbeStatus int

const (
	ProbeOK ProbeStatus = iota
	// ProbeNoAnswer: the listed test point got no answer, or a query failed.
	ProbeNoAnswer
	// ProbeRefused: the list answered with one of its error codes.
	ProbeRefused
	// ProbeListsAll: the never-listed point got a listing code.
	ProbeListsAll
	// ProbeUnexpected: any other answer.
	ProbeUnexpected
)

// unlistedDomain is a name no domain list can list: .invalid never
// resolves (RFC 6761).
const unlistedDomain = "csm-probe.invalid"

// ProbeQueries lists the questions for s's probed zones: the listed test
// point and the unlisted point, which for IP lists is also rspamd's own
// monitored address.
func ProbeQueries(s Settings) []ProbeQuery {
	var out []ProbeQuery
	for _, f := range s.DNSFeeds() {
		for _, z := range f.Zones {
			if z.TestName == "" {
				continue
			}
			zone := strings.ReplaceAll(z.Zone, dqsKeyMark, s.DQSKey.Reveal())
			unlisted := "1.0.0.127"
			if z.Domain {
				unlisted = unlistedDomain
			}
			out = append(out,
				ProbeQuery{Feed: f.Name, Zone: z, Name: z.TestName + "." + zone, Listed: true},
				ProbeQuery{Feed: f.Name, Zone: z, Name: unlisted + "." + zone})
		}
	}
	return out
}

// ClassifyProbe judges one answer. The second result is the meaning of an
// error answer, from the catalogue.
func ClassifyProbe(f Feed, q ProbeQuery, a ProbeAnswer) (ProbeStatus, string) {
	scores := func(addr string) bool {
		return slices.ContainsFunc(q.Zone.Codes, func(c Code) bool { return slices.Contains(c.Answers, addr) })
	}
	// Rspamd scores each returned address independently. A refusal alongside
	// a listing does not make a listing of the negative test point harmless.
	hasListing := slices.ContainsFunc(a.Addrs, scores)
	if !q.Listed && hasListing {
		return ProbeListsAll, ""
	}
	for _, addr := range a.Addrs {
		if meaning, ok := f.Errors[addr]; ok {
			if hasListing {
				return ProbeUnexpected, ""
			}
			return ProbeRefused, meaning
		}
	}
	switch {
	case a.Failed:
		return ProbeNoAnswer, ""
	case q.Listed && (a.NXDomain || len(a.Addrs) == 0):
		return ProbeNoAnswer, ""
	case q.Listed && slices.ContainsFunc(a.Addrs, func(addr string) bool { return slices.Contains(q.Zone.TestAnswers, addr) }):
		return ProbeOK, ""
	case !q.Listed && a.NXDomain:
		return ProbeOK, ""
	}
	return ProbeUnexpected, ""
}
