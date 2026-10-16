package antispam

import (
	"strings"
	"testing"
)

func TestProbeQueries(t *testing.T) {
	s := defaults(false)
	s.Feeds = []string{FeedPSBL, FeedSEM, FeedURIBL, FeedSpamhausDQS}
	s.DQSKeyFile, s.DQSKey = "/etc/csm/k", NewSecret(testKey)
	var names []string
	for _, q := range ProbeQueries(s) {
		names = append(names, q.Name)
	}
	want := []string{
		"2.0.0.127.psbl.surriel.com", "1.0.0.127.psbl.surriel.com",
		"2.0.0.127.bl.spameatingmonkey.net", "1.0.0.127.bl.spameatingmonkey.net",
		"test.uribl.com.multi.uribl.com", "csm-probe.invalid.multi.uribl.com",
		"2.0.0.127." + testKey + ".zen.dq.spamhaus.net", "1.0.0.127." + testKey + ".zen.dq.spamhaus.net",
	}
	if strings.Join(names, " ") != strings.Join(want, " ") {
		t.Fatal("probe queries differ from the expected test points")
	}
}

func TestClassifyProbe(t *testing.T) {
	uribl, _ := FeedByName(FeedURIBL)
	z := uribl.Zones[0]
	listed := ProbeQuery{Feed: FeedURIBL, Zone: z, Listed: true}
	unlisted := ProbeQuery{Feed: FeedURIBL, Zone: z}
	for _, tc := range []struct {
		q    ProbeQuery
		a    ProbeAnswer
		want ProbeStatus
	}{
		{listed, ProbeAnswer{Addrs: []string{"127.0.0.14"}}, ProbeOK},
		{listed, ProbeAnswer{Addrs: []string{"127.0.0.1"}}, ProbeRefused},
		{listed, ProbeAnswer{NXDomain: true}, ProbeNoAnswer},
		{listed, ProbeAnswer{Failed: true}, ProbeNoAnswer},
		{listed, ProbeAnswer{}, ProbeNoAnswer},
		{listed, ProbeAnswer{Addrs: []string{"127.0.0.4"}}, ProbeUnexpected},
		{unlisted, ProbeAnswer{NXDomain: true}, ProbeOK},
		{unlisted, ProbeAnswer{Addrs: []string{"127.0.0.2"}}, ProbeListsAll},
		{unlisted, ProbeAnswer{Addrs: []string{"127.0.0.255"}}, ProbeRefused},
		{unlisted, ProbeAnswer{Failed: true}, ProbeNoAnswer},
		{unlisted, ProbeAnswer{Addrs: []string{"192.0.2.1"}}, ProbeUnexpected},
	} {
		if got, _ := ClassifyProbe(uribl, tc.q, tc.a); got != tc.want {
			t.Errorf("listed=%v %+v = %v, want %v", tc.q.Listed, tc.a, got, tc.want)
		}
	}
	if _, meaning := ClassifyProbe(uribl, listed, ProbeAnswer{Addrs: []string{"127.0.0.1"}}); meaning != "URIBL refuses this resolver" {
		t.Errorf("meaning %q", meaning)
	}
}
