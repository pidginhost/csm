package firewall

import "testing"

func TestInferProvenance(t *testing.T) {
	cases := []struct {
		action string
		reason string
		want   string
	}{
		{action: "block", reason: "Blocked via CSM Web UI", want: SourceWebUI},
		{action: "allow", reason: "Allowed via CLI", want: SourceCLI},
		{action: "block", reason: "CSM auto-block: brute force", want: SourceAutoResponse},
		{action: "temp_allow", reason: "passed challenge", want: SourceChallenge},
		{action: "allow", reason: "CSM temp whitelist", want: SourceWhitelist},
		{action: "allow", reason: "CSM whitelist: customer IP", want: SourceWhitelist},
		{action: "allow", reason: "dyndns: admin.example.com", want: SourceDynDNS},
		{action: "temp_allow_expired", reason: "", want: SourceSystem},
		{action: "unblock", reason: "manual unblock via UI", want: SourceWebUI},
		{action: "block", reason: "custom operator reason", want: SourceUnknown},
	}

	for _, tc := range cases {
		if got := InferProvenance(tc.action, tc.reason); got != tc.want {
			t.Errorf("InferProvenance(%q, %q) = %q; want %q", tc.action, tc.reason, got, tc.want)
		}
	}
}
