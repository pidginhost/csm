package daemon

import "testing"

func TestClassifyModSecConfidence(t *testing.T) {
	tests := []struct {
		name    string
		ruleNum int
		msg     string
		tags    string
		want    modsecConfidence
	}{
		{
			name:    "comodo content-type policy is low",
			ruleNum: 210710,
			msg:     "COMODO WAF: Request content type is not allowed by policy. Please update file userdata_wl_content_type.",
			want:    modsecConfLow,
		},
		{
			name:    "comodo inbound anomaly points is low",
			ruleNum: 214930,
			msg:     "COMODO WAF: Inbound Points Exceeded|Total Incoming Points: 5",
			want:    modsecConfLow,
		},
		{
			name:    "comodo url-encoding-abuse attack is high",
			ruleNum: 210381,
			msg:     "COMODO WAF: URL Encoding Abuse Attack Attempt",
			want:    modsecConfHigh,
		},
		{
			name:    "comodo sql injection is high",
			ruleNum: 211000,
			msg:     "COMODO WAF: SQL Injection Attack: Common Injection Testing Detected",
			want:    modsecConfHigh,
		},
		{
			name:    "comodo remote command attack is high",
			ruleNum: 212000,
			msg:     "COMODO WAF: Remote Command Injection Attack",
			want:    modsecConfHigh,
		},
		{
			name:    "csm custom 900115 is high",
			ruleNum: 900115,
			msg:     "CSM custom probe rule",
			want:    modsecConfHigh,
		},
		{
			name:    "csm custom 900116 is high",
			ruleNum: 900116,
			msg:     "CSM custom attack rule",
			want:    modsecConfHigh,
		},
		{
			name:    "crs inbound anomaly score is low not high despite high range",
			ruleNum: 949110,
			msg:     "Inbound Anomaly Score Exceeded (Total Score: 5)",
			tags:    "anomaly-evaluation",
			want:    modsecConfLow,
		},
		{
			name:    "crs protocol-version policy is low",
			ruleNum: 920430,
			msg:     "HTTP protocol version is not allowed by policy",
			want:    modsecConfLow,
		},
		{
			name:    "crs sqli by tag is high",
			ruleNum: 942100,
			msg:     "SQL Injection Attack Detected via libinjection",
			tags:    "application-multi language-multi platform-multi attack-sqli OWASP_CRS",
			want:    modsecConfHigh,
		},
		{
			name:    "unknown blocking rule with no metadata is unknown",
			ruleNum: 211500,
			msg:     "",
			want:    modsecConfUnknown,
		},
		{
			name:    "attack signal wins over known-low id",
			ruleNum: 210710,
			msg:     "COMODO WAF: SQL Injection Attack via content type",
			tags:    "attack-sqli",
			want:    modsecConfHigh,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyModSecConfidence(tt.ruleNum, tt.msg, tt.tags)
			if got != tt.want {
				t.Fatalf("classifyModSecConfidence(%d, %q, %q) = %v, want %v",
					tt.ruleNum, tt.msg, tt.tags, got, tt.want)
			}
		})
	}
}
