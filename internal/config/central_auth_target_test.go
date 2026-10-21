package config

import (
	"strings"
	"testing"
)

type reportTarget = struct {
	Name      string `yaml:"name"`
	URL       string `yaml:"url"`
	Transport string `yaml:"transport"`
	NodeID    string `yaml:"node_id"`
	KeyID     string `yaml:"key_id"`
	KeyEnv    string `yaml:"key_env"`
	TokenEnv  string `yaml:"token_env"`
}

func authTargetConfig(setURL string, targets ...reportTarget) *Config {
	cfg := lockoutTestConfig(nil)
	cfg.Reputation.Central.Enabled = true
	cfg.Reputation.Central.SetURL = setURL
	cfg.Reputation.Central.AuthTarget = "central"
	cfg.Reputation.Report.Targets = targets
	return cfg
}

func centralTarget() reportTarget {
	return reportTarget{Name: "central", URL: "https://abuse.example.net/report", Transport: "ed25519",
		NodeID: "n_000000000000000000000001", KeyID: "k_000000000000000000000002", KeyEnv: "CSM_REPORT_KEY"}
}

func TestValidateCentralAuthTarget(t *testing.T) {
	const field = "reputation.central.auth_target"
	const setURL = "https://abuse.example.net/decisions"
	with := func(edit func(*reportTarget)) reportTarget {
		tg := centralTarget()
		edit(&tg)
		return tg
	}
	for _, c := range []struct {
		name    string
		cfg     *Config
		wantErr string
	}{
		{"valid", authTargetConfig(setURL, centralTarget()), ""},
		{"explicit default port", authTargetConfig("https://abuse.example.net:443/decisions", centralTarget()), ""},
		{"host case", authTargetConfig("https://ABUSE.example.net/decisions", centralTarget()), ""},
		{"no such target", authTargetConfig(setURL, with(func(tg *reportTarget) { tg.Name = "other" })), "exactly one"},
		{"two targets", authTargetConfig(setURL, centralTarget(), centralTarget()), "exactly one"},
		{"hmac target", authTargetConfig(setURL, with(func(tg *reportTarget) { tg.Transport = "hmac" })), "ed25519"},
		{"no node_id", authTargetConfig(setURL, with(func(tg *reportTarget) { tg.NodeID = "" })), "node_id"},
		{"no key_id", authTargetConfig(setURL, with(func(tg *reportTarget) { tg.KeyID = "" })), "key_id"},
		{"no key_env", authTargetConfig(setURL, with(func(tg *reportTarget) { tg.KeyEnv = "" })), "key_env"},
		{"other host", authTargetConfig("https://lists.example.net/decisions", centralTarget()), "same scheme, host and port"},
		{"other port", authTargetConfig("https://abuse.example.net:8443/decisions", centralTarget()), "same scheme, host and port"},
		{"other scheme", authTargetConfig("http://abuse.example.net/decisions", centralTarget()), "same scheme, host and port"},
	} {
		t.Run(c.name, func(t *testing.T) {
			res, ok := findResult(Validate(c.cfg), "error", field)
			if c.wantErr == "" && ok {
				t.Fatalf("unexpected error: %s", res.Message)
			}
			if c.wantErr != "" && (!ok || !strings.Contains(res.Message, c.wantErr)) {
				t.Fatalf("error = %q (found %v), want it to mention %q", res.Message, ok, c.wantErr)
			}
		})
	}
	unset := authTargetConfig(setURL)
	unset.Reputation.Central.AuthTarget = ""
	if _, ok := findResult(Validate(unset), "error", field); ok {
		t.Fatal("an unset auth_target must stay valid: pulls stay unsigned")
	}
}

func TestValidateCentralAuthTargetOrigins(t *testing.T) {
	const field = "reputation.central.auth_target"
	for _, tc := range []struct {
		name      string
		reportURL string
		setURL    string
		wantValid bool
	}{
		{"IPv6 default port", "https://[2001:db8::1]/report", "https://[2001:db8::1]:443/decisions", true},
		{"IPv6 expanded address", "https://[2001:db8::1]/report", "https://[2001:0db8:0:0:0:0:0:1]/decisions", true},
		{"IPv6 address case", "https://[2001:db8::a]/report", "https://[2001:DB8::A]/decisions", true},
		{"IPv6 different address", "https://[2001:db8::1]/report", "https://[2001:db8::2]/decisions", false},
		{"IPv6 different port", "https://[2001:db8::1]/report", "https://[2001:db8::1]:8443/decisions", false},
		{"IPv6 different scheme", "https://[2001:db8::1]:443/report", "http://[2001:db8::1]:443/decisions", false},
		{"IPv6 same zone", "https://[2001:db8::1%25eth0]/report", "https://[2001:db8::1%25eth0]:443/decisions", true},
		{"IPv6 expanded address with zone", "https://[2001:db8::1%25eth0]/report", "https://[2001:db8:0:0:0:0:0:1%25eth0]/decisions", true},
		{"IPv6 zone case differs", "https://[2001:db8::1%25eth0]/report", "https://[2001:db8::1%25ETH0]/decisions", false},
		{"IPv6 different zone", "https://[2001:db8::1%25eth0]/report", "https://[2001:db8::1%25eth1]/decisions", false},
		{"IPv6 missing zone", "https://[2001:db8::1%25eth0]/report", "https://[2001:db8::1]/decisions", false},
		{"IPv4 default port", "https://192.0.2.1/report", "https://192.0.2.1:443/decisions", true},
		{"IPv4 different address", "https://192.0.2.1/report", "https://192.0.2.2/decisions", false},
		{"userinfo same host", "https://abuse.example.net/report", "https://operator@abuse.example.net/decisions", true},
		{"userinfo different host", "https://abuse.example.net/report", "https://abuse.example.net@other.example.net/decisions", false},
		{"matching trailing dots", "https://abuse.example.net./report", "https://ABUSE.example.net.:443/decisions", true},
		{"trailing dot differs", "https://abuse.example.net/report", "https://abuse.example.net./decisions", false},
		{"HTTP default port", "http://localhost/report", "http://LOCALHOST:80/decisions", true},
		{"empty URL", "https://abuse.example.net/report", "", false},
		{"relative URL", "https://abuse.example.net/report", "/decisions", false},
		{"missing scheme", "https://abuse.example.net/report", "//abuse.example.net/decisions", false},
		{"invalid escape", "https://abuse.example.net/report", "https://abuse.example.net/%zz", false},
		{"missing host", "https://abuse.example.net/report", "https:///decisions", false},
		{"invalid port", "https://abuse.example.net/report", "https://abuse.example.net:invalid/decisions", false},
		{"out of range port", "https://abuse.example.net/report", "https://abuse.example.net:65536/decisions", false},
		{"non-HTTP scheme", "ftp://abuse.example.net/report", "ftp://abuse.example.net/decisions", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Origin equality must hold regardless of which URL is the target.
			for _, urls := range [][2]string{{tc.reportURL, tc.setURL}, {tc.setURL, tc.reportURL}} {
				target := centralTarget()
				target.URL = urls[0]
				res, found := findResult(Validate(authTargetConfig(urls[1], target)), "error", field)
				if found == tc.wantValid {
					t.Errorf("report URL %q, set URL %q: error = %q (found %v), want valid %v", urls[0], urls[1], res.Message, found, tc.wantValid)
				}
				if found && !strings.Contains(res.Message, "same scheme, host and port") {
					t.Errorf("unexpected error: %s", res.Message)
				}
			}
		})
	}
}
